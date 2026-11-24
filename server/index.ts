import { serve } from "@hono/node-server";
import { getConnInfo } from "@hono/node-server/conninfo";
import { serveStatic } from "@hono/node-server/serve-static";
import { Hono } from "hono";
import { secureHeaders } from "hono/secure-headers";
import { bodyLimit } from "hono/body-limit";
import { HTTPException } from "hono/http-exception";
import { config, pool, minute, fail, throttle, type Env } from "./helpers";
import auth from "./routes/auth";
import google from "./routes/google";
import twoFactor from "./routes/two-factor";
import account from "./routes/account";
import admin from "./routes/admin";

const app = new Hono<Env>();
app.use(
  "*",
  secureHeaders({
    referrerPolicy: "no-referrer",
    contentSecurityPolicy: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
    },
  }),
);
app.use("/api/*", bodyLimit({ maxSize: 16 * 1024 }));
app.use("/api/*", async (c, next) => {
  c.header("Cache-Control", "no-store");
  const ip =
    config.TRUST_PROXY === "true"
      ? c.req.header("x-forwarded-for")?.split(",")[0].trim()
      : getConnInfo(c).remote.address;
  c.set("ip", (ip || "unknown").slice(0, 100));
  if (!["GET", "HEAD", "OPTIONS"].includes(c.req.method)) {
    if (c.req.header("origin") !== config.APP_ORIGIN)
      fail("Недозволене джерело запиту.", 403);
    if (!c.req.header("content-type")?.startsWith("application/json"))
      fail("Очікується JSON.");
  }
  await next();
});
app.use("/api/auth/*", async (c, next) => {
  await throttle(`ip:${c.get("ip")}`, 60, 15 * minute);
  await next();
});
app.get("/api/health", (c) => c.json({ ok: true }));

app.route("/api/auth", auth);
app.route("/api/auth/google", google);
app.route("/api", twoFactor);
app.route("/api/account", account);
app.route("/api/admin", admin);

app.onError((err, c) => {
  if (err instanceof HTTPException)
    return c.json({ message: err.message }, err.status);
  console.error("Request failed:", err.name);
  return c.json(
    { message: "Сервіс тимчасово недоступний. Спробуйте пізніше." },
    503,
  );
});

app.all("/api/*", (c) => c.json({ message: "Маршрут не знайдено." }, 404));
if (config.NODE_ENV === "production") {
  app.use("/assets/*", serveStatic({ root: "./dist" }));
  app.get("*", serveStatic({ path: "./dist/index.html" }));
}
const server = serve({ fetch: app.fetch, port: config.PORT }, (info) =>
  console.log(`Hono: http://localhost:${info.port}`),
);
async function shutdown() {
  server.close();
  await pool.end();
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
