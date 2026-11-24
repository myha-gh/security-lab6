import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { fileURLToPath } from 'node:url';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'APP_ORIGIN');
  const origin = new URL(env.APP_ORIGIN || 'http://localhost:5175');

  return {
    resolve: { alias: { '@': fileURLToPath(new URL('./client', import.meta.url)) } },
    plugins: [
      react(),
      tailwindcss(),
      {
        name: 'canonical-dev-origin',
        configureServer(server) {
          server.middlewares.use((req, res, next) => {
            // Keep session/OAuth cookies and CSRF checks on the same local origin.
            const host = req.headers.host;
            const localHosts = new Set(['localhost', '127.0.0.1', '[::1]']);
            const requestHost = host ? new URL(`http://${host}`) : null;
            if (
              (req.method === 'GET' || req.method === 'HEAD') &&
              requestHost &&
              localHosts.has(requestHost.hostname) &&
              requestHost.host !== origin.host
            ) {
              const path = new URL(req.url || '/', origin);
              const target = new URL(origin);
              target.pathname = path.pathname;
              target.search = path.search;
              res.writeHead(307, { Location: target.href, 'Cache-Control': 'no-store' });
              res.end();
              return;
            }
            next();
          });
        },
      },
    ],
    server: {
      host: '127.0.0.1',
      port: Number(origin.port) || 5175,
      strictPort: true,
      proxy: { '/api': 'http://127.0.0.1:3000' },
    },
    build: { outDir: 'dist' },
  };
});
