import React, { useEffect, useState, type FormEvent } from 'react';
import { createRoot } from 'react-dom/client';
import { Check, Circle, Eye, EyeOff } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import './style.css';

type User = {
  id: string;
  email: string;
  role: 'user' | 'admin';
  activatedAt: string | null;
  twoFactor: boolean;
  hasPassword: boolean;
  googleLinked: boolean;
  createdAt: string;
};
type AdminUser = User & {
  blocked: boolean;
  failedAttempts: number;
  lockedUntil: string | null;
};
type Log = {
  id: string;
  email: string;
  ip: string;
  event: string;
  success: boolean;
  createdAt: string;
};
type View = 'login' | 'register' | 'forgot' | 'activate' | 'reset' | '2fa' | 'resend';

async function api<T = { message: string }>(path: string, data?: unknown): Promise<T> {
  const res = await fetch(`/api${path}`, {
    credentials: 'same-origin',
    ...(data === undefined
      ? {}
      : {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data),
        }),
  });
  const body = await res.json().catch(() => ({ message: 'Сервер недоступний.' }));
  if (!res.ok) throw new Error(body.message || 'Не вдалося виконати запит.');
  return body;
}

const date = (s: string) =>
  new Date(s).toLocaleString('uk-UA', {
    dateStyle: 'medium',
    timeStyle: 'short',
  });

function passwordChecks(value: string) {
  return [
    { label: '8–128 символів', valid: value.length >= 8 && value.length <= 128 },
    { label: 'Великі й малі літери', valid: /\p{Lu}/u.test(value) && /\p{Ll}/u.test(value) },
    { label: 'Цифра', valid: /\d/.test(value) },
    { label: 'Спеціальний символ', valid: /[^\p{L}\p{N}\s]/u.test(value) },
  ];
}

function Password({
  value,
  onChange,
  policy = false,
}: {
  value: string;
  onChange: (value: string) => void;
  policy?: boolean;
}) {
  const [show, setShow] = useState(false);
  const checks = passwordChecks(value);
  return (
    <div className="space-y-2">
      <Label htmlFor="password">Пароль</Label>
      <div className="flex gap-2">
        <Input
          id="password"
          required
          type={show ? 'text' : 'password'}
          minLength={policy ? 8 : 1}
          maxLength={128}
          autoComplete={policy ? 'new-password' : 'current-password'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          aria-describedby={policy ? 'password-rules' : undefined}
          aria-invalid={policy && !!value && checks.some((check) => !check.valid)}
        />
        <Button
          type="button"
          variant="outline"
          size="icon"
          aria-label={show ? 'Приховати пароль' : 'Показати пароль'}
          onClick={() => setShow(!show)}
        >
          {show ? <EyeOff /> : <Eye />}
        </Button>
      </div>
      {policy && (
        <ul id="password-rules" className="space-y-1 text-sm text-muted-foreground">
          {checks.map(({ label, valid }) => (
            <li key={label} className="flex items-center gap-2">
              {valid ? <Check className="size-4" aria-hidden="true" /> : <Circle className="size-4" aria-hidden="true" />}
              {label}
              <span className="sr-only">{valid ? ' — виконано' : ' — не виконано'}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function CodeInput({
  id,
  label,
  value,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="space-y-2">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        inputMode="numeric"
        autoComplete="one-time-code"
        pattern="[0-9]{6}"
        maxLength={6}
        required
        value={value}
        onChange={(e) => onChange(e.target.value.replace(/\D/g, ''))}
      />
    </div>
  );
}

const isTemporarilyLocked = (u: AdminUser) => !!u.lockedUntil && new Date(u.lockedUntil) > new Date();

function App() {
  const params = new URLSearchParams(location.search);
  const [view, setView] = useState<View>(
    location.pathname === '/activate'
      ? 'activate'
      : location.pathname === '/reset'
        ? 'reset'
        : params.get('step') === '2fa'
          ? '2fa'
          : 'login',
  );
  const [token] = useState(() => new URLSearchParams(location.hash.slice(1)).get('token') || '');
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [tab, setTab] = useState<'profile' | 'users' | 'logs'>('profile');
  const [challenge, setChallenge] = useState<{
    id: string;
    enable: boolean;
  } | null>(null);
  const [adminUsers, setAdminUsers] = useState<AdminUser[]>([]);
  const [logs, setLogs] = useState<Log[]>([]);
  const refresh = async () => {
    const res = await api<{ user: User }>('/account/me');
    setUser(res.user);
  };
  useEffect(() => {
    const errors: Record<string, string> = {
      google_conflict:
        'Ця пошта вже має акаунт. Увійдіть за допомогою пароля. Автоматичне об’єднання вимкнене.',
      blocked: 'Вхід заблоковано. Зверніться до адміністратора або спробуйте пізніше.',
      google_failed: 'Не вдалося увійти через Google. Спробуйте ще раз.',
    };
    if (params.get('error')) setError(errors[params.get('error')!] || 'Не вдалося увійти.');
    history.replaceState(null, '', '/');
    // An email action must remain visible even when another session already exists.
    if (view === 'activate' || view === 'reset' || view === '2fa') {
      setLoading(false);
      return;
    }
    refresh()
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);
  useEffect(() => {
    if (!user || user.role !== 'admin' || tab === 'profile') return;
    let active = true;
    setError('');
    const load =
      tab === 'users'
        ? api<{ users: AdminUser[] }>('/admin/users').then((r) => active && setAdminUsers(r.users))
        : api<{ logs: Log[] }>('/admin/logs').then((r) => active && setLogs(r.logs));
    load.catch((e) => active && setError(e.message));
    return () => {
      active = false;
    };
  }, [tab, user]);
  const run = async (work: () => Promise<void>) => {
    if (busy) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await work();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Сталася помилка.');
    } finally {
      setBusy(false);
    }
  };
  const go = (next: View) => {
    setView(next);
    setError('');
    setNotice('');
    setPassword('');
    setCode('');
  };
  const invalidPassword = ['register', 'reset'].includes(view) && passwordChecks(password).some((check) => !check.valid);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (invalidPassword) {
      setError('Пароль має відповідати всім вимогам.');
      return;
    }
    await run(async () => {
      if (view === 'login') {
        const r = await api<{ twoFactorRequired?: boolean }>('/auth/login', {
          email,
          password,
        });
        setPassword('');
        if (r.twoFactorRequired) {
          setView('2fa');
          setNotice('Код надіслано на вашу пошту. Він діє 5 хвилин.');
        } else await refresh();
      } else if (view === 'register') {
        const r = await api('/auth/register', { email, password });
        setView('login');
        setPassword('');
        setNotice(r.message);
      } else if (view === 'forgot' || view === 'resend') {
        const r = await api(view === 'forgot' ? '/auth/forgot-password' : '/auth/resend-activation', {
          email,
        });
        setNotice(r.message);
      } else if (view === 'activate') {
        const r = await api('/auth/activate', { token });
        setView('login');
        setNotice(r.message);
      } else if (view === 'reset') {
        const r = await api('/auth/reset-password', { token, password });
        setView('login');
        setPassword('');
        setUser(null);
        setNotice(r.message);
      } else if (view === '2fa') {
        await api('/auth/2fa/verify', { code });
        setCode('');
        await refresh();
      }
    });
  }
  const actionLabels: Record<View, string> = {
    login: 'Увійти в акаунт',
    register: 'Створити акаунт',
    forgot: 'Надіслати посилання',
    resend: 'Надіслати лист',
    activate: 'Підтвердити пошту',
    reset: 'Зберегти пароль',
    '2fa': 'Підтвердити вхід',
  };
  const notifications = (
    <div className="space-y-3" aria-live="polite">
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {notice && (
        <Alert>
          <AlertDescription>{notice}</AlertDescription>
        </Alert>
      )}
    </div>
  );

  async function changeStatus(id: string, blocked: boolean) {
    await run(async () => {
      await api(`/admin/users/${id}/status`, { blocked });
      const result = await api<{ users: AdminUser[] }>('/admin/users');
      setAdminUsers(result.users);
    });
  }

  if (loading) return <div className="grid min-h-svh place-items-center">Завантаження…</div>;

  return (
    <div className="flex min-h-svh flex-col">
      <header className="flex items-center justify-between border-b p-4">
        <a href="/">lab6</a>
        {user && (
          <Button
            variant="outline"
            disabled={busy}
            onClick={() =>
              run(async () => {
                await api('/account/logout', {});
                setUser(null);
                setTab('profile');
                setChallenge(null);
                go('login');
              })
            }
          >
            Вийти
          </Button>
        )}
      </header>

      {!user ? (
        <main className="grid flex-1 place-items-center p-4">
          <Card className="w-full max-w-sm">
            <CardContent className="space-y-4">
              {notifications}
              <form onSubmit={submit} aria-label={actionLabels[view]} className="space-y-4">
                {['login', 'register', 'forgot', 'resend'].includes(view) && (
                  <div className="space-y-2">
                    <Label htmlFor="email">Електронна пошта</Label>
                    <Input
                      id="email"
                      type="email"
                      autoComplete="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                      maxLength={254}
                      placeholder="you@example.com"
                    />
                  </div>
                )}
                {['login', 'register', 'reset'].includes(view) && (
                  <Password value={password} onChange={setPassword} policy={view !== 'login'} />
                )}
                {view === 'login' && (
                  <Button type="button" variant="link" onClick={() => go('forgot')}>
                    Забули пароль?
                  </Button>
                )}
                {view === '2fa' && (
                  <CodeInput id="login-code" label="Код із листа" value={code} onChange={setCode} />
                )}
                {['activate', 'reset'].includes(view) && !token && (
                  <Alert variant="destructive">
                    <AlertDescription>Відкрийте повне посилання з листа.</AlertDescription>
                  </Alert>
                )}
                <Button
                  type="submit"
                  className="w-full"
                  disabled={busy || invalidPassword || (['activate', 'reset'].includes(view) && !token)}
                >
                  {busy ? 'Зачекайте…' : actionLabels[view]}
                </Button>
              </form>
              {['login', 'register'].includes(view) && (
                <>
                  <Separator />
                  <Button
                    variant="outline"
                    className="w-full"
                    render={<a href="/api/auth/google" />}
                    nativeButton={false}
                  >
                    Продовжити з Google
                  </Button>
                </>
              )}
              <div className="text-center">
                {view === 'login' ? (
                  <Button variant="link" onClick={() => go('register')}>
                    Зареєструватися
                  </Button>
                ) : (
                  <Button variant="link" onClick={() => go('login')}>
                    Повернутися до входу
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>
        </main>
      ) : (
        <main className="mx-auto w-full max-w-5xl space-y-4 p-4">
          {user.role === 'admin' && (
            <nav className="flex flex-wrap gap-2" aria-label="Адміністрування">
              {(
                [
                  ['profile', 'Мій профіль'],
                  ['users', 'Користувачі'],
                  ['logs', 'Журнал входів'],
                ] as const
              ).map(([id, label]) => (
                <Button
                  key={id}
                  variant={tab === id ? 'default' : 'outline'}
                  onClick={() => {
                    setTab(id);
                    setError('');
                    setNotice('');
                  }}
                >
                  {label}
                </Button>
              ))}
            </nav>
          )}
          {notifications}
          {tab === 'profile' ? (
            <>
              <div className="grid gap-4 md:grid-cols-2">
                <Card>
                  <CardHeader>
                    <CardTitle>Особисті дані</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <dl className="space-y-4 text-sm">
                      <div>
                        <dt className="text-muted-foreground">Електронна пошта</dt>
                        <dd className="break-all">{user.email}</dd>
                      </div>
                      <div>
                        <dt className="text-muted-foreground">Підтвердження пошти</dt>
                        <dd>{user.activatedAt ? 'Підтверджено' : 'Не підтверджено'}</dd>
                      </div>
                      <div>
                        <dt className="text-muted-foreground">Роль</dt>
                        <dd>{user.role === 'admin' ? 'Адміністратор' : 'Користувач'}</dd>
                      </div>
                      <div>
                        <dt className="text-muted-foreground">Дата реєстрації</dt>
                        <dd>{date(user.createdAt)}</dd>
                      </div>
                    </dl>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle>Двофакторний захист</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <Badge variant="secondary">{user.twoFactor ? '2FA увімкнено' : '2FA вимкнено'}</Badge>
                    {challenge ? (
                      <form
                        className="space-y-4"
                        onSubmit={(e) => {
                          e.preventDefault();
                          void run(async () => {
                            const result = await api('/account/2fa/confirm', {
                              enable: challenge.enable,
                              challengeId: challenge.id,
                              code,
                            });
                            setChallenge(null);
                            setCode('');
                            await refresh();
                            setNotice(result.message);
                          });
                        }}
                      >
                        <CodeInput id="settings-code" label="Код підтвердження" value={code} onChange={setCode} />
                        <div className="flex gap-2">
                          <Button type="submit" disabled={busy}>
                            Підтвердити
                          </Button>
                          <Button
                            type="button"
                            variant="outline"
                            onClick={() => {
                              setChallenge(null);
                              setCode('');
                            }}
                          >
                            Скасувати
                          </Button>
                        </div>
                      </form>
                    ) : (
                      <div>
                        <Button
                          disabled={busy}
                          onClick={() =>
                            run(async () => {
                              const enable = !user.twoFactor;
                              const result = await api<{ challengeId: string; message: string }>(
                                '/account/2fa/request',
                                { enable },
                              );
                              setChallenge({ id: result.challengeId, enable });
                              setCode('');
                              setNotice(result.message);
                            })
                          }
                        >
                          {user.twoFactor ? 'Вимкнути 2FA' : 'Увімкнути 2FA'}
                        </Button>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>
              <Card>
                <CardHeader>
                  <CardTitle>Способи входу</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4 text-sm">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span>Пароль: {user.hasPassword ? 'налаштовано' : 'не налаштовано'}</span>
                    <Button
                      variant="outline"
                      disabled={busy}
                      onClick={() =>
                        run(async () => {
                          const result = await api('/auth/forgot-password', { email: user.email });
                          setNotice(result.message);
                        })
                      }
                    >
                      {user.hasPassword ? 'Змінити пароль' : 'Встановити пароль'}
                    </Button>
                  </div>
                  <Separator />
                  <p>Google: {user.googleLinked ? 'підключено' : 'не підключено'}</p>
                </CardContent>
              </Card>
            </>
          ) : (
            <Card>
              <CardContent className="space-y-4">
                {tab === 'users' ? (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Пошта</TableHead>
                        <TableHead>Роль</TableHead>
                        <TableHead>Статус</TableHead>
                        <TableHead>2FA</TableHead>
                        <TableHead>Невдалі входи</TableHead>
                        <TableHead>Дії</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {adminUsers.map((u) => (
                        <TableRow key={u.id}>
                          <TableCell>{u.email}</TableCell>
                          <TableCell>{u.role}</TableCell>
                          <TableCell>
                            <Badge variant={u.blocked ? 'destructive' : 'secondary'}>
                              {u.blocked
                                ? 'Заблоковано'
                                : isTemporarilyLocked(u)
                                  ? 'Тимчасове блокування'
                                  : u.activatedAt
                                    ? 'Активний'
                                    : 'Не підтверджено'}
                            </Badge>
                          </TableCell>
                          <TableCell>{u.twoFactor ? 'Так' : 'Ні'}</TableCell>
                          <TableCell>{u.failedAttempts}</TableCell>
                          <TableCell>
                            <div className="flex gap-2">
                              <Button
                                variant="outline"
                                size="sm"
                                disabled={busy || u.id === user.id}
                                onClick={() => changeStatus(u.id, !u.blocked)}
                              >
                                {u.blocked ? 'Розблокувати' : 'Заблокувати'}
                              </Button>
                              {!u.blocked && isTemporarilyLocked(u) && (
                                <Button
                                  variant="outline"
                                  size="sm"
                                  disabled={busy || u.id === user.id}
                                  onClick={() => changeStatus(u.id, false)}
                                >
                                  Зняти обмеження
                                </Button>
                              )}
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Час</TableHead>
                        <TableHead>Пошта</TableHead>
                        <TableHead>IP</TableHead>
                        <TableHead>Подія</TableHead>
                        <TableHead>Результат</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {logs.map((log) => (
                        <TableRow key={log.id}>
                          <TableCell>{date(log.createdAt)}</TableCell>
                          <TableCell>{log.email}</TableCell>
                          <TableCell>{log.ip}</TableCell>
                          <TableCell>{log.event}</TableCell>
                          <TableCell>{log.success ? 'Успішно' : 'Не завершено'}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
                {(tab === 'users' ? adminUsers : logs).length === 0 && (
                  <p className="text-sm text-muted-foreground">Записів немає.</p>
                )}
              </CardContent>
            </Card>
          )}
        </main>
      )}
    </div>
  );
}

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
