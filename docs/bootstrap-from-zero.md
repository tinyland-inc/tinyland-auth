# Bootstrap a consuming SvelteKit app from zero

This is the missing "from nothing" adoption guide for `@tummycrypt/tinyland-auth`.
It takes a brand-new SvelteKit app and wires it up to a working house-native
password plus TOTP login with a first `super_admin`, using only the public
`0.7.1` API.

Everything below is grounded in the reviewed `0.7.1` source. Each API is cited to
its source file at the end (see "Provenance"). Where a snippet fills an
integration seam that the package does not itself export, it is labelled
`ILLUSTRATIVE` so you can tell verified package API from glue you supply.

Pin `0.7.1` from the configured package authority. This guide is written
against that exact release.

## What you get

- A pluggable storage adapter holding users, sessions, TOTP secrets, backup
  codes, and audit events (built-in memory or file adapter, or a separate
  Postgres/Redis adapter package).
- A `hooks.server.ts` chain that resolves the session cookie into
  `event.locals.session` / `event.locals.user` on every request, renews sessions
  near expiry, and stamps a hashed client IP.
- Password hashing (bcrypt) and replay-resistant TOTP verification.
- A first-run `super_admin` bootstrap, both as an operator seed script and as an
  in-app guided flow.
- CSRF double-submit protection and route guards.

## 0. Prerequisites

The package declares these engines and peer deps:

- Node `>=22`
- `@sveltejs/kit` `^2.0.0` (peer, optional)
- `svelte` `^5.0.0` (peer, optional)

A default `npm create svelte@latest` (SvelteKit 2 + Svelte 5) app satisfies
this.

### A note on install authority

Per the package README, Tinyland's current release authority for this repo is
Bazel-first, and npmjs publication is disabled. `pnpm add
@tummycrypt/tinyland-auth` is valid only against a registry configured to serve
the `@tummycrypt` scope; Bazel consumers should depend through the Tinyland
Bazel registry / BCR module path (`tummycrypt_tinyland_auth`) instead of a
workspace-local copy. This guide shows the import surface; how you make that
surface resolvable (registry npm, Bazel module graph, or vendored copy) is your
build's decision. The TypeScript import specifier is always
`@tummycrypt/tinyland-auth`.

## 1. Required env and secrets

| Variable | Required | Purpose |
| --- | --- | --- |
| `TOTP_ENCRYPTION_KEY` | Yes | Symmetric key used to encrypt TOTP secrets at rest (`scrypt` key derivation + AES-256-GCM). Use a long, high-entropy string (32+ chars). Losing or rotating it makes every stored TOTP secret undecryptable. |
| `AUTH_DATA_DIR` | Only for the file adapter | Directory the `FileStorageAdapter` writes auth JSON under. Not needed for the memory adapter or a Postgres/Redis adapter. |
| `DATABASE_URL` | Only for `tinyland-auth-pg` | Postgres connection string, if you choose the Postgres adapter package instead of the built-in adapters. |

Never commit these. Load them from your platform's secret store or a local
`.env` that is gitignored.

The `TOTP_ENCRYPTION_KEY` is consumed as `TOTPServiceConfig.encryptionKey`.

## 2. Pick a storage adapter

`tinyland-auth` is storage-agnostic: it ships two built-in adapters and defers
durable backends to separate packages. All of them implement `IStorageAdapter`.

- `MemoryStorageAdapter` - in-process, non-durable. Perfect for tests and first
  boot. Everything is lost on restart.
- `FileStorageAdapter` (`createFileStorageAdapter`) - JSON-on-disk. Durable for a
  single-node app. Config fields: `authDir` (default `content/auth`), `totpDir`
  (default `.totp-secrets`), `sessionMaxAge`.
- `@tummycrypt/tinyland-auth-pg` / `@tummycrypt/tinyland-auth-redis` - separate
  packages for Postgres and Upstash Redis.

Start with the file adapter for a real single-node app:

```ts
// src/lib/server/storage.ts
import { createFileStorageAdapter } from '@tummycrypt/tinyland-auth/storage';

export const storage = createFileStorageAdapter({
  authDir: process.env.AUTH_DATA_DIR ?? 'content/auth',
});

// Call once at startup before first use.
await storage.init();
```

`init()` is part of the adapter lifecycle and must run before the adapter is
used (the shipped example calls `await storage.init()` right after
construction).

## 3. Central auth config and singletons

Create one module that builds the config once and constructs the long-lived
services. `createAuthConfig(overrides)` deep-merges your overrides over
`DEFAULT_AUTH_CONFIG`, so you only specify what differs.

```ts
// src/lib/server/auth.ts
import {
  createAuthConfig,
  createSessionManager,
  TOTPService,
} from '@tummycrypt/tinyland-auth';
import { storage } from './storage.js';

const encryptionKey = process.env.TOTP_ENCRYPTION_KEY;
if (!encryptionKey) {
  throw new Error('TOTP_ENCRYPTION_KEY is required');
}

export const authConfig = createAuthConfig({
  appName: 'My App',
  appUrl: process.env.PUBLIC_APP_URL ?? 'http://localhost:5173',
  session: {
    cookieName: 'sessionId',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    renewThreshold: 24 * 60 * 60 * 1000,
    maxConcurrentSessions: 5,
    // secureCookie defaults to true; keep it true in production.
  },
});

// createSessionManager takes (storage, sessionConfig).
export const sessions = createSessionManager(storage, authConfig.session);

// TOTPService takes { encryptionKey, issuer }.
export const totp = new TOTPService({
  encryptionKey,
  issuer: authConfig.appName,
});
```

`DEFAULT_AUTH_CONFIG` ships sensible defaults: session `cookieName: 'sessionId'`,
`maxAge` 7 days, `renewThreshold` 24h, `secureCookie: true`, `sameSite: 'lax'`,
password `minLength: 12` with complexity on, `bcryptRounds: 12`, TOTP
`issuer: 'Tinyland.dev'`, `digits: 6`, `period: 30`, `window: 1`. Override only
what you need.

## 4. Type your locals

The auth hook writes `session`, `user`, `clientIp`, `clientIpMasked`, and
`userAgent` onto `event.locals`. Declare them so the rest of your app is typed:

```ts
// src/app.d.ts
import type { Session, AdminUser } from '@tummycrypt/tinyland-auth/types';

declare global {
  namespace App {
    interface Locals {
      session: Session | null;
      user: AdminUser | null;
      clientIp: string;
      clientIpMasked: string;
      userAgent: string;
    }
  }
}

export {};
```

## 5. Wire hooks.server.ts

The SvelteKit adapter (`@tummycrypt/tinyland-auth/sveltekit`) provides
`createAuthHandle`, `createCSRFHandle`, and a `sequence` helper. `createAuthHandle`
resolves the session cookie, loads the user via your `loadUser` callback, renews
the session when `shouldRenewSession` says so, and populates `event.locals`.

```ts
// src/hooks.server.ts
import type { Handle } from '@sveltejs/kit';
import { redirect } from '@sveltejs/kit';
import {
  createAuthHandle,
  createCSRFHandle,
  sequence,
} from '@tummycrypt/tinyland-auth/sveltekit';
import { authConfig, sessions } from '$lib/server/auth.js';
import { storage } from '$lib/server/storage.js';

// 1. Resolve session + user into event.locals on every request.
const authHandle = createAuthHandle({
  sessionManager: sessions,
  config: authConfig,
  loadUser: (userId) => storage.getUser(userId),
  skipRoutes: ['/api/health', '/favicon.ico'],
});

// 2. Deny-by-default gate. Everything except public routes needs a session.
//    ILLUSTRATIVE: this small gate is app policy, not a package export. The
//    package ships per-route guards (requireAuth / requireRole) you can use
//    instead; this hook-level version mirrors the dollhouse-farm reference app.
const PUBLIC_ROUTES = ['/login', '/logout', '/api/health'];
const guardHandle: Handle = async ({ event, resolve }) => {
  const path = event.url.pathname;
  const isPublic = PUBLIC_ROUTES.some((r) => path === r || path.startsWith(r + '/'));
  if (!isPublic && !event.locals.session) {
    throw redirect(303, `/login?returnUrl=${encodeURIComponent(path)}`);
  }
  return resolve(event);
};

// 3. CSRF double-submit. Skip safe methods and the login/logout entry points.
const csrfHandle = createCSRFHandle({
  skipRoutes: ['/login', '/logout'],
});

export const handle = sequence(authHandle, guardHandle, csrfHandle);
```

`sequence` here is the package's own export (do not confuse it with
`@sveltejs/kit/hooks` `sequence`; either works, but the package ships its own).
The auth hook degrades to logged-out rather than throwing if the session cannot
be resolved, so a misconfigured secret yields a login redirect, not a 500.

## 6. First super_admin bootstrap (operator seed script)

This is the "from nothing" moment: the store has zero users and you need the
first `super_admin`. Use the storage-level claim/finalize protocol so no active
user, credential, role, session authority, TOTP enrollment, or backup-code use
exists before one atomic finalization. The immutable completion receipt makes
an exact retry idempotent and rejects mismatched retries.

```ts
// scripts/auth-seed.ts  (run with: node --env-file=.env scripts/auth-seed.ts)
import {
  hashPassword,
  generateBackupCodes,
  createBackupCodeSet,
  type FirstUserBootstrapFinalization,
  type InertFirstUserClaim,
} from '@tummycrypt/tinyland-auth';
import { randomUUID } from 'node:crypto';
import { stdin, stdout } from 'node:process';
import { createInterface } from 'node:readline/promises';
import { AdminRole } from '@tummycrypt/tinyland-auth/types';
import { createFileStorageAdapter } from '@tummycrypt/tinyland-auth/storage';
import { TOTPService } from '@tummycrypt/tinyland-auth/totp';

const HANDLE = process.env.SEED_HANDLE ?? 'admin';
const PASSWORD = process.env.SEED_PASSWORD; // supply via env, do not hardcode

async function main() {
  if (!PASSWORD) throw new Error('SEED_PASSWORD required');
  const encryptionKey = process.env.TOTP_ENCRYPTION_KEY;
  if (!encryptionKey) throw new Error('TOTP_ENCRYPTION_KEY required');

  const storage = createFileStorageAdapter({
    authDir: process.env.AUTH_DATA_DIR ?? 'content/auth',
  });
  await storage.init();

  const totp = new TOTPService({ encryptionKey, issuer: 'My App' });
  const tenantId = process.env.AUTH_TENANT_ID;
  if (!tenantId) throw new Error('AUTH_TENANT_ID required');
  const claimedAt = new Date().toISOString();
  const claim: InertFirstUserClaim = {
    version: 1,
    tenantId,
    attemptId: randomUUID(),
    actor: {
      id: randomUUID(),
      handle: HANDLE,
      isActive: false,
      totpEnabled: false,
      sessionAuthority: false,
      backupCodesGenerated: false,
    },
    claimedAt,
  };
  await storage.claimFirstUserBootstrap(claim);

  // Prepare all credential material without making any of it authoritative.
  const passwordHash = await hashPassword(PASSWORD, { rounds: 12 });
  const secret = await totp.generateSecret(claim.actor.handle);
  const enc = totp.encrypt(secret.secret);
  const plainCodes = generateBackupCodes(10);
  const finalizedAt = new Date().toISOString();
  const finalization: FirstUserBootstrapFinalization = {
    version: 1,
    tenantId: claim.tenantId,
    attemptId: claim.attemptId,
    finalizedAt,
    user: {
      id: claim.actor.id,
      handle: claim.actor.handle,
      displayName: HANDLE,
      passwordHash,
      role: AdminRole.SUPER_ADMIN,
      isActive: true,
      totpEnabled: true,
      totpSecretId: claim.actor.handle,
      needsOnboarding: false,
      onboardingStep: 0,
      createdAt: claimedAt,
      updatedAt: finalizedAt,
    },
    totpSecret: {
      userId: claim.actor.id,
      handle: claim.actor.handle,
      encryptedSecret: enc.encrypted,
      iv: enc.iv,
      authTag: enc.tag,
      salt: enc.salt,
      createdAt: finalizedAt,
      backupCodesGenerated: true,
      version: 1,
    },
    backupCodes: {
      ...createBackupCodeSet(claim.actor.id, plainCodes),
      generatedAt: finalizedAt,
    },
  };

  // Put the factor in the operator's authenticator and save the recovery
  // codes before any credential or role becomes authoritative.
  console.log('Scan this TOTP secret in your authenticator app:');
  console.log('  otpauth secret:', secret.secret);
  console.log('  qr (data url):', secret.qrCodeUrl);
  console.log('Backup codes (store now, shown once):');
  for (const c of plainCodes) console.log('  ', c);

  const prompt = createInterface({ input: stdin, output: stdout });
  try {
    const code = await prompt.question('Enter the current 6-digit TOTP code: ');
    if (!(await totp.verifyToken(secret, code))) {
      throw new Error('TOTP verification failed; no authority was finalized');
    }
    const confirmation = await prompt.question(
      'Type COMMIT after storing the backup codes: ',
    );
    if (confirmation !== 'COMMIT') {
      throw new Error('Bootstrap cancelled; no authority was finalized');
    }
  } finally {
    prompt.close();
  }

  const receipt = await storage.finalizeFirstUserBootstrap(finalization);
  console.log('super_admin created:', receipt.handle);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
```

Note the field mapping when persisting the secret: `TOTPService.encrypt()`
returns `EncryptedData` with `{ encrypted, salt, iv, tag }`, while the stored
`EncryptedTOTPSecret` shape uses `{ encryptedSecret, iv, authTag, salt }`. Map
`encrypted -> encryptedSecret` and `tag -> authTag`. This exact mapping appears
in the shipped example.

After this runs once, the operator has a working `super_admin` with password and
a TOTP secret in their authenticator app, plus one-time backup codes. Keep the
same finalization object for an exact retry within the running process;
regenerating any field is a mismatched replay and fails closed. An unattended
restart needs sealed durable custody for that exact finalization. This compact
example intentionally makes no crash-restart claim; use the guided service with
a durable attempt store for that workflow.

## 7. Login route (password + replay-resistant TOTP)

Login is two factors. Verify the password against the stored hash, then verify
the TOTP code. Since `0.6.0`, use `verifyTokenWithStep`, which rejects replay of a
still-valid code by comparing the consumed time-step against the last one you
persisted.

```ts
// src/routes/login/+page.server.ts
import { fail, redirect } from '@sveltejs/kit';
import { verifyPassword } from '@tummycrypt/tinyland-auth';
import type { TOTPSecret } from '@tummycrypt/tinyland-auth/types';
import { setSessionCookie } from '@tummycrypt/tinyland-auth/sveltekit';
import { sessions, totp, authConfig } from '$lib/server/auth.js';
import { storage } from '$lib/server/storage.js';

export const actions = {
  default: async ({ request, cookies, getClientAddress }) => {
    const form = await request.formData();
    const handle = String(form.get('handle') ?? '');
    const password = String(form.get('password') ?? '');
    const code = String(form.get('totp') ?? '');

    const user = await storage.getUserByHandle(handle);
    if (!user || !user.isActive) return fail(401, { error: 'Invalid credentials' });

    // Factor 1: password.
    const okPassword = await verifyPassword(password, user.passwordHash);
    if (!okPassword) return fail(401, { error: 'Invalid credentials' });

    // Factor 2: TOTP with replay protection.
    const stored = await storage.getTOTPSecret(user.handle);
    if (!stored) return fail(401, { error: 'TOTP not enrolled' });

    const plainSecret = totp.decrypt({
      encrypted: stored.encryptedSecret,
      salt: stored.salt,
      iv: stored.iv,
      tag: stored.authTag,
    });
    const secret: TOTPSecret = {
      handle: user.handle,
      secret: plainSecret,
      createdAt: new Date(),
    };

    const result = await totp.verifyTokenWithStep(secret, code, stored.lastUsedTotpStep);
    if (!result.valid) return fail(401, { error: 'Invalid or reused code' });

    // Persist the consumed step so the same code cannot be replayed.
    // ILLUSTRATIVE: re-save the record with the new lastUsedTotpStep. Use
    // whatever update path your adapter exposes; saveTOTPSecret overwrites by
    // handle in the built-in adapters.
    await storage.saveTOTPSecret(user.handle, {
      ...stored,
      lastUsedTotpStep: result.step,
    });

    // Mint the session and set the cookie.
    const session = await sessions.createSession(user.id, user, {
      clientIp: getClientAddress(),
      clientIpMasked: getClientAddress(),
      userAgent: request.headers.get('user-agent') ?? 'unknown',
      deviceType: 'desktop',
    });
    setSessionCookie(cookies, session.id, {
      sessionCookieName: authConfig.session.cookieName,
      secure: authConfig.session.secureCookie,
      maxAge: Math.floor(authConfig.session.maxAge / 1000),
    });

    throw redirect(303, '/');
  },
};
```

`verifyTokenWithStep` returns `{ valid, step? }`. On success, `step` is the
newly-consumed time-step; persist it into `lastUsedTotpStep` and feed it back on
the next verification. The legacy boolean `verifyToken(secret, code)` still
exists as a stateless migration path if you do not want replay tracking yet.

To log out, clear the cookies and remove the session:

```ts
// src/routes/logout/+page.server.ts (action)
import { clearSessionCookies } from '@tummycrypt/tinyland-auth/sveltekit';
import { sessions } from '$lib/server/auth.js';

// inside the action:
if (locals.session) await sessions.removeSession(locals.session.id);
clearSessionCookies(cookies);
```

## 8. Enroll TOTP for a user who does not have it yet

The seed script enrolls the first admin. For later users (or a user who skipped
it), the enroll flow is: generate a secret, show the QR, verify one code from
the authenticator, then persist the encrypted secret and flip `totpEnabled`.

```ts
// generate + show (server load or action)
const secret = await totp.generateSecret(user.handle); // secret.qrCodeUrl is a data: URL to render
// keep secret.secret in a short-lived server-side store until verified;
// do not put it in a signed or encrypted browser cookie

// verify the first code before saving
const ok = await totp.verifyToken(
  { handle: user.handle, secret: pendingSecret, createdAt: new Date() },
  submittedCode,
);
if (ok) {
  const enc = totp.encrypt(pendingSecret);
  await storage.saveTOTPSecret(user.handle, {
    userId: user.id,
    handle: user.handle,
    encryptedSecret: enc.encrypted,
    iv: enc.iv,
    authTag: enc.tag,
    salt: enc.salt,
    createdAt: new Date().toISOString(),
    backupCodesGenerated: false,
    version: 1,
  });
  // then mark user.totpEnabled = true via your adapter's user update path
}
```

## 9. Optional: in-app guided bootstrap with BootstrapService

If you prefer a guided `/bootstrap` route over a seed script, the package ships
`BootstrapService` (`createBootstrapService`). It enforces the "no users yet"
precondition, validates the handle, and its `complete()` step hardcodes
`role: 'super_admin'`, so it is purpose-built for the first admin. Its config
takes callbacks for the TOTP primitives:

The unreleased 0.8 service uses the same atomic claim/finalize protocol. Its
browser state is only an opaque attempt reference. All credential material and
the compare-and-set prepared finalization stay in an explicit server-side
`BootstrapAttemptStore`.

```ts
import {
  MemoryBootstrapAttemptStore,
  createBootstrapService,
} from '@tummycrypt/tinyland-auth';
import {
  generateTOTPSecret,
  generateTOTPUri,
  generateTOTPQRCode,
} from '@tummycrypt/tinyland-auth/totp';
import { totp } from '$lib/server/auth.js';
import { storage } from '$lib/server/storage.js';

const bootstrap = createBootstrapService({
  storage,                       // atomic bootstrap + status/audit reads
  tenantId: process.env.AUTH_TENANT_ID!,
  // Single-process only. Multi-replica apps must inject durable CAS custody.
  attemptStore: new MemoryBootstrapAttemptStore(),
  appName: 'My App',
  bcryptRounds: 12,
  backupCodesCount: 10,
  generateTOTPSecret,            // () => string (base32 secret)
  generateQRCode: (handle, secret, issuer) =>
    generateTOTPQRCode(generateTOTPUri(secret, issuer, handle)), // () => Promise<data-url>
  encryptTOTPSecret: async (handle, secret) => {
    const enc = totp.encrypt(secret);
    return {
      userId: 'pending',         // service binds the stored factor to the claimed actor
      handle,
      encryptedSecret: enc.encrypted,
      iv: enc.iv,
      authTag: enc.tag,
      salt: enc.salt,
      createdAt: new Date().toISOString(),
      backupCodesGenerated: true,
      version: 1,
    };
  },
  decryptTOTPSecret: async (stored) => totp.decrypt({
    encrypted: stored.encryptedSecret,
    salt: stored.salt,
    iv: stored.iv,
    tag: stored.authTag,
  }),
  // verifyTOTP: (secret: string, token: string) => boolean
  // ILLUSTRATIVE seam: the package does not export a synchronous string-based
  // TOTP verifier, and this callback must be synchronous (complete() calls it
  // without awaiting). Supply one using otplib, which tinyland-auth itself
  // depends on internally, configured to match the package (step 30, window 1,
  // SHA1, 6 digits). If you cannot add that verifier, prefer the seed script in
  // section 6, which needs no in-app code round-trip.
  verifyTOTP: (secret, token) => {
    // e.g. otplib authenticator.check(token, secret) with matching options
    throw new Error('supply a synchronous TOTP verifier');
  },
});
```

Flow: `getStatus()` reports both first-user eligibility and whether finalized
authority metadata is present with decryptable TOTP ciphertext. It is not a
live authenticator-code canary. `initiate({ handle, password, displayName,
email? })` returns
`{ state, qrCodeUrl, backupCodes }`; `state` is `{ version: 1, attemptId }` and
can be carried to `complete(state, { handle, totpCode })`. Profile updates use
`await bootstrap.updateProfile(state, profile)` so profile data also stays in
server custody. Completion verifies the code, freezes one deterministic
finalization, commits the user/TOTP/backup-code authority atomically, and
returns the safe user. Exact lost-response retries resolve from the immutable
receipt before expiry or TOTP checks. Plaintext pending credentials are erased
on the normal success path before the response returns. Receipt replay never
re-emits backup codes, even if cleanup failed and left the pending record
behind; save the one-time codes returned by `initiate`. Durable attempt stores
must enforce expiry as a backstop for process crashes and cleanup failures.

`complete()` never returns backup codes, including its first success. The
one-time disclosure is the `initiate()` response. The attempt and storage claim
share one fixed ten-minute lifetime; shorter or longer service lifetimes are
rejected so the browser-state and storage-authority windows cannot diverge.

Protect the attempt id as a bearer capability in an httpOnly cookie or an
equivalent server-bound transport. Never serialize the pending attempt object:
it contains the password hash, raw TOTP secret, and plaintext backup codes. The
attempt store must implement atomic create and prepare-finalization operations;
an ordinary cache get/set pair is not sufficient for multiple replicas.
The default attempt-id generator is cryptographically random. A custom
`generateAttemptId` must preserve at least 128 bits of entropy.

The seed script in section 6 is the lower-friction path for most apps; reach for
`BootstrapService` when you want the whole thing to happen inside the running app
with no shell access.

## 10. Minimum viable checklist

1. `TOTP_ENCRYPTION_KEY` set (32+ chars, secret, stable).
2. A storage adapter constructed and `init()`ed (`FileStorageAdapter` to start).
3. `src/lib/server/auth.ts` building `createAuthConfig`, `createSessionManager`,
   and `TOTPService`.
4. `src/app.d.ts` declaring the five locals the hook writes.
5. `src/hooks.server.ts` running `sequence(authHandle, guardHandle, csrfHandle)`.
6. First `super_admin` seeded once (section 6) or bootstrapped in-app (section 9).
7. A `/login` action verifying password + TOTP and calling `setSessionCookie`.

At that point an unauthenticated request to any non-public route redirects to
`/login`, and a correct password plus TOTP code mints a session.

## Provenance (0.7.1 release plus unreleased 0.8 bootstrap source)

The general auth APIs below are public exports of
`@tummycrypt/tinyland-auth@0.7.1`. The atomic first-user storage protocol,
`MemoryBootstrapAttemptStore`, and opaque `BootstrapService` state are
unreleased 0.8 source and must not be claimed as available from 0.7.1.

- Root exports (`hashPassword`, `verifyPassword`, `validatePassword`,
  `generateBackupCodes`, `createBackupCodeSet`, `verifyBackupCode`,
  `createAuthConfig`, `DEFAULT_AUTH_CONFIG`, `TOTPService`, `createTOTPService`,
  `createSessionManager`, `SessionManager`, `MemoryStorageAdapter`,
  `FileStorageAdapter`, `createFileStorageAdapter`, `createBootstrapService`,
  `BootstrapService`, `hashIp`, `maskIp`): `src/index.ts`.
- SvelteKit adapter (`createAuthHandle`, `createCSRFHandle`, `sequence`,
  `getClientIp`, `requireAuth`, `requireRole`, `requirePermission`,
  `setSessionCookie`, `clearSessionCookies`, `getSessionIdFromCookies`):
  `src/adapters/sveltekit/{index,hook,guards,session-cookies}.ts`.
- `TOTPService` methods (`generateSecret`, `generateToken`, `verifyToken`,
  `verifyTokenWithStep`, `encrypt`, `decrypt`) and `TOTPServiceConfig`:
  `src/core/totp/index.ts`. `verifyTokenWithStep` and the
  `EncryptedTOTPSecret.lastUsedTotpStep` field are the `0.6.0` replay-protection
  additions (TIN-2667).
- `./totp` compat helpers (`generateTOTPSecret`, `generateTOTPUri`,
  `generateTOTPQRCode`, `generateTOTPToken`): `src/totp/compat.ts`.
- `SessionManager` (`createSession`, `getSession`, `validateSession`,
  `refreshSession`, `removeSession`, `shouldRenewSession`) and
  `createSessionManager(storage, sessionConfig)`: `src/core/session/index.ts`.
- Storage interface (`IStorageAdapter`, `BootstrapStorage`, `createUser`,
  `hasUsers`, `getUser`, `getUserByHandle`, `saveTOTPSecret`, `getTOTPSecret`,
  `saveBackupCodes`, `logAuditEvent`): `src/storage/interface.ts`,
  `src/storage/{memory,file}.ts`.
- `FileStorageConfig` (`authDir`, `totpDir`, `sessionMaxAge`):
  `src/storage/file.ts`.
- `BootstrapService` config and `complete()` writing `role: 'super_admin'`:
  `src/modules/bootstrap/index.ts`.
- `DEFAULT_AUTH_CONFIG` values (session `cookieName: 'sessionId'`, `maxAge` 7d,
  `renewThreshold` 24h, password `minLength: 12`, TOTP `issuer`, `digits: 6`,
  `period: 30`, `window: 1`): `src/types/config.ts`.
- `AdminRole` value map (`AdminRole.SUPER_ADMIN === 'super_admin'`),
  `EncryptedTOTPSecret`, `AdminUser`, `Session`, `TOTPSecret`, `EncryptedData`
  types: `src/types/auth.ts`.
- End-to-end reference for the create-user + encrypt + save-TOTP + backup-codes
  sequence: `examples/tinyland-databaseless-auth-mvp.ts`.

Snippets labelled `ILLUSTRATIVE` fill integration seams (a deny-by-default hook,
persisting `lastUsedTotpStep`, and a synchronous TOTP verifier for
`BootstrapService`) that are app policy or supplied glue rather than package
exports. Everything else is verified `0.7.1` API.
