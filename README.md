# @tummycrypt/tinyland-auth

Production-grade authentication system with TOTP, RBAC, and pluggable storage.

## Install

```sh
pnpm add @tummycrypt/tinyland-auth
```

## Exports

- `.` — core auth: session management, password hashing, permissions, RBAC
- `./sveltekit` — SvelteKit integration: hooks, guards, CSRF, session cookies
- `./storage` — storage adapter interface + memory/file implementations
- `./types` — TypeScript type definitions
- `./totp` — TOTP generation and verification
- `./activity` — activity tracking
- `./audit` — audit logging
- `./cred-gen` — credential generation and display
- `./validation` — input validation utilities

## Storage Adapters

Implement `IStorageAdapter` for your backend:

- **Built-in**: `MemoryStorageAdapter`, `FileStorageAdapter`
- **Separate packages**: `@tummycrypt/tinyland-auth-pg` (PostgreSQL), `@tummycrypt/tinyland-auth-redis` (Upstash Redis)

## Tinyland Databaseless MVP

Tinyland's intended app shape is handle-first and email-less by default:

- directory actors are keyed by handle
- email is optional contact metadata, not identity authority
- sessions bind capabilities to directory actors
- FingerprintJS and Tempo are evidence/overlay planes, not auth credentials
- GitHub OAuth is an app-local provider handoff that creates a normal package
  session after provider policy passes

See the
[Tinyland databaseless auth MVP](https://github.com/tinyland-inc/tinyland-auth/blob/main/docs/tinyland-databaseless-auth-mvp.md)
and the
[executable example](https://github.com/tinyland-inc/tinyland-auth/blob/main/examples/tinyland-databaseless-auth-mvp.ts).
