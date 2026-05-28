# @tummycrypt/tinyland-auth

Production-grade authentication system with TOTP, RBAC, and pluggable storage.

## Consumption And Release Authority

The TypeScript import API stays under `@tummycrypt/tinyland-auth`. Tinyland's
current release authority for this repo is Bazel-first:

- CI validates the package through a repo-owned GloriousFlywheel runner lane and
  `//:pkg //:test //:typecheck`.
- npmjs publication is disabled in package workflows.
- GitHub Packages mirror publication uses `@tinyland-inc/tinyland-auth`, because
  GitHub Packages npm scopes are owner-bound.
- Bazel consumers should depend through the Tinyland Bazel registry / BCR module
  path instead of relying on a workspace-local package copy.

`pnpm add @tummycrypt/tinyland-auth` is valid only when the consumer is
configured for a registry that intentionally serves the `@tummycrypt` package
scope. It is not the current Tinyland publication authority for this repo.

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

## RBAC

Role management order and permission checks are intentionally separate. See
[the RBAC matrix](https://github.com/tinyland-inc/tinyland-auth/blob/main/docs/rbac-matrix.md)
for the package-owned matrix and downstream test guidance.
