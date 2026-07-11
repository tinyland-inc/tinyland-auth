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

## Invitation Authority

`@tummycrypt/tinyland-auth` does not export an invitation service or factory.
Use `@tummycrypt/tinyland-invitation` for fail-closed invitation authorization,
minting, acceptance, revocation, and lifecycle management.

The invitation record types and storage adapter methods in this package remain
compatibility surfaces for persisting application state. They do not generate
tokens or authorize a caller to mint an invitation.

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

### Browser-as-a-factor (fingerprint doctrine)

> Browser-as-a-factor (operator-canonized 2026-07-05): the Tempo-derived
> browser fingerprint (tinyland-fingerprint — UA-parse + Tempo evidence, NOT
> the fingerprintjs library) is not a traditional factor but correctly
> represents the user by print as a viable element of
> user-proof-during-session, enabling cookieless / localStorage-less
> persistent sessions with browser-backed persistence — the novel tempo +
> print + factors stack iterated for over a year. Boundary invariant
> (TIN-1610, ratified): the print is evidence at the credential boundary,
> never a veto — validateSession() never destroys an authenticated session on
> a missing/changed fingerprint. The two truths are LAYERED, not
> contradictory: evidence-only at the credential boundary; a
> session-persistence factor at the product layer. Do not flatten either half
> away.

Cross-references: TIN-1610 (evidence-not-veto boundary invariant),
[`@tummycrypt/tinyland-fingerprint` v0.3.0](https://github.com/tinyland-inc/tinyland-fingerprint)
(supplier of the print + Tempo evidence), and prompts-enqueue
golden-objectives §tinyland-auth (corrected 2026-07-05).

## RBAC

Role management order and permission checks are intentionally separate. See
[the RBAC matrix](https://github.com/tinyland-inc/tinyland-auth/blob/main/docs/rbac-matrix.md)
for the package-owned matrix and downstream test guidance, and
[the role charter](https://github.com/tinyland-inc/tinyland-auth/blob/main/docs/role-charter.md)
for the two-axis model and the P1/P2/P3 invariants.

### Role x feature charter (operator-ratified 2026-07-04, TIN-2435)

Roles live on two axes: a **governance spine** (`viewer -> member ->
moderator -> admin -> super_admin`, totally ordered by `ROLE_HIERARCHY`,
governs who manages whom) and horizontal **feature capability**
(`ROLE_PERMISSIONS`, an intentional lattice -- capabilities do NOT nest by
rank; TIN-1606 precedent).

| Role | Axis | Feature charter |
| --- | --- | --- |
| `super_admin` | governance-spine | System owner; every permission. |
| `admin` | governance-spine | General administration across domains. |
| `moderator` | governance-spine | Fedi / community moderation. |
| `editor` | specialist | Blog editorial. |
| `event_manager` | specialist | Events / calendaring. |
| `contributor` | specialist | Drafts / submissions. |
| `member` | governance-spine | Self-service core (`MEMBER_SELF_SERVICE_CORE`). |
| `viewer` | governance-spine | Read-only admin surface. |

Every role at or above `member` holds `MEMBER_SELF_SERVICE_CORE`
(invariant P2), and every `can*` predicate derives from `ROLE_PERMISSIONS`
-- there are no hand-maintained role arrays. Machine-readable charter:
`ROLE_CHARTER` and `PERMISSION_FEATURE_DOMAIN` in
`src/types/permissions.ts`.
