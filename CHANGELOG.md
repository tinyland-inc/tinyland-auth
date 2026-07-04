# @tummycrypt/tinyland-auth

## 0.4.0

### Minor Changes

- RBAC SSOT hardening (TIN-2435, operator-ratified 2026-07-04; precedent
  TIN-1606).

  **New exports**: `MEMBER_SELF_SERVICE_CORE` (defined as
  `ROLE_PERMISSIONS.member` by construction: `admin.access`,
  `admin.content.view`, `admin.events.view`), `ROLE_CHARTER` (two-axis
  role tags: governance-spine | specialist, with `ROLE_HIERARCHY` ranks),
  `FEATURE_DOMAINS` and `PERMISSION_FEATURE_DOMAIN` (feature-domain
  registry over the permission vocabulary), plus types `FeatureDomain`,
  `RoleAxis`, `RoleCharterEntry`.

  **P2 data reconciliation** (behavior change: view-level grants). Every
  role ranked at or above `member` now holds the member self-service core:

  - `moderator` gains `admin.events.view`
  - `editor` gains `admin.events.view`
  - `contributor` gains `admin.events.view`
  - `event_manager` gains `admin.content.view`

  **New permission strings** (behavior change: vocabulary additions so
  `can*` predicates derive from `ROLE_PERMISSIONS` instead of the
  hand-maintained role arrays — the tinyland.dev#628 anti-pattern class):

  - `admin.content.publish` → contributor, event_manager, editor,
    moderator, admin, super_admin (backs `canCreatePublicContent`)
  - `admin.content.media_create` → contributor, editor, admin,
    super_admin (backs `canCreateVideos`)
  - `admin.content.delete` → admin, super_admin (backs `canDeletePosts`,
    `canDeleteVideos`, `canDeleteContent`)
  - `admin.events.delete` → admin, super_admin (backs `canDeleteEvents`)

  **Predicate derivation**: every `can*` predicate now derives from
  `ROLE_PERMISSIONS`. The full role × predicate matrix is locked in
  `tests/rbac-invariants.test.ts`. Intentional behavior deltas (P2
  member-core flow-through; everything else is cell-identical):

  - `canCreateEvents` now true for `moderator`, `editor`, `contributor`
  - `canDeleteOwnContent` now true for `moderator`

  **Invariants**: deterministic, exhaustive tests for P1 (management order
  is `ROLE_HIERARCHY`, all 64 pairs), P2 (member self-service floor), P3
  (feature-domain registry covers the granted vocabulary exactly), plus
  pinned lattice counterexamples documenting that chain-monotonicity is
  NOT an invariant (ratified: TIN-1606, TIN-2435). Docs:
  `docs/role-charter.md`.

### Patch Changes

- Clarify the package release authority: the TypeScript import API remains
  `@tummycrypt/tinyland-auth`, npmjs publication is disabled, GitHub Packages
  uses the `@tinyland-inc/tinyland-auth` mirror coordinate, and Bazel targets
  provide the package proof lane.

## 0.3.3

### Patch Changes

- Make TOTP and invitation exports compatible with both legacy `otplib` v12
  authenticator exports and modern `otplib` v13 functional exports used by
  SvelteKit SSR consumers.

## 0.3.2

### Patch Changes

- Disable package-level npm provenance so the self-hosted Bazel package publish
  lane can publish without npm rejecting the runner environment.

## 0.3.1

### Patch Changes

- Fix Node ESM consumption of the TOTP and invitation exports by importing the
  CommonJS `otplib` package through its default namespace.

## 0.2.2

### Patch Changes

- Roll forward published package versions so the next release re-establishes npm artifact truth for the current repo contents. This excludes `@tummycrypt/tinyland-schemas` because `0.2.1` is not published on npm yet.

## 0.2.1

### Patch Changes

- 429a49c: Strip .js.map sourcemaps from published packages and resolve workspace:\* dependencies to real version ranges.
