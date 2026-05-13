# @tummycrypt/tinyland-auth

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
