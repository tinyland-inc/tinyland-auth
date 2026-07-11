#!/usr/bin/env bash
set -euo pipefail

printf 'Executing Bazel tests: //:test (and building //:typecheck)\n'
npx --yes @bazel/bazelisk test //:test //:typecheck --test_output=errors
