import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

const readText = (path: string) => readFile(path, 'utf8');
const normalizeWhitespace = (value: string) => value.replace(/\s+/g, ' ');

describe('package release authority', () => {
  it('keeps the TypeScript import API under the @tummycrypt scope', async () => {
    const packageJson = JSON.parse(await readText('package.json')) as {
      name?: string;
      publishConfig?: unknown;
    };
    const buildBazel = await readText('BUILD.bazel');

    expect(packageJson.name).toBe('@tummycrypt/tinyland-auth');
    expect(packageJson.publishConfig).toBeUndefined();
    expect(buildBazel).toContain('package = "@tummycrypt/tinyland-auth"');
  });

  it('keeps npmjs publication disabled in package workflows', async () => {
    const workflowPaths = ['.github/workflows/ci.yml', '.github/workflows/publish.yml'];

    for (const workflowPath of workflowPaths) {
      const workflow = await readText(workflowPath);

      expect(workflow).toContain('runner_mode: repo_owned');
      expect(workflow).toContain('runner_labels_json: ${{ vars.PRIMARY_LINUX_RUNNER_LABELS_JSON }}');
      expect(workflow).toContain('bazel_targets: "//:pkg //:test //:typecheck"');
      expect(workflow).toContain('npm_publish_mode: disabled');
      expect(workflow).toContain('github_package_name: "@tinyland-inc/tinyland-auth"');
    }
  });

  it('documents Bazel-first release authority for consumers', async () => {
    const readme = await readText('README.md');
    const mvpDoc = await readText('docs/tinyland-databaseless-auth-mvp.md');

    expect(readme).toContain('npmjs publication is disabled');
    expect(readme).toContain('GitHub Packages mirror');
    expect(readme).toContain('Tinyland Bazel registry');
    expect(readme).toContain('repo-owned GloriousFlywheel runner lane');
    expect(mvpDoc).toContain('`//:pkg //:test //:typecheck`');
    expect(mvpDoc).toContain('repo-owned GloriousFlywheel runner lane');
    expect(normalizeWhitespace(mvpDoc)).toContain('npmjs publication is disabled');
  });
});
