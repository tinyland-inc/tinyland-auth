import { readFile } from "node:fs/promises";

const packageJson = JSON.parse(await readFile("package.json", "utf8"));
const moduleBazel = await readFile("MODULE.bazel", "utf8");
const buildBazel = await readFile("BUILD.bazel", "utf8");
const changelog = await readFile("CHANGELOG.md", "utf8");

const moduleVersion = moduleBazel.match(
  /module\([\s\S]*?\bversion\s*=\s*"([^"]+)"/,
)?.[1];
const packageRuleVersion = buildBazel.match(
  /npm_package\([\s\S]*?\bversion\s*=\s*"([^"]+)"/,
)?.[1];
const packageVersion = packageJson.version;

const failures = [];

for (const [surface, version] of [
  ["MODULE.bazel", moduleVersion],
  ["BUILD.bazel npm_package", packageRuleVersion],
]) {
  if (version !== packageVersion) {
    failures.push(
      `${surface} version ${JSON.stringify(version)} does not match package.json ${JSON.stringify(packageVersion)}`,
    );
  }
}

if (!changelog.includes(`## ${packageVersion}\n`)) {
  failures.push(`CHANGELOG.md has no release heading for ${packageVersion}`);
}

if (process.env.GITHUB_REF_TYPE === "tag") {
  const expectedTag = `v${packageVersion}`;
  if (process.env.GITHUB_REF_NAME !== expectedTag) {
    failures.push(
      `release tag ${JSON.stringify(process.env.GITHUB_REF_NAME)} does not match ${expectedTag}`,
    );
  }
}

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`release metadata error: ${failure}`);
  }
  process.exit(1);
}

console.log(`release metadata aligned at ${packageVersion}`);
