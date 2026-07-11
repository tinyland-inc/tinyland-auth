import { access, readFile } from 'node:fs/promises';
import ts from 'typescript';

const surfaces = ['src/index.ts', 'dist/index.d.ts'];
const retainedCompatibilityTypes = [
  'AdminInvitation',
  'InvitationConfig',
  'InvitationStorage',
  'InvitationCreateRequest',
  'InvitationCreateResponse',
  'InvitationAcceptRequest',
  'InvitationAcceptResponse',
  'InvitationListResponse',
  'InvitationRevokeRequest',
  'InvitationRevokeResponse',
];

function exportedNames(source, filename) {
  const sourceFile = ts.createSourceFile(
    filename,
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const names = new Set();

  for (const statement of sourceFile.statements) {
    if (
      ts.isExportDeclaration(statement) &&
      statement.exportClause &&
      ts.isNamedExports(statement.exportClause)
    ) {
      for (const element of statement.exportClause.elements) {
        names.add(element.name.text);
      }
      continue;
    }

    const exported = statement.modifiers?.some(
      (modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword,
    );
    if (!exported) continue;

    if ('name' in statement && statement.name && ts.isIdentifier(statement.name)) {
      names.add(statement.name.text);
    }

    if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        if (ts.isIdentifier(declaration.name)) {
          names.add(declaration.name.text);
        }
      }
    }
  }

  return names;
}

function isExecutableInvitationAuthority(name) {
  return (
    /^(?:create|mint|issue|accept|revoke|extend|list|get|generate)(?:Invitation|Invite)/i.test(
      name,
    ) ||
    /^(?:Invitation|Invite).*(?:Service|Factory|Manager|Authority)/i.test(name)
  );
}

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
      return false;
    }
    throw error;
  }
}

const failures = [];

for (const surface of surfaces) {
  const names = exportedNames(await readFile(surface, 'utf8'), surface);
  const executableExports = [...names].filter(isExecutableInvitationAuthority);

  if (executableExports.length > 0) {
    failures.push(`${surface} exports invitation authority: ${executableExports.join(', ')}`);
  }

  for (const retained of retainedCompatibilityTypes) {
    if (!names.has(retained)) {
      failures.push(`${surface} no longer exports retained compatibility type ${retained}`);
    }
  }
}

const packageJson = JSON.parse(await readFile('package.json', 'utf8'));
const invitationSubpaths = Object.keys(packageJson.exports ?? {}).filter((path) =>
  /invitation|invite/i.test(path),
);
if (invitationSubpaths.length > 0) {
  failures.push(`package.json exposes invitation subpaths: ${invitationSubpaths.join(', ')}`);
}

for (const implementationPath of [
  'src/modules/invitation/index.ts',
  'dist/modules/invitation/index.js',
  'dist/modules/invitation/index.d.ts',
]) {
  if (await exists(implementationPath)) {
    failures.push(`duplicate invitation implementation exists at ${implementationPath}`);
  }
}

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`invitation authority error: ${failure}`);
  }
  process.exit(1);
}

console.log(
  `invitation authority surface clean; retained compatibility types: ${retainedCompatibilityTypes.join(', ')}`,
);
