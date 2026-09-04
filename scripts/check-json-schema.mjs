import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function normalizePath(path) {
  return path.replaceAll("\\", "/");
}

function absolutePath(relativePath) {
  return resolve(repositoryRoot, ...relativePath.split("/"));
}

function readJson(relativePath) {
  try {
    return JSON.parse(readFileSync(absolutePath(relativePath), "utf8"));
  } catch (error) {
    throw new Error(`${relativePath}: ${error.message}`, { cause: error });
  }
}

function listJsonFiles(relativeDirectory) {
  const directory = absolutePath(relativeDirectory);
  return readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const relativeEntry = normalizePath(join(relativeDirectory, entry.name));
      return entry.isDirectory()
        ? listJsonFiles(relativeEntry)
        : entry.name.endsWith(".json")
          ? [relativeEntry]
          : [];
    })
    .sort();
}

function listSchemaFiles() {
  const rootSchemas = readdirSync(absolutePath("contracts"), { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".schema.json"))
    .map((entry) => `contracts/${entry.name}`);
  return [...rootSchemas, ...listJsonFiles("contracts/json-schema")]
    .filter((path) => path.endsWith(".schema.json"))
    .sort();
}

function formatValidationErrors(errors) {
  return (errors ?? [])
    .map((error) => {
      const location = error.instancePath || "$";
      const details = Object.keys(error.params ?? {}).length
        ? ` (${JSON.stringify(error.params)})`
        : "";
      return `${location} ${error.message ?? error.keyword}${details}`;
    })
    .join("; ");
}

function compileSchema(schemaPath) {
  const schema = readJson(schemaPath);
  if (schema.$schema !== "https://json-schema.org/draft/2020-12/schema") {
    throw new Error(`${schemaPath}: must declare JSON Schema 2020-12`);
  }

  const ajv = new Ajv2020({
    allErrors: true,
    allowUnionTypes: true,
    strict: true,
    validateSchema: true,
  });
  return ajv.compile(schema);
}

function documentValidationFailure(
  validate,
  schemaPath,
  documentPath,
  value = readJson(documentPath),
) {
  if (!validate(value)) {
    return `${documentPath}: does not satisfy ${schemaPath}: ${formatValidationErrors(validate.errors)}`;
  }
  return undefined;
}

function assertSamePaths(label, expected, actual) {
  const expectedSet = new Set(expected);
  const actualSet = new Set(actual);
  const missing = [...expectedSet].filter((path) => !actualSet.has(path));
  const unexpected = [...actualSet].filter((path) => !expectedSet.has(path));
  if (missing.length || unexpected.length) {
    throw new Error(
      `${label}: mapping is incomplete; missing=[${missing.join(", ")}], unexpected=[${unexpected.join(", ")}]`,
    );
  }
}

function contractAssignments() {
  return [
    {
      schema: "contracts/json-schema/foundation-health.schema.json",
      documents: ["contracts/fixtures/foundation-health.valid.json"],
    },
    {
      schema: "contracts/fixture-envelope.schema.json",
      documents: listJsonFiles("contracts/fixtures/task/v1"),
    },
    {
      schema: "contracts/collaboration-fixture-envelope.schema.json",
      documents: listJsonFiles("contracts/fixtures/collaboration/v1"),
    },
    {
      schema: "contracts/harness-fixture-envelope.schema.json",
      documents: listJsonFiles("contracts/fixtures/harness/v1"),
    },
    {
      schema: "contracts/artifact-fixture-envelope.schema.json",
      documents: listJsonFiles("contracts/fixtures/artifact/v1"),
    },
    {
      schema: "contracts/verification-fixture-envelope.schema.json",
      documents: listJsonFiles("contracts/fixtures/verification/v1"),
    },
    {
      schema: "contracts/verdict-fixture-envelope.schema.json",
      documents: listJsonFiles("contracts/fixtures/verdict/v1"),
    },
    {
      schema: "contracts/policy-fixture-envelope.schema.json",
      documents: listJsonFiles("contracts/fixtures/policy/v1"),
    },
    {
      schema: "contracts/localapi-fixture-envelope.schema.json",
      documents: listJsonFiles("contracts/fixtures/localapi/v1"),
    },
    {
      schema: "contracts/persistence-fixture-envelope.schema.json",
      documents: listJsonFiles("contracts/fixtures/persistence/v1"),
    },
    {
      schema: "contracts/authorization-capability-profile.schema.json",
      documents: ["contracts/profiles/authorization/v1/v01-default.json"],
    },
    {
      schema: "contracts/client-kernel-profile.schema.json",
      documents: ["contracts/profiles/client-kernel/v1/v01-default.json"],
    },
    {
      schema: "contracts/context-revoke-semantic-profile.schema.json",
      documents: ["contracts/profiles/context-revoke/v1/v01-default.json"],
    },
    {
      schema: "contracts/harness-content-disclosure-profile.schema.json",
      documents: ["contracts/profiles/harness-content-disclosure/v1/v01-default.json"],
    },
    {
      schema: "contracts/quality-budget-profile.schema.json",
      documents: ["contracts/profiles/quality-budget/v1/v01-default.json"],
    },
  ];
}

function assertStandardKeywordsAreEnforced(compiledSchemas) {
  const authorizationPath = "contracts/profiles/authorization/v1/v01-default.json";
  const invalidAuthorization = structuredClone(readJson(authorizationPath));
  invalidAuthorization.contractVersion = "not-semver";
  const authorizationValidator = compiledSchemas.get(
    "contracts/authorization-capability-profile.schema.json",
  );
  if (authorizationValidator(invalidAuthorization)) {
    throw new Error("JSON Schema regression: pattern constraints are not enforced");
  }
  if (!authorizationValidator.errors?.some((error) => error.keyword === "pattern")) {
    throw new Error("JSON Schema regression: invalid contractVersion did not fail by pattern");
  }

  const artifactPath = "contracts/fixtures/artifact/v1/valid-create-atomic-artifact-set.json";
  const invalidArtifact = structuredClone(readJson(artifactPath));
  invalidArtifact.expected.businessWriteCount = 2;
  const artifactValidator = compiledSchemas.get(
    "contracts/artifact-fixture-envelope.schema.json",
  );
  if (artifactValidator(invalidArtifact)) {
    throw new Error("JSON Schema regression: numeric maximum constraints are not enforced");
  }
  if (!artifactValidator.errors?.some((error) => error.keyword === "maximum")) {
    throw new Error("JSON Schema regression: invalid businessWriteCount did not fail by maximum");
  }
}

function main() {
  const assignments = contractAssignments();
  const assignedSchemas = assignments.map(({ schema }) => schema).sort();
  const assignedDocuments = assignments.flatMap(({ documents }) => documents).sort();
  const repositoryDocuments = [
    ...listJsonFiles("contracts/fixtures"),
    ...listJsonFiles("contracts/profiles"),
  ].sort();

  assertSamePaths("JSON Schema files", listSchemaFiles(), assignedSchemas);
  assertSamePaths("JSON Schema documents", repositoryDocuments, assignedDocuments);

  const compiledSchemas = new Map();
  const validationFailures = [];
  for (const { schema, documents } of assignments) {
    let validate;
    try {
      validate = compileSchema(schema);
    } catch (error) {
      validationFailures.push(`${schema}: invalid JSON Schema: ${error.message}`);
      continue;
    }
    compiledSchemas.set(schema, validate);
    for (const document of documents) {
      const failure = documentValidationFailure(validate, schema, document);
      if (failure) validationFailures.push(failure);
    }
  }

  if (validationFailures.length) {
    throw new Error(
      `JSON Schema document validation failed (${validationFailures.length}):\n${validationFailures.join("\n")}`,
    );
  }

  assertStandardKeywordsAreEnforced(compiledSchemas);
  console.log(
    `JSON Schema 2020-12 checks passed: schemas=${assignedSchemas.length}, documents=${assignedDocuments.length}, regression_cases=2`,
  );
}

main();
