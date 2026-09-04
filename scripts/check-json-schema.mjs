import { readFileSync } from "node:fs";

function fail(path, message) {
  throw new Error(`${path}: ${message}`);
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function validate(schema, value, path = "$") {
  if (Object.hasOwn(schema, "const") && !sameJson(value, schema.const)) {
    fail(path, `must equal ${JSON.stringify(schema.const)}`);
  }
  if (schema.enum && !schema.enum.some((candidate) => sameJson(value, candidate))) {
    fail(path, `must be one of ${JSON.stringify(schema.enum)}`);
  }

  if (schema.type === "object") {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      fail(path, "must be an object");
    }
    for (const key of schema.required ?? []) {
      if (!Object.hasOwn(value, key)) fail(`${path}.${key}`, "is required");
    }
    if (schema.additionalProperties === false) {
      const known = new Set(Object.keys(schema.properties ?? {}));
      for (const key of Object.keys(value)) {
        if (!known.has(key)) fail(`${path}.${key}`, "is an unknown property");
      }
    }
    for (const [key, childSchema] of Object.entries(schema.properties ?? {})) {
      if (Object.hasOwn(value, key)) validate(childSchema, value[key], `${path}.${key}`);
    }
    return;
  }

  if (schema.type === "array") {
    if (!Array.isArray(value)) fail(path, "must be an array");
    if (schema.minItems !== undefined && value.length < schema.minItems) fail(path, `must contain at least ${schema.minItems} items`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) fail(path, `must contain at most ${schema.maxItems} items`);
    if (schema.uniqueItems && new Set(value.map((entry) => JSON.stringify(entry))).size !== value.length) fail(path, "must contain unique items");
    value.forEach((entry, index) => validate(schema.items ?? {}, entry, `${path}[${index}]`));
    return;
  }

  if (schema.type === "string") {
    if (typeof value !== "string") fail(path, "must be a string");
    if (schema.minLength !== undefined && value.length < schema.minLength) fail(path, `must contain at least ${schema.minLength} characters`);
    return;
  }

  if (schema.type === "integer" && !Number.isInteger(value)) fail(path, "must be an integer");
  if (schema.type === "number" && typeof value !== "number") fail(path, "must be a number");
  if (schema.type === "boolean" && typeof value !== "boolean") fail(path, "must be a boolean");
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

const foundationSchema = readJson("contracts/json-schema/foundation-health.schema.json");
const foundationFixture = readJson("contracts/fixtures/foundation-health.valid.json");
if (foundationSchema.$schema !== "https://json-schema.org/draft/2020-12/schema") {
  throw new Error("Foundation schema must use JSON Schema 2020-12");
}
validate(foundationSchema, foundationFixture, "foundation-health.valid.json");

const disclosureSchema = readJson("contracts/harness-content-disclosure-profile.schema.json");
const disclosureProfile = readJson("contracts/profiles/harness-content-disclosure/v1/v01-default.json");
if (disclosureSchema.$schema !== "https://json-schema.org/draft/2020-12/schema") {
  throw new Error("Harness content disclosure schema must use JSON Schema 2020-12");
}
validate(disclosureSchema, disclosureProfile, "harness-content-disclosure/v01-default.json");

console.log("JSON Schema fixture/profile checks passed");
