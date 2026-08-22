import { readFileSync } from "node:fs";

const schema = JSON.parse(
  readFileSync("contracts/json-schema/foundation-health.schema.json", "utf8")
);
const fixture = JSON.parse(
  readFileSync("contracts/fixtures/foundation-health.valid.json", "utf8")
);

if (schema.$schema !== "https://json-schema.org/draft/2020-12/schema") {
  throw new Error("Foundation schema must use JSON Schema 2020-12");
}
for (const key of schema.required ?? []) {
  if (!(key in fixture)) throw new Error(`Fixture is missing required key: ${key}`);
}
if (!schema.properties.state.enum.includes(fixture.state)) {
  throw new Error("Fixture state is not allowed by schema");
}
if (fixture.architectureVersion !== schema.properties.architectureVersion.const) {
  throw new Error("Fixture architecture version does not match schema");
}

console.log("JSON Schema fixture check passed");
