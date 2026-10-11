// The JSON Schema that A2A specification v0.3.0 publishes, and a validator for
// the part of JSON Schema draft-07 that it uses.
//
// test/schema/a2a-v0.3.0.json is specification/json/a2a.json from
// https://github.com/a2aproject/A2A at tag v0.3.0, indented with 2 spaces
// instead of 4. Its content is unchanged: JSON.stringify of the parsed file has
// the SHA-256 in publishedSha256, as it has for the published file. To check:
//   curl -sL https://raw.githubusercontent.com/a2aproject/A2A/v0.3.0/specification/json/a2a.json |
//     node -e 'let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () =>
//       console.log(require("node:crypto").createHash("sha256").update(JSON.stringify(JSON.parse(s))).digest("hex")))'
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const schema = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "schema/a2a-v0.3.0.json"), "utf8")
);

export const publishedSha256 = "4fa158d64ec2b6d7608fa258241cb03f24e745421ad384ffa0fcfe3c14d54f57";

export function contentSha256(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

// The keywords the validator applies, and the annotations it reads past.
const applied = ["$ref", "type", "const", "enum", "anyOf", "required", "properties", "additionalProperties", "items"];
const annotations = ["description", "examples", "default"];

// The keywords of the schema nodes under node that the validator neither
// applies nor reads past as annotations, so that a schema using one fails a
// test instead of being checked in part.
export function unknownKeywords(node = schema) {
  if (typeof node === "boolean") return [];
  const nested = [
    ...Object.values(node.definitions ?? {}),
    ...Object.values(node.properties ?? {}),
    ...(node.anyOf ?? []),
    ...[node.items, node.additionalProperties].filter((child) => child !== undefined),
  ];
  const own = Object.keys(node).filter((k) => !applied.includes(k) && !annotations.includes(k) && k !== "$schema" && k !== "definitions");
  return [...new Set([...own, ...nested.flatMap((child) => unknownKeywords(child))])];
}

// The ways value fails the definition called name, one "path: reason" line
// each, or an empty list when it passes. Beyond draft-07, a property that an
// object schema with properties does not list fails too, unless the schema sets
// additionalProperties. The published schema leaves additional properties
// open, and a client written to it ignores one, so a field the specification
// does not define, or a misspelled one, would otherwise pass unnoticed.
export function schemaErrors(name, value, definitions = schema.definitions) {
  return check({ $ref: `#/definitions/${name}` }, value, name, definitions);
}

function check(node, value, path, definitions) {
  if (node === true) return [];
  if (node === false) return [`${path}: is not allowed`];
  const unknown = Object.keys(node).filter((k) => !applied.includes(k) && !annotations.includes(k));
  if (unknown.length > 0) throw new Error(`${path}: the validator does not apply ${unknown.join(", ")}`);
  const errors = [];
  if (node.$ref !== undefined) {
    const target = node.$ref.match(/^#\/definitions\/(.+)$/)?.[1];
    if (!target || !Object.hasOwn(definitions, target)) throw new Error(`${path}: ${node.$ref} names no definition`);
    errors.push(...check(definitions[target], value, path, definitions));
  }
  if (node.type !== undefined) {
    const types = [node.type].flat();
    if (!types.some((type) => isType(value, type))) return [...errors, `${path}: is not of type ${types.join(" or ")}`];
  }
  if (Object.hasOwn(node, "const") && value !== node.const) errors.push(`${path}: is not ${JSON.stringify(node.const)}`);
  if (node.enum !== undefined && !node.enum.includes(value)) {
    errors.push(`${path}: is not one of ${node.enum.map((v) => JSON.stringify(v)).join(", ")}`);
  }
  if (node.anyOf !== undefined && !node.anyOf.some((branch) => check(branch, value, path, definitions).length === 0)) {
    errors.push(`${path}: matches none of the schemas in anyOf`);
  }
  if (isType(value, "object")) {
    for (const key of node.required ?? []) {
      if (!Object.hasOwn(value, key)) errors.push(`${path}.${key}: is required`);
    }
    for (const [key, item] of Object.entries(value)) {
      if (node.properties !== undefined && Object.hasOwn(node.properties, key)) {
        errors.push(...check(node.properties[key], item, `${path}.${key}`, definitions));
      } else if (node.additionalProperties !== undefined) {
        errors.push(...check(node.additionalProperties, item, `${path}.${key}`, definitions));
      } else if (node.properties !== undefined) {
        errors.push(`${path}.${key}: is not a property the schema defines`);
      }
    }
  }
  if (Array.isArray(value) && node.items !== undefined) {
    value.forEach((item, i) => errors.push(...check(node.items, item, `${path}[${i}]`, definitions)));
  }
  return errors;
}

function isType(value, type) {
  switch (type) {
    case "object":
      return value !== null && typeof value === "object" && !Array.isArray(value);
    case "array":
      return Array.isArray(value);
    case "integer":
      return Number.isInteger(value);
    case "number":
      return typeof value === "number";
    case "null":
      return value === null;
    case "string":
    case "boolean":
      return typeof value === type;
    default:
      throw new Error(`the validator does not know the type ${type}`);
  }
}
