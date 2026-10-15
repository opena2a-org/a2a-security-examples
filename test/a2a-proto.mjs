// The protocol definition that A2A specification v1.0.1 publishes, and a check
// of a JSON value against a message it defines.
//
// test/schema/a2a-v1.0.1.proto is specification/a2a.proto from
// https://github.com/a2aproject/A2A at tag v1.0.1, unchanged. Section 1.4 of
// the specification names it the single authoritative normative definition of
// the protocol's objects and messages; the JSON Schema published beside it is
// a non-normative build artifact that leaves out which fields are REQUIRED.
// The file's text has the SHA-256 in publishedSha256, as the published file
// has. To check:
//   curl -sL https://raw.githubusercontent.com/a2aproject/A2A/v1.0.1/specification/a2a.proto | shasum -a 256
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// The text with "\n" line endings, so the hash holds on a copy with "\r\n"
// ones. .gitattributes gives a checkout "\n" line endings, but a copy made
// outside git keeps the ones it was given.
export const protoText = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "schema/a2a-v1.0.1.proto"), "utf8").replace(/\r\n/g, "\n");

export const publishedSha256 = "e195bf96ab630c69797851970203e1b2b6b19528f2e9803b7d904b91a5104016";

export function textSha256(text) {
  return createHash("sha256").update(text).digest("hex");
}

// The name ProtoJSON gives a field in JSON: its proto name with each
// underscore dropped and the character after it capitalized.
export function jsonName(name) {
  return name.replace(/_(.)/g, (_, next) => next.toUpperCase());
}

const required = "(google.api.field_behavior) = REQUIRED";

// The messages and enums a proto file defines. A message has its fields, each
// with its proto name, JSON name, type (the value type for a map), whether it
// is repeated, whether it is a map and whether it is marked REQUIRED, and its
// oneofs, each the JSON names of its fields. An enum has its value names and
// the name of its value numbered 0. The service and the file options are
// passed over. The reader throws on a line it does not know, so that a form it
// does not read fails a test instead of being skipped.
export function readProto(text) {
  const messages = new Map();
  const enums = new Map();
  let block;
  let oneof;
  let depth = 0;
  text.split("\n").forEach((raw, index) => {
    const where = `line ${index + 1}`;
    // Strings first, so that a // or a brace inside one is not read.
    const line = raw.replace(/"[^"]*"/g, '""').replace(/\/\/.*$/, "").trim();
    if (line === "") return;
    let m;
    if (block === undefined) {
      if ((m = line.match(/^message (\w+) \{$/))) {
        block = { kind: "message", fields: [], oneofs: [] };
        messages.set(m[1], block);
      } else if ((m = line.match(/^enum (\w+) \{$/))) {
        block = { kind: "enum", names: [], zero: undefined };
        enums.set(m[1], block);
      } else if (/^service \w+ \{$/.test(line)) {
        block = { kind: "service" };
        depth = 1;
      } else if (!/^(syntax|package|import|option) [^{}]*;$/.test(line)) {
        throw new Error(`${where}: the reader does not know ${raw.trim()}`);
      }
      return;
    }
    if (block.kind === "service") {
      depth += (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
      if (depth === 0) block = undefined;
      return;
    }
    if (line === "}") {
      if (oneof) oneof = undefined;
      else block = undefined;
      return;
    }
    if (block.kind === "enum") {
      if (!(m = line.match(/^(\w+) = (\d+);$/))) throw new Error(`${where}: the reader does not know ${raw.trim()}`);
      block.names.push(m[1]);
      if (m[2] === "0") block.zero = m[1];
      return;
    }
    if (!oneof && (m = line.match(/^oneof \w+ \{$/))) {
      oneof = [];
      block.oneofs.push(oneof);
      return;
    }
    m = line.match(/^(repeated |optional )?(?:map<string, ([\w.]+)>|([\w.]+)) (\w+) = \d+(?: \[(.+)\])?;$/);
    if (!m) throw new Error(`${where}: the reader does not know ${raw.trim()}`);
    const [, label, mapValue, type, name, options = ""] = m;
    for (const option of options.split(", ").filter(Boolean)) {
      if (option !== required && option !== "deprecated = true") throw new Error(`${where}: the reader does not know the option ${option}`);
    }
    const field = {
      name,
      json: jsonName(name),
      type: mapValue ?? type,
      repeated: label === "repeated ",
      map: mapValue !== undefined,
      required: options.split(", ").includes(required),
    };
    block.fields.push(field);
    if (oneof) oneof.push(field.json);
  });
  if (block !== undefined) throw new Error("the file ends inside a block");
  return { messages, enums };
}

export const proto = readProto(protoText);

// The scalar and well-known types the check knows, beside the messages and
// enums the proto defines.
const scalars = ["string", "bool", "int32", "bytes", "google.protobuf.Struct", "google.protobuf.Value", "google.protobuf.Timestamp"];

// The types of fields the proto defines that the check does not know, so that
// a proto using one fails a test instead of being checked in part.
export function unknownTypes(definitions = proto) {
  const known = (type) => scalars.includes(type) || definitions.messages.has(type) || definitions.enums.has(type);
  const types = [...definitions.messages.values()].flatMap((message) => message.fields.map((field) => field.type));
  return [...new Set(types.filter((type) => !known(type)))];
}

// The ways value fails to be the JSON of the message called name, one
// "path: reason" line each, or an empty list when it passes. A value is read
// as ProtoJSON (https://protobuf.dev/programming-guides/json/) reads it, which
// section 5.5 of the specification names, with these differences:
// - a field must have its JSON name: ProtoJSON also reads the proto name, as
//   default_input_modes for defaultInputModes, and section 5.5 says JSON uses
//   camelCase;
// - an enum value must be its name, not its number, as section 5.5 says;
// - an int32 must be a JSON number, not a string;
// - null fails for any field but a google.protobuf.Value, where ProtoJSON reads
//   it as the field's default;
// - a field the message does not define fails. Section 5.7 says a reader
//   should ignore one, so a field the specification does not define, or a
//   misspelled one, would otherwise pass unnoticed.
// It adds two checks the proto states and ProtoJSON does not make: a field
// marked REQUIRED is present and set (section 5.7), which for a string is not
// empty, for a list holds at least one element and for an enum is not the
// value numbered 0; and at most one field of a oneof is set.
export function protoErrors(name, value, path = name) {
  return messageErrors(name, value, path);
}

function messageErrors(name, value, path) {
  const message = proto.messages.get(name);
  if (!message) throw new Error(`${path}: the proto defines no message ${name}`);
  if (!isObject(value)) return [`${path}: is not an object`];
  const errors = [];
  for (const [key, item] of Object.entries(value)) {
    const field = message.fields.find((f) => f.json === key);
    if (field) errors.push(...fieldErrors(field, item, `${path}.${key}`));
    else if (message.fields.some((f) => f.name === key)) errors.push(`${path}.${key}: is the proto name of ${jsonName(key)}, which JSON uses`);
    else errors.push(`${path}.${key}: is not a field of ${name}`);
  }
  for (const field of message.fields.filter((f) => f.required)) {
    if (!Object.hasOwn(value, field.json)) errors.push(`${path}.${field.json}: is required`);
    else if (!isSet(field, value[field.json])) errors.push(`${path}.${field.json}: is required and is not set`);
  }
  for (const fields of message.oneofs) {
    const set = fields.filter((key) => Object.hasOwn(value, key));
    if (set.length > 1) errors.push(`${path}: sets ${set.join(" and ")}, which are one oneof`);
  }
  return errors;
}

function fieldErrors(field, item, path) {
  if (field.map) {
    if (!isObject(item)) return [`${path}: is not an object`];
    return Object.entries(item).flatMap(([key, entry]) => typeErrors(field.type, entry, `${path}.${key}`));
  }
  if (field.repeated) {
    if (!Array.isArray(item)) return [`${path}: is not an array`];
    return item.flatMap((entry, i) => typeErrors(field.type, entry, `${path}[${i}]`));
  }
  return typeErrors(field.type, item, path);
}

// Whether a field marked REQUIRED is set. A value of the wrong type counts as
// set here, since fieldErrors reports it.
function isSet(field, item) {
  if (field.repeated && Array.isArray(item)) return item.length > 0;
  if (field.repeated || field.map) return true;
  if (field.type === "string") return item !== "";
  const values = proto.enums.get(field.type);
  return values === undefined || item !== values.zero;
}

function typeErrors(type, item, path) {
  if (item === null && type !== "google.protobuf.Value") return [`${path}: is null`];
  const fails = (reason) => [`${path}: ${reason}`];
  switch (type) {
    case "string":
      return typeof item === "string" ? [] : fails("is not a string");
    case "bool":
      return typeof item === "boolean" ? [] : fails("is not a boolean");
    case "int32":
      return Number.isInteger(item) && item >= -(2 ** 31) && item < 2 ** 31 ? [] : fails("is not a 32-bit integer");
    case "bytes":
      // ProtoJSON reads the standard and the URL-safe base64 alphabets, with
      // or without padding.
      return typeof item === "string" && /^[A-Za-z0-9+/_-]*={0,2}$/.test(item) ? [] : fails("is not base64");
    case "google.protobuf.Struct":
      return isObject(item) ? [] : fails("is not an object");
    case "google.protobuf.Value":
      return [];
    case "google.protobuf.Timestamp":
      return typeof item === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,9})?(Z|[+-]\d\d:\d\d)$/.test(item) ? [] : fails("is not an RFC 3339 timestamp");
  }
  const values = proto.enums.get(type);
  if (values) return values.names.includes(item) ? [] : fails(`is not a value of ${type}`);
  if (proto.messages.has(type)) return messageErrors(type, item, path);
  throw new Error(`${path}: the check does not know the type ${type}`);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

// The fields of the example agent card that A2A v1.0 defines and v0.3.0 does
// not, and those that v0.3.0 defines and v1.0 does not, each as the keys that
// lead to it. The card carries both: section 5.7 of v1.0 says an
// implementation should ignore a field it does not recognize, and the JSON
// Schema of v0.3.0 allows fields it does not define. So the check for each
// version reads the card without the other version's fields.
export const v1Fields = [["supportedInterfaces"], ["securityRequirements"], ["securitySchemes", "bearer", "httpAuthSecurityScheme"]];

export const v03Fields = [
  ["url"],
  ["protocolVersion"],
  ["preferredTransport"],
  ["security"],
  ["capabilities", "stateTransitionHistory"],
  ["securitySchemes", "bearer", "type"],
  ["securitySchemes", "bearer", "scheme"],
];

// A copy of value without the fields at paths.
export function withoutFields(value, paths) {
  const copy = structuredClone(value);
  for (const path of paths) {
    const parent = path.slice(0, -1).reduce((node, key) => node?.[key], copy);
    if (isObject(parent)) delete parent[path.at(-1)];
  }
  return copy;
}
