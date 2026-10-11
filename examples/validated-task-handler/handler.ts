/**
 * Validated A2A Task Handler
 *
 * An agent written to A2A specification v0.3.0: it answers the JSON-RPC 2.0
 * method message/send at POST / and serves its agent card at
 * /.well-known/agent-card.json. It also answers POST /a2a/message, a route
 * A2A v0.3.0 does not define, which the a2a target of the HackMyAgent scanner
 * posts its payloads to.
 *
 * Demonstrates secure task handling with:
 * - Zod schema validation on all inputs
 * - Prompt injection detection
 * - Rate limiting per client
 * - Audit logging
 * - Proper error handling (no internal detail leaks)
 *
 * Test an agent against A2A attack pages that each hide an indirect prompt
 * injection (agent impersonation, delegation abuse and worm propagation):
 * https://agentpwn.com/attacks/a2a-attack
 */

import express from "express";
import { z } from "zod";
import { randomUUID } from "crypto";
import { readFileSync } from "fs";
import { dirname, join } from "path";
import { RateLimiterMemory } from "rate-limiter-flexible";

const app = express();
// Express names itself in an X-Powered-By header on every response otherwise.
app.disable("x-powered-by");
const port = parsePort(process.env.PORT ?? "3000");

// Exit with one line naming the variable instead of the stack trace that
// app.listen throws for a port it cannot use. An empty PORT is rejected like
// any other value that is not a port, not treated as unset.
function parsePort(value: string): number {
  const parsed = /^\d+$/.test(value) ? Number(value) : NaN;
  if (!(parsed >= 1 && parsed <= 65535)) {
    console.error(`PORT must be a number from 1 to 65535; got ${JSON.stringify(value)}`);
    process.exit(1);
  }
  return parsed;
}

// --- Rate Limiting ---

// The limiter counts each client's requests for 60 seconds from its first one,
// and starts again with its first request after those 60 seconds have ended.
// It keys on req.ip. Behind a reverse proxy, req.ip is the proxy's address
// unless the deployment sets Express's "trust proxy" to the proxies it runs,
// and without that every client behind the proxy shares one count. Name their
// addresses, as in app.set("trust proxy", "10.0.0.2") for one proxy at
// 10.0.0.2, and never set it to true: req.ip would then be the leftmost
// X-Forwarded-For address, which the client chooses, so a client that sends a
// different one with each request would never be limited.
const rateLimiter = new RateLimiterMemory({
  points: 30, // requests
  duration: 60, // per minute
});

// --- Input Schemas ---

// The JSON-RPC 2.0 request and the message/send params of A2A specification
// v0.3.0, narrowed to what this agent accepts: text parts, and file parts that
// carry base64 bytes with an allowlisted MIME type. A file part that gives a
// URI instead of bytes is rejected, not fetched, and so is a data part.

const MEDIA_TYPES = ["text/plain", "application/json", "application/pdf", "image/png", "image/jpeg"] as const;

const RequestIdSchema = z.union([z.string().max(128), z.number().int()]);

const JsonRpcRequestSchema = z.object({
  jsonrpc: z.literal("2.0"),
  id: RequestIdSchema,
  method: z.string(),
  params: z.unknown(),
});

const TextPartSchema = z.object({
  kind: z.literal("text"),
  text: z.string().min(1).max(10000),
});

const FilePartSchema = z.object({
  kind: z.literal("file"),
  file: z.object({
    bytes: z.string().max(1048576), // 1MB base64
    mimeType: z.enum(MEDIA_TYPES),
    name: z.string().max(255).optional(),
  }),
});

const PartSchema = z.discriminatedUnion("kind", [TextPartSchema, FilePartSchema]);

const MessageSchema = z.object({
  kind: z.literal("message"),
  messageId: z.string().min(1).max(128),
  role: z.enum(["user", "agent"]),
  parts: z.array(PartSchema).min(1).max(10),
  contextId: z.string().min(1).max(128).optional(),
  taskId: z.string().min(1).max(128).optional(),
});

const MessageSendParamsSchema = z.object({
  message: MessageSchema,
  metadata: z.record(z.string(), z.string().max(1000)).optional(),
});

// The message HackMyAgent's a2a target sends in place of a JSON-RPC request:
// the names of the sending and receiving agents and one text payload, which
// has the bounds of a text part.
const AgentMessageSchema = z.object({
  from: z.string().min(1).max(200),
  to: z.string().min(1).max(200),
  content: TextPartSchema.shape.text,
});

// --- Prompt Injection Detection ---

const INJECTION_PATTERNS = [
  /ignore\s+(previous|above|all)\s+(instructions|prompts|rules)/i,
  /disregard\s+(your|the|all)\s+(system|previous)/i,
  /you\s+are\s+now\s+a/i,
  /new\s+instructions?\s*:/i,
  /IMPORTANT\s*:\s*(override|ignore|forget)/i,
  /system\s*:\s*/i,
  /<\s*system\s*>/i,
  /\[INST\]/i,
  /<<\s*SYS\s*>>/i,
  /\bdo\s+not\s+follow\s+(your|the|any)\s+rules\b/i,
  /\bpretend\s+(you|that)\b.*\b(admin|root|unrestricted)\b/i,
];

function containsInjection(text: string): boolean {
  return INJECTION_PATTERNS.some((pattern) => pattern.test(text));
}

// --- Audit Logging ---

interface AuditEntry {
  timestamp: string;
  taskId: string;
  clientIp: string;
  action: string;
  details: Record<string, unknown>;
}

function audit(entry: AuditEntry): void {
  // In production, send to structured logging service
  console.log(JSON.stringify(entry));
}

// --- Header Line Limit ---

// The number of header lines at which a request gets 431. Node.js 22.23.2,
// 24.18.1, 26.5.1 and later releases of those three lines answer a request
// with more than that with a bare HTTP 431 before any handler runs. Node.js 18
// and 20, and Node.js 22, 24 and 26 releases before those, instead pass the
// request on. There, req.headers is built from the first 1,000 lines only, and
// req.rawHeaders holds the first 1,000 or, on releases such as 18.20.8,
// 20.20.2, 22.0.0 and 24.0.0, up to the first 1,023, so a later line, such as
// a second Authorization header, may be in neither. A request that has this
// many may have had more, so it gets 431 here whichever release runs the
// example.
const maxHeaderLines = 1000;

function limitHeaderLines(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): void {
  // rawHeaders holds the name and then the value of each header line.
  if (req.rawHeaders.length >= maxHeaderLines * 2) {
    res.status(431).json({ error: "Too many header lines" });
    return;
  }
  next();
}

app.use(limitHeaderLines);

// --- Authentication Middleware ---

// The challenge each 401 response, and each 400 response to a malformed
// Authorization header, carries. A 401 response names the scheme the
// server accepts in a challenge (RFC 9110, section 15.5.2), and RFC 6750,
// section 3, says the Bearer scheme in it is followed by one or more
// auth-params, here a realm.
const bearerChallenge = 'Bearer realm="a2a"';

// An Authorization header value that names the Bearer scheme: it starts with
// the scheme name, in any letter case (RFC 9110, section 11.1), and the next
// character, if there is one, is not one a longer scheme name could hold
// (sections 5.6.2 and 11.4), so Bearerx names another scheme.
const bearerScheme = /^bearer(?![!#$%&'*+.^_`|~0-9a-z-])/i;

// The number of Authorization header lines in a request.
function authorizationLines(req: express.Request): number {
  return req.rawHeaders.filter((name, i) => i % 2 === 0 && name.toLowerCase() === "authorization").length;
}

// RFC 6750, section 3.1: a request that repeats a parameter or is otherwise
// malformed gets 400 and the error code invalid_request in the challenge.
function rejectMalformed(req: express.Request, res: express.Response, error: string, reason: string): void {
  auditAuthFailure(req, 400, reason);
  res.status(400).set("WWW-Authenticate", `${bearerChallenge}, error="invalid_request"`).json({ error });
}

// Each request that fails authentication writes an audit line with the status
// it gets and the reason, never the header or the token.
function auditAuthFailure(req: express.Request, status: number, reason: string): void {
  audit({
    timestamp: new Date().toISOString(),
    taskId: randomUUID(),
    clientIp: req.ip || "unknown",
    action: "auth_failed",
    details: { status, reason },
  });
}

function authenticate(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): void {
  // Node.js keeps the first Authorization header line of a request and drops
  // the rest, so the first line alone would decide the answer. A request with
  // more than one is rejected whichever comes first: a server in front of
  // this one may have read another line.
  if (authorizationLines(req) > 1) {
    rejectMalformed(req, res, "More than one Authorization header", "repeated_header");
    return;
  }

  // A request with no Authorization header, or one that names another scheme,
  // has no bearer token to check, so its 401 carries no error code (RFC 6750,
  // section 3.1).
  const authHeader = req.headers.authorization;
  if (authHeader === undefined || !bearerScheme.test(authHeader)) {
    auditAuthFailure(req, 401, authHeader ? "other_scheme" : "no_credentials");
    res.status(401).set("WWW-Authenticate", bearerChallenge).json({ error: "Authentication required" });
    return;
  }

  // Scheme names are case-insensitive (RFC 9110, section 11.1), and one or
  // more spaces may separate the scheme from the token (section 11.4); none
  // of them is part of the token. The token is made of the characters RFC
  // 6750, section 2.1, allows in a bearer token and of no others. Node.js
  // decodes header bytes as Latin-1, so a pattern that took any character but
  // a space would reject a token outside ASCII only when one of its bytes is
  // 0xA0, a no-break space in Latin-1.
  const credentials = authHeader.match(/^bearer +([A-Za-z0-9._~+\/-]+=*)$/i);
  if (!credentials) {
    rejectMalformed(req, res, "Malformed Authorization header", "malformed_header");
    return;
  }

  const token = credentials[1];

  // Validate token (replace with your auth provider)
  // NEVER log the full token
  if (!isValidToken(token)) {
    // RFC 6750, section 3.1: a token that is invalid or expired gets 401 and
    // the error code invalid_token in the challenge.
    auditAuthFailure(req, 401, "invalid_token");
    res.status(401).set("WWW-Authenticate", `${bearerChallenge}, error="invalid_token"`).json({ error: "Invalid or expired token" });
    return;
  }

  next();
}

function isValidToken(token: string): boolean {
  // Replace with real token validation (JWT verification, OAuth introspection, etc.)
  // See: https://agentpwn.com/tools/openai-api-key-management for API key best practices
  return token.length > 0 && token !== "undefined";
}

// --- Rate Limiting Middleware ---

async function rateLimit(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): Promise<void> {
  const clientIp = req.ip || "unknown";
  try {
    await rateLimiter.consume(clientIp);
  } catch {
    audit({
      timestamp: new Date().toISOString(),
      taskId: randomUUID(),
      clientIp,
      action: "rate_limited",
      details: {},
    });
    res.status(429).json({ error: "Too many requests" });
    return;
  }

  next();
}

// --- JSON-RPC Responses ---

type RequestId = z.infer<typeof RequestIdSchema> | null;

interface RpcError {
  code: number;
  message: string;
  data?: { field: string; message: string }[];
}

// A JSON-RPC 2.0 error response. id is the request's id, or null when the
// request has no valid one.
function sendError(res: express.Response, status: number, id: RequestId, error: RpcError) {
  return res.status(status).json({ jsonrpc: "2.0", id, error });
}

// The id of a request that failed validation, when it has a valid one.
function requestIdOf(body: unknown): RequestId {
  const parsed = RequestIdSchema.safeParse((body as { id?: unknown } | null)?.id);
  return parsed.success ? parsed.data : null;
}

// Only expose field-level errors, not internal details
function fieldErrors(issues: z.ZodIssue[], prefix: string[] = []) {
  return issues.map((i) => ({ field: [...prefix, ...i.path].join("."), message: i.message }));
}

// What a route reads from a body: the message/send params, or the error for
// the first check that fails, each with the id the reply answers.
type ParsedRequest =
  | { id: RequestId; error: RpcError }
  | { id: RequestId; params: z.infer<typeof MessageSendParamsSchema> };

// Check the JSON-RPC request, its method, then its params, and return the
// message/send params or the error for the first check that fails.
function parseRequest(body: unknown): ParsedRequest {
  const request = JsonRpcRequestSchema.safeParse(body);
  if (!request.success) {
    return { id: requestIdOf(body), error: { code: -32600, message: "Invalid Request", data: fieldErrors(request.error.issues) } };
  }
  const { id } = request.data;
  if (request.data.method !== "message/send") {
    return { id, error: { code: -32601, message: "Method not found" } };
  }
  const params = MessageSendParamsSchema.safeParse(request.data.params);
  if (!params.success) {
    return { id, error: { code: -32602, message: "Invalid params", data: fieldErrors(params.error.issues, ["params"]) } };
  }
  return { id, params: params.data };
}

// Check the message HackMyAgent's a2a target sends and return it as the
// message/send params of a user message with one text part. The message has
// no request id, so the reply to it answers id null.
function parseAgentMessage(body: unknown): ParsedRequest {
  const agentMessage = AgentMessageSchema.safeParse(body);
  if (!agentMessage.success) {
    return { id: null, error: { code: -32600, message: "Invalid Request", data: fieldErrors(agentMessage.error.issues) } };
  }
  const text = agentMessage.data.content;
  return {
    id: null,
    params: { message: { kind: "message", messageId: randomUUID(), role: "user", parts: [{ kind: "text", text }] } },
  };
}

// --- Task Handler ---

// Parse the body only after rate limiting and authentication pass, so
// rate-limited and unauthenticated clients never reach the JSON parser.
const parseJson = express.json({ limit: "1mb" });

// Every request that reaches the limiter counts toward the rate limit before
// authentication reads it, so a client that guesses tokens gets 429, not a 401
// for each guess, once it has used up the requests the limiter allows it in
// the 60 seconds that started with its first request. A request that
// limitHeaderLines answers 431 never reaches the limiter and is not counted.
app.post("/", rateLimit, authenticate, parseJson, (req, res) =>
  handleMessage(req, res, parseRequest, (id, result) => ({ jsonrpc: "2.0", id, result }))
);

// HackMyAgent's a2a target (hackmyagent attack <url> --target-type a2a) posts
// {"from", "to", "content"} to <url>/a2a/message, a route A2A v0.3.0 does not
// define, in place of a message/send request. The content is read as a user
// message with one text part, so the message counts toward the same rate
// limit and gets the same authentication, injection filter, audit lines and
// JSON-RPC errors as a message sent to POST /. The reply to a message the
// agent accepts holds the text of the completed task's reply.
app.post("/a2a/message", rateLimit, authenticate, parseJson, (req, res) =>
  handleMessage(req, res, parseAgentMessage, (_id, result) => ({ content: result.status.message.parts[0].text }))
);

// Check the body with parse, run the message it gives through the checks
// below, and answer with the completed task in the route's own reply format
// or with a JSON-RPC error.
async function handleMessage(
  req: express.Request,
  res: express.Response,
  parse: (body: unknown) => ParsedRequest,
  toReply: (id: RequestId, result: Awaited<ReturnType<typeof processTask>>) => unknown
) {
  const clientIp = req.ip || "unknown";
  const requestId = randomUUID();

  // Schema validation
  const parsed = parse(req.body);
  if ("error" in parsed) {
    const { error } = parsed;
    audit({
      timestamp: new Date().toISOString(),
      taskId: requestId,
      clientIp,
      action: "validation_failed",
      details: { code: error.code, issues: error.data?.length ?? 0 },
    });
    return sendError(res, 400, parsed.id, error);
  }

  const { id, params } = parsed;
  const message = params.message;
  const taskId = requestId;

  // This agent keeps no task once it has answered, so a message that
  // continues an earlier task names a task it cannot find.
  if (message.taskId !== undefined) {
    audit({
      timestamp: new Date().toISOString(),
      taskId,
      clientIp,
      action: "task_not_found",
      details: { partCount: message.parts.length },
    });
    return sendError(res, 400, id, { code: -32001, message: "Task not found" });
  }

  // Prompt injection check on all text parts
  for (const part of message.parts) {
    if (part.kind === "text" && containsInjection(part.text)) {
      audit({
        timestamp: new Date().toISOString(),
        taskId,
        clientIp,
        action: "injection_detected",
        details: { partCount: message.parts.length },
      });
      return sendError(res, 400, id, { code: -32602, message: "Request rejected by security filter" });
    }
  }

  // Process the task
  audit({
    timestamp: new Date().toISOString(),
    taskId,
    clientIp,
    action: "task_accepted",
    details: {
      partCount: message.parts.length,
      hasMetadata: !!params.metadata,
    },
  });

  try {
    const result = await processTask(taskId, message.contextId ?? randomUUID(), message);
    return res.json(toReply(id, result));
  } catch (error) {
    // Never leak internal error details
    audit({
      timestamp: new Date().toISOString(),
      taskId,
      clientIp,
      action: "task_failed",
      details: { error: error instanceof Error ? error.message : "unknown" },
    });
    return sendError(res, 500, id, { code: -32603, message: "Task processing failed" });
  }
}

// --- Agent Card Endpoint ---

// An AgentCard as A2A specification v0.3.0 defines it, read from
// examples/secure-agent-card/agent-card.json, so the card the README shows and
// the card clients fetch are one file. Only url, which clients send JSON-RPC
// requests to, is replaced, with the address this server answers on. The card
// is public: securitySchemes says how to authenticate and never holds a
// credential. The example's directory is this file's directory when tsx runs
// handler.ts, and its parent when node runs the compiled dist/handler.js.
const exampleDir = __filename.endsWith(".ts") ? __dirname : dirname(__dirname);
const agentCard = JSON.parse(
  readFileSync(join(exampleDir, "..", "secure-agent-card", "agent-card.json"), "utf8")
);

// Specification v0.3.0 names /.well-known/agent-card.json. Earlier versions
// named /.well-known/agent.json, which still serves the same card.
app.get(["/.well-known/agent-card.json", "/.well-known/agent.json"], (_req, res) => {
  res.json({ ...agentCard, url: process.env.AGENT_URL || `http://localhost:${port}` });
});

// --- Error Handling ---

// Unknown routes would otherwise get Express's default HTML 404 page.
app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

// Errors raised before a route handler runs, such as a body that is not valid
// JSON, would otherwise reach Express's default handler, which answers with an
// HTML page containing the stack trace.
//
// A client that closes the connection before sending the whole body is
// reported here as request.aborted only once the connection has closed, so the
// rejection is audited but the JSON reply below never reaches the client; it
// gets at most the bare HTTP 400 that Node's HTTP server writes. An upload
// that stalls until the request timeout is reported as request.aborted too,
// after Node has answered it with a bare HTTP 408, so the audit line records
// 408 for it.
app.use(
  (
    err: unknown,
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    if (res.headersSent) {
      next(err);
      return;
    }

    const { status, type, code } = (err ?? {}) as {
      status?: unknown;
      type?: unknown;
      code?: unknown;
    };
    const clientError = typeof status === "number" && status >= 400 && status < 500;
    const responseStatus = requestTimedOut(req) ? 408 : clientError ? status : 500;

    audit({
      timestamp: new Date().toISOString(),
      taskId: randomUUID(),
      clientIp: req.ip || "unknown",
      action: "request_rejected",
      details: {
        status: responseStatus,
        reason: rejectionReason(type, code),
      },
    });

    // No request id has been read, so the JSON-RPC error answers id null.
    if (type === "entity.parse.failed") {
      sendError(res, 400, null, { code: -32700, message: "Invalid JSON" });
    } else if (clientError) {
      sendError(res, responseStatus, null, { code: -32600, message: "Invalid request body" });
    } else {
      sendError(res, 500, null, { code: -32603, message: "Request failed" });
    }
  }
);

// The parser names most rejections in the error's type. A compressed body that
// does not inflate arrives as the zlib error instead, which has no type and a
// Z_* code such as Z_DATA_ERROR.
function rejectionReason(type: unknown, code: unknown): string {
  if (typeof type === "string") return type;
  if (typeof code === "string" && code.startsWith("Z_")) return "body.inflate.failed";
  return "unknown";
}

// When the request timeout expires, Node writes its bare HTTP 408 and destroys
// the socket with ERR_HTTP_REQUEST_TIMEOUT before the parser reports the
// unfinished body.
function requestTimedOut(req: express.Request): boolean {
  const errored = req.socket.errored as NodeJS.ErrnoException | null;
  return errored?.code === "ERR_HTTP_REQUEST_TIMEOUT";
}

// --- Task Processing ---

// Returns the completed task as an A2A v0.3.0 Task object.
async function processTask(
  taskId: string,
  contextId: string,
  message: z.infer<typeof MessageSchema>
) {
  // Extract text from parts
  const textParts = message.parts
    .filter((p): p is z.infer<typeof TextPartSchema> => p.kind === "text")
    .map((p) => p.text);

  const inputText = textParts.join("\n");

  // Your actual task processing logic here
  const responseText = `Processed task ${taskId}: received ${textParts.length} text parts (${inputText.length} chars total)`;

  return {
    kind: "task",
    id: taskId,
    contextId,
    status: {
      state: "completed",
      message: {
        kind: "message",
        messageId: randomUUID(),
        role: "agent",
        parts: [{ kind: "text", text: responseText }],
      },
    },
  };
}

// --- Start Server ---

const server = app.listen(port, () => {
  console.log(`Secure A2A agent listening on port ${port}`);
  console.log(`Agent card: http://localhost:${port}/.well-known/agent-card.json`);
});
// Node.js builds req.headers from at most 1,000 header lines when this is
// unset. Setting it keeps the limit Node.js applies and the one the handler
// checks the same. While maxHeaderLines is 1,000 the line changes nothing; it
// takes effect once maxHeaderLines is changed.
server.maxHeadersCount = maxHeaderLines;

// Without a listener, a port that is already taken ends the process with the
// stack trace of an unhandled 'error' event. The listener also receives errors
// raised after the server is listening, such as a failed accept, so only an
// error raised before then is reported as a listen failure.
server.on("error", (err: NodeJS.ErrnoException) => {
  if (server.listening) {
    console.error(`Server error on port ${port}: ${err.message}`);
  } else if (err.code === "EADDRINUSE") {
    console.error(`Port ${port} is already in use; set PORT to a free port`);
  } else {
    console.error(`Cannot listen on port ${port}: ${err.message}`);
  }
  process.exit(1);
});

export { app };
