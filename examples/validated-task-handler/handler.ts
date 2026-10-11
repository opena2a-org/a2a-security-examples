/**
 * Validated A2A Task Handler
 *
 * An agent written to A2A specification v0.3.0: it answers the JSON-RPC 2.0
 * method message/send at POST / and serves its agent card at
 * /.well-known/agent-card.json.
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

// --- Authentication Middleware ---

function authenticate(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): void {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  const token = authHeader.slice(7);

  // Validate token (replace with your auth provider)
  // NEVER log the full token
  if (!isValidToken(token)) {
    res.status(403).json({ error: "Invalid or expired token" });
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

type ParsedRequest =
  | { error: RpcError }
  | { id: z.infer<typeof RequestIdSchema>; params: z.infer<typeof MessageSendParamsSchema> };

// Check the JSON-RPC request, its method, then its params, and return the
// message/send params or the error for the first check that fails.
function parseRequest(body: unknown): ParsedRequest {
  const request = JsonRpcRequestSchema.safeParse(body);
  if (!request.success) {
    return { error: { code: -32600, message: "Invalid Request", data: fieldErrors(request.error.issues) } };
  }
  if (request.data.method !== "message/send") {
    return { error: { code: -32601, message: "Method not found" } };
  }
  const params = MessageSendParamsSchema.safeParse(request.data.params);
  if (!params.success) {
    return { error: { code: -32602, message: "Invalid params", data: fieldErrors(params.error.issues, ["params"]) } };
  }
  return { id: request.data.id, params: params.data };
}

// --- Task Handler ---

// Parse the body only after authentication and rate limiting pass, so
// unauthenticated and rate-limited clients never reach the JSON parser.
const parseJson = express.json({ limit: "1mb" });

app.post("/", authenticate, rateLimit, parseJson, async (req, res) => {
  const clientIp = req.ip || "unknown";
  const requestId = randomUUID();

  // Schema validation
  const parsed = parseRequest(req.body);
  if ("error" in parsed) {
    const { error } = parsed;
    audit({
      timestamp: new Date().toISOString(),
      taskId: requestId,
      clientIp,
      action: "validation_failed",
      details: { code: error.code, issues: error.data?.length ?? 0 },
    });
    return sendError(res, 400, requestIdOf(req.body), error);
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
    return res.json({ jsonrpc: "2.0", id, result });
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
});

// --- Agent Card Endpoint ---

// An AgentCard as A2A specification v0.3.0 defines it. Clients send JSON-RPC
// requests to url. The card is public: securitySchemes says how to
// authenticate and never holds a credential.
function agentCard() {
  return {
    protocolVersion: "0.3.0",
    name: "SecureAnalysisAgent",
    description: "Analyzes documents for security compliance",
    url: process.env.AGENT_URL || `http://localhost:${port}`,
    preferredTransport: "JSONRPC",
    version: "1.0.0",
    capabilities: {
      streaming: false,
      pushNotifications: false,
      stateTransitionHistory: false,
    },
    securitySchemes: {
      bearer: { type: "http", scheme: "bearer" },
    },
    security: [{ bearer: [] }],
    defaultInputModes: [...MEDIA_TYPES],
    defaultOutputModes: ["text/plain"],
    skills: [
      {
        id: "compliance-check",
        name: "Compliance Check",
        description: "Check a document against security compliance rules",
        tags: ["security", "compliance"],
        examples: ["Check this document for PCI-DSS compliance"],
      },
    ],
  };
}

// Specification v0.3.0 names /.well-known/agent-card.json. Earlier versions
// named /.well-known/agent.json, which still serves the same card.
app.get(["/.well-known/agent-card.json", "/.well-known/agent.json"], (_req, res) => {
  res.json(agentCard());
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
