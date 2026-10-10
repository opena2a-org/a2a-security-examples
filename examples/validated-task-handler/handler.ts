/**
 * Validated A2A Task Handler
 *
 * Demonstrates secure task handling with:
 * - Zod schema validation on all inputs
 * - Prompt injection detection
 * - Rate limiting per client
 * - Audit logging
 * - Proper error handling (no internal detail leaks)
 *
 * Test against known A2A attacks, including task injection and response
 * poisoning:
 * https://agentpwn.com/attacks/a2a-attack
 */

import express from "express";
import { z } from "zod";
import { randomUUID } from "crypto";
import { RateLimiterMemory } from "rate-limiter-flexible";

const app = express();
const port = parsePort(process.env.PORT || "3000");

// Exit with one line naming the variable instead of the stack trace that
// app.listen throws for a port it cannot use.
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

const TextPartSchema = z.object({
  type: z.literal("text").default("text"),
  text: z.string().min(1).max(10000),
});

const DataPartSchema = z.object({
  type: z.literal("data"),
  data: z.string().max(1048576), // 1MB base64
  mimeType: z
    .string()
    .regex(/^(text|application|image)\/(plain|json|pdf|png|jpeg)$/),
});

const PartSchema = z.discriminatedUnion("type", [TextPartSchema, DataPartSchema]);

const TaskMessageSchema = z.object({
  role: z.enum(["user", "agent"]),
  parts: z.array(PartSchema).min(1).max(10),
});

const TaskRequestSchema = z.object({
  task: z.object({
    id: z.string().uuid().optional(),
    message: TaskMessageSchema,
    metadata: z.record(z.string(), z.string().max(1000)).optional(),
  }),
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

// --- Task Handler ---

// Parse the body only after authentication and rate limiting pass, so
// unauthenticated and rate-limited clients never reach the JSON parser.
const parseJson = express.json({ limit: "1mb" });

app.post("/tasks", authenticate, rateLimit, parseJson, async (req, res) => {
  const clientIp = req.ip || "unknown";
  const requestId = randomUUID();

  // Schema validation
  const parsed = TaskRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    audit({
      timestamp: new Date().toISOString(),
      taskId: requestId,
      clientIp,
      action: "validation_failed",
      details: { issues: parsed.error.issues.length },
    });
    return res.status(400).json({
      error: "Invalid task format",
      // Only expose field-level errors, not internal details
      details: parsed.error.issues.map((i) => ({
        field: i.path.join("."),
        message: i.message,
      })),
    });
  }

  const task = parsed.data.task;
  const taskId = task.id || requestId;

  // Prompt injection check on all text parts
  for (const part of task.message.parts) {
    if ("text" in part && containsInjection(part.text)) {
      audit({
        timestamp: new Date().toISOString(),
        taskId,
        clientIp,
        action: "injection_detected",
        details: { partCount: task.message.parts.length },
      });
      return res.status(400).json({ error: "Request rejected by security filter" });
    }
  }

  // Process the task
  audit({
    timestamp: new Date().toISOString(),
    taskId,
    clientIp,
    action: "task_accepted",
    details: {
      partCount: task.message.parts.length,
      hasMetadata: !!task.metadata,
    },
  });

  try {
    const result = await processTask(taskId, task);
    return res.json(result);
  } catch (error) {
    // Never leak internal error details
    audit({
      timestamp: new Date().toISOString(),
      taskId,
      clientIp,
      action: "task_failed",
      details: { error: error instanceof Error ? error.message : "unknown" },
    });
    return res.status(500).json({ error: "Task processing failed" });
  }
});

// --- Agent Card Endpoint ---

app.get("/.well-known/agent.json", (_req, res) => {
  res.json({
    name: "SecureAnalysisAgent",
    description: "Analyzes documents for security compliance",
    url: process.env.AGENT_URL || `http://localhost:${port}`,
    version: "1.0.0",
    capabilities: {
      streaming: false,
      pushNotifications: false,
      stateTransitionHistory: false,
    },
    authentication: {
      schemes: ["bearer"],
      credentials: null,
    },
    skills: [
      {
        id: "compliance-check",
        name: "Compliance Check",
        description: "Check a document against security compliance rules",
        tags: ["security", "compliance"],
        examples: ["Check this document for PCI-DSS compliance"],
        inputModes: ["text"],
        outputModes: ["text"],
      },
    ],
  });
});

// --- Error Handling ---

// Unknown routes would otherwise get Express's default HTML 404 page.
app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

// Errors raised before a route handler runs, such as a body that is not valid
// JSON, would otherwise reach Express's default handler, which answers with an
// HTML page containing the stack trace.
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

    const { status, type } = (err ?? {}) as { status?: unknown; type?: unknown };
    const clientError = typeof status === "number" && status >= 400 && status < 500;
    const responseStatus = clientError ? status : 500;

    audit({
      timestamp: new Date().toISOString(),
      taskId: randomUUID(),
      clientIp: req.ip || "unknown",
      action: "request_rejected",
      details: {
        status: responseStatus,
        reason: typeof type === "string" ? type : "unknown",
      },
    });

    if (type === "entity.parse.failed") {
      res.status(400).json({ error: "Invalid JSON" });
    } else if (clientError) {
      res.status(responseStatus).json({ error: "Invalid request body" });
    } else {
      res.status(500).json({ error: "Request failed" });
    }
  }
);

// --- Task Processing ---

async function processTask(
  taskId: string,
  task: z.infer<typeof TaskRequestSchema>["task"]
) {
  // Extract text from parts
  const textParts = task.message.parts
    .filter((p): p is z.infer<typeof TextPartSchema> => "text" in p)
    .map((p) => p.text);

  const inputText = textParts.join("\n");

  // Your actual task processing logic here
  const responseText = `Processed task ${taskId}: received ${textParts.length} text parts (${inputText.length} chars total)`;

  return {
    task: {
      id: taskId,
      status: "completed",
      message: {
        role: "agent",
        parts: [{ text: responseText }],
      },
    },
  };
}

// --- Start Server ---

app.listen(port, () => {
  console.log(`Secure A2A agent listening on port ${port}`);
  console.log(`Agent card: http://localhost:${port}/.well-known/agent.json`);
});

export { app };
