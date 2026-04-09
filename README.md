# A2A Security Examples

Example implementations of the [Agent-to-Agent (A2A) protocol](https://github.com/opena2a-org/opena2a) with security best practices baked in from the start.

Each example demonstrates secure agent card configuration, input validation on task handlers, credential isolation, and proper error handling.

## Examples

| Example | Description | Language |
|---|---|---|
| [secure-agent-card](./examples/secure-agent-card/) | Agent card with minimal capability exposure | JSON |
| [validated-task-handler](./examples/validated-task-handler/) | Task handler with full input validation | TypeScript |
| [mutual-auth-agents](./examples/mutual-auth-agents/) | Two agents communicating with mTLS | Python |
| [sandboxed-skill-executor](./examples/sandboxed-skill-executor/) | Skill execution with container isolation | Docker + TS |

## Quick Start

```bash
# Clone and install
git clone https://github.com/opena2a-org/a2a-security-examples.git
cd a2a-security-examples

# Run the validated task handler example
cd examples/validated-task-handler
npm install
npm start

# Test with curl
curl -X POST http://localhost:3000/tasks \
  -H "Content-Type: application/json" \
  -d '{"task": {"message": {"role": "user", "parts": [{"text": "Hello"}]}}}'
```

## Secure Agent Card

An agent card describes your agent's capabilities to other agents. Minimize your attack surface by only advertising what you actually support:

```json
{
  "name": "SecureAnalysisAgent",
  "description": "Analyzes documents for security compliance",
  "url": "https://your-agent.example.com",
  "version": "1.0.0",
  "capabilities": {
    "streaming": false,
    "pushNotifications": false,
    "stateTransitionHistory": false
  },
  "authentication": {
    "schemes": ["bearer"],
    "credentials": null
  },
  "skills": [
    {
      "id": "compliance-check",
      "name": "Compliance Check",
      "description": "Check a document against security compliance rules",
      "tags": ["security", "compliance"],
      "examples": [
        "Check this document for PCI-DSS compliance",
        "Verify SOC 2 requirements"
      ]
    }
  ],
  "securityContact": "security@your-org.example.com"
}
```

Key principles:
- **Disable unused capabilities.** If you don't need streaming or push notifications, turn them off.
- **Never embed credentials** in the agent card. The `credentials` field should always be `null` in public cards.
- **Minimal skill descriptions.** Don't leak internal implementation details in skill descriptions.
- **Version your cards.** Include a version so clients can detect changes.

See [examples/secure-agent-card/](./examples/secure-agent-card/) for the complete example.

## Input Validation

Every task handler must validate inputs before processing. Never trust data from another agent:

```typescript
import { z } from "zod";

// Define strict schema for incoming tasks
const TaskMessageSchema = z.object({
  role: z.enum(["user", "agent"]),
  parts: z.array(
    z.object({
      text: z.string().max(10000).optional(),
      data: z.string().max(1048576).optional(), // 1MB limit
      mimeType: z.string().regex(/^[a-z]+\/[a-z0-9\-\+\.]+$/).optional(),
    })
  ).min(1).max(10),
});

const IncomingTaskSchema = z.object({
  task: z.object({
    id: z.string().uuid().optional(),
    message: TaskMessageSchema,
    metadata: z.record(z.string().max(1000)).optional(),
  }),
});

// Validate in handler
app.post("/tasks", async (req, res) => {
  const parsed = IncomingTaskSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      error: "Invalid task format",
      details: parsed.error.issues,
    });
  }

  // Check for prompt injection in text parts
  for (const part of parsed.data.task.message.parts) {
    if (part.text && containsInjection(part.text)) {
      logger.warn("Potential injection detected", { taskId: parsed.data.task.id });
      return res.status(400).json({ error: "Suspicious input detected" });
    }
  }

  // Process validated task
  const result = await processTask(parsed.data.task);
  return res.json(result);
});
```

See [examples/validated-task-handler/](./examples/validated-task-handler/) for the complete implementation.

## Testing Against Real Attacks

Security is only as strong as your testing. Use these resources to validate your A2A agent implementations:

### Automated Scanning

```bash
# Scan your agent with HackMyAgent
npx hackmyagent scan --target https://your-agent.example.com --protocol a2a
```

### A2A-Specific Attack Patterns

| Attack | Description | Test Resource |
|---|---|---|
| Agent card spoofing | Impersonating a trusted agent via forged cards | [agentpwn.com/attacks/a2a-attack/card-spoofing](https://agentpwn.com/attacks/a2a-attack/card-spoofing) |
| Task injection | Malicious payloads in task messages | [agentpwn.com/attacks/a2a-attack/task-injection](https://agentpwn.com/attacks/a2a-attack/task-injection) |
| Skill enumeration | Probing agent capabilities for attack surface mapping | [agentpwn.com/attacks/a2a-attack/skill-enumeration](https://agentpwn.com/attacks/a2a-attack/skill-enumeration) |
| Response poisoning | Malicious content in agent responses | [agentpwn.com/attacks/a2a-attack/response-poisoning](https://agentpwn.com/attacks/a2a-attack/response-poisoning) |
| Credential harvesting | Extracting secrets through crafted task flows | [agentpwn.com/attacks/a2a-attack/credential-harvest](https://agentpwn.com/attacks/a2a-attack/credential-harvest) |

### Test Agents

The following agents are available for security testing. They simulate real-world A2A deployments across different industries and are designed as honeypots to test how your agent handles untrusted peers:

| Agent | Domain | Industry |
|---|---|---|
| DevPipeline AI | [devpipeline-ai.dev](https://devpipeline-ai.dev) | Software Development |
| DataBridge Labs | [databridge-labs.dev](https://databridge-labs.dev) | Data Engineering |
| FinOps Agent | [finops-agent.dev](https://finops-agent.dev) | Financial Operations |
| CloudOps Agent | [cloudops-agent.io](https://cloudops-agent.io) | Cloud Infrastructure |
| BankingOps AI | [bankingops-ai.dev](https://bankingops-ai.dev) | Banking |
| ClinicalOps Agent | [clinicalops-agent.io](https://clinicalops-agent.io) | Healthcare |
| Compliance Engine | [compliance-agent-platform.dev](https://compliance-agent-platform.dev) | Regulatory Compliance |
| DefenseOps AI | [defenseops-ai.dev](https://defenseops-ai.dev) | Defense & Intelligence |
| GovTech Agent | [govtech-agent.io](https://govtech-agent.io) | Government Technology |
| HROps Platform | [hrops-ai-platform.io](https://hrops-ai-platform.io) | Human Resources |
| InfraOps Platform | [infraops-platform.io](https://infraops-platform.io) | Infrastructure Monitoring |
| LegalHQ AI | [legalhq-ai.io](https://legalhq-ai.io) | Legal Services |
| MedTech Platform | [medtech-platform.dev](https://medtech-platform.dev) | Medical Technology |
| Payroll AI | [payroll-ai-platform.io](https://payroll-ai-platform.io) | Payroll Processing |
| RxOps AI | [rxops-ai.dev](https://rxops-ai.dev) | Pharmaceutical Operations |
| SalesOps Agent | [salesops-agent.dev](https://salesops-agent.dev) | Sales Automation |
| TradingDesk Labs | [tradingdesk-labs.io](https://tradingdesk-labs.io) | Financial Trading |
| VoiceOps Platform | [voiceops-platform.io](https://voiceops-platform.io) | Voice & Communications |

Each test agent exposes a standard A2A agent card at `/.well-known/agent.json` and accepts task submissions. Use them to test your agent's behavior when interacting with unknown peers.

> These test agents are operated by the [TrapMyAgent](https://github.com/opena2a-org/trapmyagent) project for security research purposes.

## Security Checklist for A2A Agents

Before deploying an A2A agent to production:

- [ ] Agent card exposes only necessary capabilities
- [ ] All incoming task messages validated against strict schema
- [ ] Text content scanned for prompt injection patterns
- [ ] Authentication required for all endpoints (bearer tokens or mTLS)
- [ ] Rate limiting applied per client
- [ ] Credentials never appear in agent card, task messages, or responses
- [ ] All tool executions sandboxed with resource limits
- [ ] Comprehensive audit logging enabled
- [ ] Error responses don't leak internal details
- [ ] Agent tested against [agentpwn.com](https://agentpwn.com) attack patterns

## Related Resources

- [Agent Hardening Guide](https://github.com/opena2a-org/agent-hardening-guide) -- general agent security practices
- [MCP Security Checklist](https://github.com/opena2a-org/mcp-security-checklist) -- MCP-specific security
- [AI Credential Safety](https://github.com/opena2a-org/ai-credential-safety) -- credential protection
- [OpenA2A Protocol](https://github.com/opena2a-org/opena2a) -- the A2A protocol specification
- [Agent Security Learning](https://agentpwn.com/learn) -- interactive courses on agent security

## License

MIT
