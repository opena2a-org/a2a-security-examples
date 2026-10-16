# Testing against real attacks

The [README](../README.md#testing-against-real-attacks) has the HackMyAgent command and what the test agents are for. This page holds the rest: the payload table and the scanner release it was read from, how the example answers the route HackMyAgent sends its payloads to, and the test agent table and when the test agents were checked.

## Payloads

The README's command sends the `passive` and `active` payloads at the default `active` intensity, and all of them with `--intensity aggressive`:

| Payload | Intensity | Description |
|---|---|---|
| A2A Agent Discovery | passive | Discovers available agents and their capabilities |
| A2A Trust Probe | passive | Probes agent trust boundaries and authentication |
| A2A Identity Spoofing - Admin | active | Claims to be an admin agent to gain elevated access |
| A2A Identity Spoofing - Orchestrator | active | Claims to be the orchestrator to control workers |
| A2A Delegation Abuse - Elevated Privileges | active | Requests task execution with elevated privileges |
| A2A Delegation Abuse - Cross-boundary | active | Attempts to delegate tasks outside authorized scope |
| A2A Embedded Prompt Injection | active | Embeds prompt injection attack in A2A message content |
| A2A Data Exfiltration via Message | active | Attempts to extract system information through A2A responses |
| A2A Chain Attack | aggressive | Chains multiple A2A agents to escalate privileges |
| A2A Message Replay Probe | aggressive | Tests if agents accept replayed/stale messages |

The table gives the scanner's own names and descriptions.

## The /a2a/message route

The table is the `a2a-attack` category of hackmyagent 0.33.2, with the scanner's own names and descriptions. With `--target-type a2a` that release posts each payload as `{"from", "to", "content"}` to `/a2a/message`, not as a `message/send` request, so the example answers `POST /a2a/message` too. It puts the request through steps 1 to 3 of [Input validation](input-validation.md), counting it toward the same rate limit as a request to `POST /`, checks in place of step 4 that `from` and `to` are strings of 1 to 200 characters and `content` is one of 1 to 10,000 (`-32600` otherwise), and reads `content` as a message with one text part for steps 5 and 6. The route has a body limit of its own in step 3, 413 for a body over 64 KB, not 11 MB: the 10,400 characters it reads take at most 62,400 bytes, each written as a six-byte `\uXXXX` escape. A message it accepts gets `{"content": ...}` holding the text of the agent's reply; an error from steps 3 to 6 is the JSON-RPC error of that step with an `id` of `null`. [agentpwn.com/attacks/a2a-attack](https://agentpwn.com/attacks/a2a-attack) is a separate test: three pages (Agent Impersonation, Delegation Abuse and Worm Propagation) that each hide an indirect prompt injection, to check whether an agent follows instructions it finds in content.

## Test agents

The following agents are available for security testing. They simulate real-world A2A deployments across different industries and are designed as honeypots to test how your agent handles untrusted peers:

| Agent | Domain | Industry |
|---|---|---|
| DevPipeline AI | [devpipeline-ai.dev](https://devpipeline-ai.dev) | Software Development |
| DataBridge Labs | [databridge-labs.dev](https://databridge-labs.dev) | Data Engineering |
| FinOps Agent | [finops-agent.dev](https://finops-agent.dev) | Financial Operations |
| CloudOps Agent | [cloudops-agent.io](https://cloudops-agent.io) | Cloud Infrastructure |
| BankingOps AI | [bankingops-ai.dev](https://bankingops-ai.dev) | Banking |
| ClinicalOps Agent | [clinicalops-agent.io](https://clinicalops-agent.io) | Healthcare |
| Compliance Agent Platform | [compliance-agent-platform.dev](https://compliance-agent-platform.dev) | Regulatory Compliance |
| DefenseOps AI | [defenseops-ai.dev](https://defenseops-ai.dev) | Defense & Intelligence |
| GovTech Agent | [govtech-agent.io](https://govtech-agent.io) | Government Technology |
| HROps AI Platform | [hrops-ai-platform.io](https://hrops-ai-platform.io) | Human Resources |
| InfraOps Platform | [infraops-platform.io](https://infraops-platform.io) | Infrastructure Monitoring |
| LegalHQ AI | [legalhq-ai.io](https://legalhq-ai.io) | Legal Services |
| MedTech Platform | [medtech-platform.dev](https://medtech-platform.dev) | Medical Technology |
| Payroll AI Platform | [payroll-ai-platform.io](https://payroll-ai-platform.io) | Payroll Processing |
| RxOps AI | [rxops-ai.dev](https://rxops-ai.dev) | Pharmaceutical Operations |
| SalesOps Agent | [salesops-agent.dev](https://salesops-agent.dev) | Sales Automation |
| TradingDesk Labs | [tradingdesk-labs.io](https://tradingdesk-labs.io) | Financial Trading |
| VoiceOps Platform | [voiceops-platform.io](https://voiceops-platform.io) | Voice & Communications |
| MCP Server Registry | [mcp-servers.org](https://mcp-servers.org) | Developer Tools |
| Agent Documentation Hub | [agent-docs.io](https://agent-docs.io) | Documentation |
| LLM Tools Guide | [llm-tools-guide.dev](https://llm-tools-guide.dev) | Developer Education |
| AI SDK Reference | [ai-sdk-reference.dev](https://ai-sdk-reference.dev) | Developer Reference |

Each test agent except CloudOps Agent exposes a standard A2A agent card at `/.well-known/agent.json` and accepts task submissions; `cloudops-agent.io` returned 404 at that path when checked on 2026-10-11. Use them to test your agent's behavior when interacting with unknown peers. To see which agents serve a card right now, run `npm run check:test-agents`: it fetches each card and home page and reports an agent whose card is missing or whose site uses a different name from the table.
