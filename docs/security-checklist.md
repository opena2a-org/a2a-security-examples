# Security checklist for A2A agents

The [README](../README.md#security-checklist-for-a2a-agents) links this checklist. Before deploying an A2A agent to production:

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
