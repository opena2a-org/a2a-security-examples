# Secure agent card

The [README](../README.md#secure-agent-card) gives the rules for an agent card and an excerpt of [agent-card.json](../examples/secure-agent-card/agent-card.json). This page holds the paths the example serves the card at and the excerpt with the card's version fields.

[handler.ts](../examples/validated-task-handler/handler.ts) serves [agent-card.json](../examples/secure-agent-card/agent-card.json) at `/.well-known/agent-card.json`, the path A2A v0.3.0 names, and at `/.well-known/agent.json`, the path earlier versions named, with `url` set to `AGENT_URL` or, when that is unset, `http://localhost:<port>`.

Excerpt:

```json
{
  "protocolVersion": "0.3.0",
  "name": "TextPartCounterAgent",
  "url": "https://your-agent.example.com",
  "version": "3.0.0",
  "capabilities": {
    "streaming": false,
    "pushNotifications": false,
    "stateTransitionHistory": false
  },
  "securitySchemes": {
    "bearer": { "type": "http", "scheme": "bearer" }
  },
  "security": [{ "bearer": [] }]
}
```
