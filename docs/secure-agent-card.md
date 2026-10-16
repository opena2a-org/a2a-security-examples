# Secure agent card

The [README](../README.md#secure-agent-card) gives the rules for an agent card and an excerpt of [agent-card.json](../examples/secure-agent-card/agent-card.json). This page holds the paths the example serves the card at, the form of its security scheme, and the excerpt with the card's version fields.

[handler.ts](../examples/validated-task-handler/handler.ts) serves [agent-card.json](../examples/secure-agent-card/agent-card.json) at `/.well-known/agent-card.json`, the path A2A v0.3.0 and v1.0 name, and at `/.well-known/agent.json`, the path earlier versions named. It sets `url` and the `url` of each entry in `supportedInterfaces` to `AGENT_URL` or, when that is unset, `http://localhost:<port>`: the handler answers both versions in the JSON-RPC binding at `POST /`, and v1.0 in the HTTP+JSON binding at `POST /message:send`, the path a client of the `HTTP+JSON` interface appends to its `url` for `SendMessage`.

The card holds the fields of both versions. Section 5.7 of A2A v1.0 says an implementation should ignore a field it does not recognize, and the JSON Schema of A2A v0.3.0 allows fields it does not define. Of the fields only one version defines, an A2A v1.0 client reads `supportedInterfaces`, whose first entry is the agent's preferred interface, `httpAuthSecurityScheme` in each security scheme, and `securityRequirements`; an A2A v0.3.0 client reads `protocolVersion`, `url`, `preferredTransport`, `capabilities.stateTransitionHistory`, the `type` and `scheme` of each security scheme, and `security`.

`securitySchemes` says how a client authenticates, here with an HTTP bearer token, in the form of A2A v1.0 and of v0.3.0; the token itself never appears in the card.

Excerpt:

```json
{
  "protocolVersion": "0.3.0",
  "name": "TextPartCounterAgent",
  "supportedInterfaces": [
    { "url": "https://your-agent.example.com", "protocolBinding": "JSONRPC", "protocolVersion": "1.0" },
    { "url": "https://your-agent.example.com", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0" },
    { "url": "https://your-agent.example.com", "protocolBinding": "JSONRPC", "protocolVersion": "0.3" }
  ],
  "url": "https://your-agent.example.com",
  "version": "3.0.0",
  "capabilities": {
    "streaming": false,
    "pushNotifications": false,
    "stateTransitionHistory": false
  },
  "securitySchemes": {
    "bearer": { "httpAuthSecurityScheme": { "scheme": "Bearer" }, "type": "http", "scheme": "bearer" }
  },
  "securityRequirements": [{ "schemes": { "bearer": { "list": [] } } }],
  "security": [{ "bearer": [] }]
}
```
