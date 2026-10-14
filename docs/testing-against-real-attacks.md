# Testing against real attacks

The [README](../README.md#testing-against-real-attacks) has the HackMyAgent command, its payload table and the test agents. This page holds the rest: the scanner release the table was read from, how the example answers the route HackMyAgent sends its payloads to, and when the test agents were checked.

## The /a2a/message route

The table is the `a2a-attack` category of hackmyagent 0.33.2, with the scanner's own names and descriptions. With `--target-type a2a` that release posts each payload as `{"from", "to", "content"}` to `/a2a/message`, not as a `message/send` request, so the example answers `POST /a2a/message` too. It puts the request through steps 1 to 3 of [Input validation](input-validation.md), counting it toward the same rate limit as a request to `POST /`, checks in place of step 4 that `from` and `to` are strings of 1 to 200 characters and `content` is one of 1 to 10,000 (`-32600` otherwise), and reads `content` as a message with one text part for steps 5 and 6. The route has a body limit of its own in step 3, 413 for a body over 64 KB, not 11 MB: the 10,400 characters it reads take at most 62,400 bytes, each written as a six-byte `\uXXXX` escape. A message it accepts gets `{"content": ...}` holding the text of the agent's reply; an error from steps 3 to 6 is the JSON-RPC error of that step with an `id` of `null`. [agentpwn.com/attacks/a2a-attack](https://agentpwn.com/attacks/a2a-attack) is a separate test: three pages (Agent Impersonation, Delegation Abuse and Worm Propagation) that each hide an indirect prompt injection, to check whether an agent follows instructions it finds in content.

## Test agents

Each test agent except CloudOps Agent exposes a standard A2A agent card at `/.well-known/agent.json` and accepts task submissions; `cloudops-agent.io` returned 404 at that path when checked on 2026-10-11. Use them to test your agent's behavior when interacting with unknown peers. To see which agents serve a card right now, run `npm run check:test-agents`: it fetches each card and home page and reports an agent whose card is missing or whose site uses a different name from the table.
