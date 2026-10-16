# Running validated-task-handler

The [quick start](../README.md#quick-start) runs this example with `npm run dev` and sends it one message. This page holds the rest of what the README says about running it: the message an A2A v1.0 client sends, the bearer tokens it accepts, the audit log it writes and the tests that check it.

## A2A v1.0 requests

An A2A v1.0 client sends the JSON-RPC method `SendMessage` to `POST /` with the header `A2A-Version: 1.0`. A v1.0 part has no `kind`: it sets `text`, or `raw` with base64 bytes, a `mediaType` and an optional `filename`. A request without the header, or with `A2A-Version: 0.3`, is read as A2A v0.3.0, as the quick start's request is, and a request for another version gets the JSON-RPC error `-32009` ([input validation](input-validation.md), step 4).

```bash
curl -s -X POST http://localhost:3000/ \
  -H "Authorization: Bearer demo-token" -H "Content-Type: application/json" -H "A2A-Version: 1.0" \
  -d '{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"Hello"}]}}}'
```

```text
{"jsonrpc":"2.0","id":1,"result":{"task":{"id":"8f5d3c57-6ba6-4af8-9ae5-3b655e0b46c0","contextId":"b0c1f992-8935-4083-94ad-9caebbf15abe","status":{"state":"TASK_STATE_COMPLETED","message":{"messageId":"e55e0a6c-2c72-479b-a87a-3c57854a2630","contextId":"b0c1f992-8935-4083-94ad-9caebbf15abe","taskId":"8f5d3c57-6ba6-4af8-9ae5-3b655e0b46c0","role":"ROLE_AGENT","parts":[{"text":"Processed task 8f5d3c57-6ba6-4af8-9ae5-3b655e0b46c0: received 1 text parts (5 chars total)"}]}}}}}
```

A client of the `HTTP+JSON` interface the agent card lists sends `SendMessage` in the HTTP+JSON binding of A2A v1.0 instead: the `SendMessageRequest` is the whole body of `POST /message:send`, sent as `application/json` or `application/a2a+json`, and the reply is the `SendMessageResponse`, with the media type `application/a2a+json`. That route answers A2A v1.0 only, so a request without `A2A-Version: 1.0` gets 400 with the reason `VERSION_NOT_SUPPORTED`. A body the parser rejects and a message the checks reject get a `google.rpc.Status` there, and the rate limit and authentication answer as they answer `POST /` ([input validation](input-validation.md), after step 6).

```bash
curl -s -X POST http://localhost:3000/message:send \
  -H "Authorization: Bearer demo-token" -H "Content-Type: application/a2a+json" -H "A2A-Version: 1.0" \
  -d '{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"Hello"}]}}'
```

```text
{"task":{"id":"d17bdcd2-8557-4138-b1ff-2cc2e88571f5","contextId":"3b35a9ec-1e28-43af-81d7-a91b83041707","status":{"state":"TASK_STATE_COMPLETED","message":{"messageId":"6ae1c3d8-2b3d-427c-8fd5-8dfbfcb999e1","contextId":"3b35a9ec-1e28-43af-81d7-a91b83041707","taskId":"d17bdcd2-8557-4138-b1ff-2cc2e88571f5","role":"ROLE_AGENT","parts":[{"text":"Processed task d17bdcd2-8557-4138-b1ff-2cc2e88571f5: received 1 text parts (5 chars total)"}]}}}}
```

## Bearer tokens

The example accepts any bearer token made of the characters RFC 6750 allows in one (one or more ASCII letters, digits, `-`, `.`, `_`, `~`, `+` or `/`, then any number of `=`) except the literal `undefined`; replace `isValidToken` in `handler.ts` with real token verification before you deploy it.

## Audit log

Requests to `POST /` and to `POST /a2a/message` (see [Testing against real attacks](../README.md#testing-against-real-attacks)) write JSON audit lines to the server terminal: `rate_limited`, `auth_failed` for a request that fails authentication, with the status it gets and a reason but never the header or the token, `request_rejected` for a body the parser rejects (not a JSON object or array, over 11 MB, or over 64 KB at the second route, an unsupported encoding or charset, a compressed body that does not inflate, or a connection closed before the whole body arrives, which gets at most a bare HTTP 400 with no body when the client closes it, and a bare HTTP 408 with no body when the upload stalls until Node's request timeout, 300 seconds by default), `version_not_supported` for a request to `POST /` whose `A2A-Version` header names a version the example does not answer, or to `POST /message:send` without `A2A-Version: 1.0`, `validation_failed`, `task_not_found`, `injection_detected`, or `task_accepted` followed by `task_failed` if processing throws. Requests rejected with HTTP 431 and requests for the agent card write no audit line. A request to `POST /message:send` writes the line a request to `POST /` writes for the same check.

## Tests

To run the repository's tests, run `npm test` from the repository root with Node.js 18.17 or later (the quick start runs on any Node.js 18, but Node.js 18.0 has no `node --test`, and releases before 18.8 have no `after` in `node:test`, which the tests import). It installs the example's dependencies, then runs every file in `test/`. Node.js 18.17 is the lowest release the tests have been run on, not a measured minimum: releases 18.8 to 18.16 are untested.
