# Running validated-task-handler

The [quick start](../README.md#quick-start) runs this example with `npm run dev` and sends it one message. This page holds the rest of what the README says about running it: the bearer tokens it accepts, the audit log it writes and the tests that check it.

## Bearer tokens

The example accepts any bearer token made of the characters RFC 6750 allows in one (one or more ASCII letters, digits, `-`, `.`, `_`, `~`, `+` or `/`, then any number of `=`) except the literal `undefined`; replace `isValidToken` in `handler.ts` with real token verification before you deploy it.

## Audit log

Requests to `POST /` and to `POST /a2a/message` (see [Testing against real attacks](../README.md#testing-against-real-attacks)) write JSON audit lines to the server terminal: `rate_limited`, `auth_failed` for a request that fails authentication, with the status it gets and a reason but never the header or the token, `request_rejected` for a body the parser rejects (not a JSON object or array, over 11 MB, or over 64 KB at the second route, an unsupported encoding or charset, a compressed body that does not inflate, or a connection closed before the whole body arrives, which gets at most a bare HTTP 400 with no body when the client closes it, and a bare HTTP 408 with no body when the upload stalls until Node's request timeout, 300 seconds by default), `validation_failed`, `task_not_found`, `injection_detected`, or `task_accepted` followed by `task_failed` if processing throws. Requests rejected with HTTP 431 and requests for the agent card write no audit line.

## Tests

To run the repository's tests, run `npm test` from the repository root with Node.js 18.17 or later (the quick start runs on any Node.js 18, but Node.js 18.0 has no `node --test`, and releases before 18.8 have no `after` in `node:test`, which the tests import). It installs the example's dependencies, then runs every file in `test/`. Node.js 18.17 is the lowest release the tests have been run on, not a measured minimum: releases 18.8 to 18.16 are untested.
