# Input validation

Never trust data from another agent. [handler.ts](../examples/validated-task-handler/handler.ts) checks each request in this order and stops at the first failure:

1. Rate limit of 30 requests per minute per client IP: a request over the limit gets the error `Too many requests`. Every request that reaches the limiter counts, including one that then fails authentication. The limiter counts a client's requests for 60 seconds from its first one and starts again with its first request after those 60 seconds have ended, so requests on the two sides of that end are counted apart. It keys on the client IP Express gives as `req.ip`, which behind a reverse proxy is the proxy's address, so every client behind the proxy shares one count, and 30 requests that fail authentication from one of them get every other one refused with `Too many requests` until those 60 seconds have ended. A deployment behind a proxy sets Express's `trust proxy` to the proxies it runs, so that `req.ip` is the client's address. It names their addresses, as in `app.set("trust proxy", "10.0.0.2")` for one proxy at 10.0.0.2, and never sets it to `true`: Express then gives as `req.ip` the leftmost `X-Forwarded-For` address, which the client chooses, so a client that sends each request with a different one is counted afresh each time and never gets `Too many requests`.
2. Bearer authentication: the `Authorization` header must be `Bearer` (in any letter case) followed by one or more spaces and one token (one or more ASCII letters, digits, `-`, `.`, `_`, `~`, `+` or `/`, then any number of `=`). A request without the header, or whose header names another scheme, such as `Basic demo` or `Bearerx demo-token`, gets the error `Authentication required`. As RFC 6750, section 3.1, suggests, a request that sends the header more than once gets the error `More than one Authorization header`, and one whose header names the `Bearer` scheme in any other form gets the error `Malformed Authorization header`: with no token (`Bearer`), with a tab, comma, colon or other character a scheme name cannot hold in place of the spaces (`Bearer,demo-token`, `Bearer:demo-token`), with more than one token (`Bearer demo token`, `Bearer demo-token extra`), with a token that starts with `=` or has a character other than `=` after an `=` (`Bearer =demo`, `Bearer demo=token`) or with a character outside that set (`Bearer café`). Two `Authorization: Basic demo` lines get `More than one Authorization header` too: the handler counts the header lines before it reads the scheme, so a repeated header gets that error whatever scheme it names; an invalid token gets the error `Invalid or expired token`. Each of these errors carries the challenge `WWW-Authenticate: Bearer realm="a2a"`; `Invalid or expired token` adds the error code from RFC 6750, section 3.1: `WWW-Authenticate: Bearer realm="a2a", error="invalid_token"`, and `More than one Authorization header` and `Malformed Authorization header` add the error code for a malformed request: `WWW-Authenticate: Bearer realm="a2a", error="invalid_request"`. On the Node.js releases the example's `package.json` admits, no request reaches the handler with an `Authorization` header left out ([why those releases](validated-task-handler.md#nodejs-releases)).
3. JSON parsing: a non-empty body sent as `application/json` that is not a JSON object or array gets the JSON-RPC error `Invalid JSON` with an `id` of `null`, not the framework's HTML error page with its stack trace. A body sent as `application/json` that the parser cannot read is rejected here whatever it contains, with the JSON-RPC error `Invalid request body`: a body over 11 MB (room for 10 file parts of 1,048,576 base64 characters written without JSON escapes, the most step 4 allows), one sent with a `Content-Encoding` other than `identity`, as the parsers are set not to inflate a compressed body, or one in a charset the parser does not read. An empty body the parser can read, or a body not sent as `application/json`, reaches step 4 as an empty object and fails there.
4. Schema validation: a JSON-RPC 2.0 request (the JSON-RPC error `Invalid Request` otherwise) for `message/send` (`Method not found` for any other method) with a message of 1 to 10 parts, text parts up to 10,000 characters and file parts with an allowlisted `mimeType` and up to 1,048,576 characters of `bytes`, which must be base64 as RFC 4648, section 4, defines it: the standard alphabet in groups of four characters, the last one padded with `=` when it is short (`Invalid params` otherwise). `FilePartSchema` in the excerpt below makes this check with the `isBase64` function, which handler.ts declares above `FilePartSchema` and the excerpt leaves out. The excerpt builds its schemas with `z`, which handler.ts imports from `zod`. `Invalid Request` and `Invalid params` list the failing fields only. A file given as a URI is rejected, not fetched, and so is a data part. The example keeps no task once it has answered, so a message with a `taskId` gets the error `Task not found`. Before these checks, the `A2A-Version` header picks the version the request is read as. No header, an empty one or `0.3` picks A2A v0.3.0, which the checks above describe. `1.0` picks A2A v1.0: the method is `SendMessage`, and a part has no `kind` but sets `text`, or sets `raw` in place of `bytes`, `mediaType` in place of `mimeType` and an optional `filename`, with the same limits; a part that sets none or more than one of `text`, `raw`, `url` and `data`, or sets `url` or `data`, is rejected. The agent card declares no streaming, no push notifications and no extended agent card, so, as section 3.3.4 of A2A v1.0 requires, a v1.0 request for `SendStreamingMessage`, `SubscribeToTask` or `GetExtendedAgentCard` gets the error `This operation is not supported`, and one for `CreateTaskPushNotificationConfig`, `GetTaskPushNotificationConfig`, `ListTaskPushNotificationConfigs` or `DeleteTaskPushNotificationConfig` gets the error `Push Notification is not supported`, without its params being checked; any other method but `SendMessage` gets `Method not found`. A patch number, as in `1.0.1`, is not considered, and any other value gets the error `Version not supported`. A v1.0 error gives the failing fields in a `google.rpc.BadRequest`, and task not found, push notifications not supported, unsupported operation and version not supported in a `google.rpc.ErrorInfo` that names them.
5. Prompt-injection patterns on every text part: a request with a text part that matches one gets the JSON-RPC error `Request rejected by security filter`. Pattern matching catches known phrasings only; treat it as one layer, not a complete defense.
6. Processing errors return the generic JSON-RPC error `Task processing failed`. The detail goes to the audit log, not to the caller.

The table below gives, for each of these errors, the HTTP status and the JSON-RPC code of the reply at `POST /`, and one request that gets it. [scripts/generate-input-validation.mjs](../scripts/generate-input-validation.mjs) writes it from [test/handler-attack-table.mjs](../test/handler-attack-table.mjs), whose requests `npm test` sends to the handler, and `npm test` fails when the page holds another table than the script writes.

<!-- BEGIN table written by node scripts/generate-input-validation.mjs from test/handler-attack-table.mjs: edit that file and run the script, not this table -->

| Step | Example request | HTTP status | JSON-RPC code | Error |
|---|---|---|---|---|
| 1 | request 31 from one address within 60 seconds | 429 | none | `Too many requests` |
| 2 | no Authorization header | 401 | none | `Authentication required` |
| 2 | the token undefined | 401 | none | `Invalid or expired token` |
| 2 | Bearer with no token | 400 | none | `Malformed Authorization header` |
| 2 | two Authorization: Bearer demo-token lines | 400 | none | `More than one Authorization header` |
| 3 | a body that is not JSON | 400 | `-32700` | `Invalid JSON` |
| 3 | a body over 11 MB | 413 | `-32600` | `Invalid request body` |
| 3 | a Content-Encoding the parser does not read | 415 | `-32600` | `Invalid request body` |
| 4 | an empty body | 400 | `-32600` | `Invalid Request` |
| 4 | a method other than message/send | 400 | `-32601` | `Method not found` |
| 4 | no parts | 400 | `-32602` | `Invalid params` |
| 4 | a message that continues an earlier task | 400 | `-32001` | `Task not found` |
| 4 | an A2A-Version header naming a version the agent does not answer | 400 | `-32009` | `Version not supported` |
| 4 | an A2A v1.0 request for SendStreamingMessage, which the card does not support | 400 | `-32004` | `This operation is not supported` |
| 4 | an A2A v1.0 request for CreateTaskPushNotificationConfig, which the card does not support | 400 | `-32003` | `Push Notification is not supported` |
| 5 | a text part matching ignore previous instructions | 400 | `-32602` | `Request rejected by security filter` |
| 6 | a message whose processing throws | 500 | `-32603` | `Task processing failed` |

<!-- END table written by node scripts/generate-input-validation.mjs -->

`POST /message:send`, where the handler answers `SendMessage` in the HTTP+JSON binding of A2A v1.0, makes the same checks in the same order. Steps 1 and 2 answer it as they answer `POST /`. Step 3 also parses a body sent as `application/a2a+json`. In step 4, a request without the `A2A-Version` header, or with one that names any version but `1.0`, gets version not supported before its body is checked, and a patch number is not considered. The body is the `SendMessageRequest` itself, with no JSON-RPC request around it, and its message gets the checks a v1.0 message to `POST /` gets. Each error with a body from steps 3 to 6 is a `google.rpc.Status`, as section 11.6 of A2A v1.0 defines it, with the media type `application/a2a+json`: `code` is the HTTP status and `status` the `google.rpc.Code` name. A body step 3 rejects, the fields step 4 rejects (listed in a `google.rpc.BadRequest`) and a text part step 5 rejects get `INVALID_ARGUMENT` with the HTTP status they get at `POST /`; version not supported gets 400 `FAILED_PRECONDITION` and task not found 404 `NOT_FOUND`, the statuses section 5.4 gives them, each with a `google.rpc.ErrorInfo` that names it; step 6 gets 500 `INTERNAL`.

```typescript
const MEDIA_TYPES = ["text/plain", "application/json", "application/pdf", "image/png", "image/jpeg"] as const;

const TextPartSchema = z.object({
  kind: z.literal("text"),
  text: z.string().min(1).max(10000),
});

const FilePartSchema = z.object({
  kind: z.literal("file"),
  file: z.object({
    bytes: z.string().max(1048576).pipe(z.string().refine(isBase64, "Invalid base64")), // 1MB base64
    mimeType: z.enum(MEDIA_TYPES),
    name: z.string().max(255).optional(),
  }),
});

const PartSchema = z.discriminatedUnion("kind", [TextPartSchema, FilePartSchema]);
```
