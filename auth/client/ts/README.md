# mogh_auth_client

Typescript client for a `mogh_auth_server` auth api: the request and
response types, a typed client, the login token store of the browser,
the passkey helpers, and the request helpers the apps' clients send
their own requests with.

```ts
import * as MoghAuth from "mogh_auth_client";

const auth = MoghAuth.MoghAuthClient(
  "https://example.com/auth",
  MoghAuth.LOGIN_TOKENS.jwt(),
);
const options = await auth.login("GetLoginOptions", {});
```

The second argument is the credential the client sends with its
requests (`MoghAuth.ClientCredential`):

- a JWT, sent as `Authorization`: a string, or `{ jwt }`.
- an api key, `{ key, secret }`, sent as `X-API-KEY` / `X-API-SECRET`.
  The server takes it for the manage requests open to api keys, eg.
  `GetUserId`, `DeleteApiKey`, and an admin's login provider / trusted
  issuer requests. A request with an api key doesn't follow redirects
  (see [Redirects of requests with an api key](#redirects-of-requests-with-an-api-key)).

A `jwt` is sent when set, otherwise the api key when both its parts are,
otherwise nothing (only the session cookie goes along). So an app client
passes the `{ jwt, key, secret }` it was created with as is.
`credentialHeaders(credential)` gives the same headers for the app's own
requests.

## Errors

Every request rejects with `{ status, result, error? }`
(`MoghAuth.RequestError`):

- `status` is the http status, or `1` when the server wasn't reached
  (network / CORS failure).
- `result` is the error body of the server: `{ error, trace }`, where
  `error` is always a string and `trace` a list of strings. When the body
  isn't json (eg. a proxy's `502` page), or is json of another shape (eg.
  a gateway's `{"error":{"code":403}}`), `error` names the status and
  `trace` holds the start of the body. A `200` with an invalid body
  rejects with `Invalid response body`.
- `server` is `true` when `result` is the server's own error body (json
  with a string `error` and a `trace` list). Not for the error page of a
  proxy, nor for the `401` / `403` of an auth gateway in front of the
  server: those say nothing about the credentials the request was sent
  with.
- `error` is the caught error, if any.

`isReauthenticationRequired(e)` tells whether a manage request needs the
user to log in again. It takes anything that was caught, never throws,
and is `false` for any other value.

`tokenExchange` rejects the same way, with the OAuth error
`{ error, error_description }` as `result`. A body which isn't an OAuth
error is `server_error`, with the status and the start of the body as
`error_description`. `temporarily_unavailable` means retry later: `429`
after too many failed requests, `503` while a login provider or trusted
issuer of the token's issuer can't be loaded.

## Requests of the app's own api

The apps' clients send their requests the same way, so a UI handles the
failures of auth and app requests alike, and the rules above live in one
place:

```ts
const notes = await MoghAuth.fetchJson<Note[]>(`${url}/read/ListNotes`, {
  method: "POST",
  body: JSON.stringify({}),
  headers: { "content-type": "application/json", authorization: jwt },
});
```

- `fetchJson<Res>(input, init)` sends the request with `fetch` and
  resolves with the json of a `200`. It rejects with a `RequestError` on
  any failure, never with anything else.
- `fetchResponse(input, init)` resolves with the `200` response itself,
  eg. to stream its body, and rejects like `fetchJson`.
- For a response fetched another way: `responseJson(response)` (the json
  of a `200`, or the rejection), `responseError(response)` (what a status
  other than `200` rejects with) and `requestFailed(error)` (what a
  request which got no response rejects with).

### Redirects of requests with an api key

`fetchJson` and `fetchResponse` (and so `MoghAuthClient`) send a request
carrying an api key (`X-API-KEY` / `X-API-SECRET`) with
`redirect: "error"`, unless its `init` sets `redirect` itself: a redirect
then rejects with `status: 1` instead of being followed. `fetch` outside
a browser (node, Deno, Bun, a Komodo Action) drops only `Authorization`
(and the browser's cookies) on a redirect to another origin, and sends
every other header on to wherever the redirect points: the login page of
an SSO proxy in front of the server, or the new address of a server
which moved, would get the api key, and a `307` / `308` sends the body
again too. A JWT in `Authorization` is dropped, so such requests follow
redirects as usual. A request with an api key sent with plain `fetch`
should pass `redirect: "error"` too.

## Login tokens

`LOGIN_TOKENS` keeps the tokens of the signed in users in `localStorage`
(key `mogh-auth-tokens-v1`).

- The stored tokens are shared by every tab of the origin: a login or a
  logout in one tab applies to all of them. Every call reads the latest
  stored state, so tabs never undo each other's changes.
- The current user is kept per tab. A tab starts with the user chosen
  last (in any tab), and only changes it by its own `add_and_change`,
  `change` or `remove`. Signing in another user or switching the user
  in one tab leaves the other tabs with their user, so a tab never
  starts sending the token of another user than the one it shows.
- When a tab's user signs out in another tab, that tab is signed out:
  `jwt()` gives `""`. It resumes when the user signs in again.
- `LOGIN_TOKENS.subscribe(listener)` calls `listener` after a change in
  this or another tab, eg. to show the login page and drop the cached
  data when the user signed out in another tab. It fits React's
  `useSyncExternalStore(LOGIN_TOKENS.subscribe, LOGIN_TOKENS.jwt)`.
- Apps served from the same origin (several apps behind one host, or
  `localhost` in development) share the default key. Give each app its
  own store with `createLoginTokens({ key: "my-app-tokens" })`, unless
  it uses the auth pages and hooks of `mogh_ui`: they always use the
  default `LOGIN_TOKENS`, so the app has to use it too (a store of its
  own would stay empty after every login).
- Where `localStorage` is unavailable (in node, or in a browser blocking
  site data, eg. in an iframe with third party cookies blocked), the
  tokens are kept in the page's memory instead, so the user can still
  log in: the login lasts until the page is closed or reloaded, and
  other tabs don't see it. A blocked `localStorage` is warned about
  once. So `LOGIN_TOKENS` is always a store, never `undefined`.
- The storage is read on first use, not on import: importing the
  package (eg. for the client in node, where reading `localStorage`
  warns) touches no storage.

## Refused tokens

Every request with a token the server refuses counts against its per IP
auth rate limit, which logging in shares. So a token the server refused
is never sent again, by any caller: the app's client and the auth and
supporter hooks of `mogh_ui` share the one latch of `LOGIN_TOKENS`.

```ts
const jwt = MoghAuth.LOGIN_TOKENS.sendableJwt();
if (!jwt) return showLoginPage();
try {
  return await MoghAuth.MoghAuthClient(url, jwt).manage("GetUserId", {});
} catch (e) {
  if (MoghAuth.isTokenRefusal(e, [401, 403])) {
    MoghAuth.LOGIN_TOKENS.refuse(jwt);
  }
  throw e;
}
```

- `isTokenRefusal(e, refusedOn = [401])` tells whether a failed request
  is the server refusing the token: a status of `refusedOn` with the
  server's own error body (`RequestError.server`), not the `401` / `403`
  of a proxy or an auth gateway in front of it. Pass `[401, 403]` for a
  request whose `403` also means that the session is over (`GetUserId`,
  an app's `GetUser`), rather than a missing permission.
- `LOGIN_TOKENS.refuse(jwt)` notes the refusal. `sendableJwt()` gives
  this tab's token unless it was refused (`""` then), `isRefused(jwt)`
  checks a given token.
- `subscribeRefusals(listener)` calls `listener` on each new refusal, eg.
  to show the login page. The `subscribe` listeners are called too, so
  `useSyncExternalStore(LOGIN_TOKENS.subscribe, LOGIN_TOKENS.sendableJwt)`
  re-renders.
- Refusals are kept per tab, until the page is reloaded. A new login
  gives a new token, which is sent.

## Passkeys

```ts
navigator.credentials
  .get(MoghAuth.Passkey.prepareRequestChallengeResponse(challenge))
  .then((credential) =>
    auth.login("CompletePasskeyLogin", {
      credential: MoghAuth.Passkey.credentialToJSON(credential),
    }),
  );
```

`credentialToJSON` base64url encodes the binary fields of the credential
where the browser (or a password manager extension) has no
`PublicKeyCredential.toJSON`. The client applies it to
`CompletePasskeyLogin` and `ConfirmPasskeyEnrollment` itself.

## Redirects

`safeBackto()` gives the `backto` query of the login page when it is a
path on the current origin, otherwise `/`. Check `backto` with it before
navigating there after a login. The result is a normalized path which
never starts with `//`, even for input like `/.//evil.example`, so it
can be passed to `location.replace` or a router as is.

`externalLogin` uses it too: started on the login page itself (`/login`
or `/login/`, not other paths starting with it like
`/login-providers/:id`), the provider sends the user back to the checked
`backto`, from anywhere else back to the current page.

## Development

```sh
npm run build   # tsc, into dist
npm test        # build, then the node tests in test/
```

`src/types.ts` is generated from the rust types:
`node auth/client/ts/generate_types.mjs` (needs `typeshare`), which
fails when typeshare fails.
