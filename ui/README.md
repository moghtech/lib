# mogh_ui

Common UI components and styling used across Mogh apps
([Mantine](https://mantine.dev) + React), including the pages and
components of [mogh_auth](../auth) (login, profile, login providers,
trusted issuers), and the supporter badge of
[mogh_supporter](../supporter/ts) (`useSupporter`, `SupporterBadge`).

## Requirements

mogh_ui is published as ESM source for a bundler, and is built and tested
with [Vite](https://vite.dev). It can't be loaded by Node directly (and has
no CommonJS build):

- Components import `.module.scss` files, so the app needs a Sass compiler:
  `sass-embedded` (or `sass`) in its dev dependencies.
- The Monaco editor loads its workers with Vite's `?worker` imports.
- Relative imports are extensionless, left for the bundler to resolve.

Install the peer dependencies next to it (npm does this by default),
`prettier` included: the editor formats yaml / typescript with it
(Alt + Shift + F, not in a read only editor), loaded only when used.
A format is one edit, which undo reverts, and is dropped when the text
changed while it ran.

```ts
import "mogh_ui/index.scss";
import { ThemeProvider } from "mogh_ui";
```

## Notes

- The auth pages and hooks (`LoginPage`, `useAuthState`, `authClient`,
  ...) keep the user's tokens in the default `MoghAuth.LOGIN_TOKENS`
  store of `mogh_auth_client`, and the app has to read them from there.
  A store with its own key (`createLoginTokens({ key })`) isn't used by
  them.
- The login page's `backto` (`backtoPath`) is only followed to a path on
  the app's origin, and without the query params an external login
  returns with (`redeem_ready`, `totp`, `passkey`, `login_error`,
  `link_error`): the server adds its own to the url the provider sends
  the user back to, and `useAuthState` would take one already there for
  the server's. `externalLogin` drops them from the current url too.
- `useAuthState` redeems a `redeem_ready` in the url once per page load.
  The login it redeems waits in the visitor's own session, so it
  completes in whichever tab the login returns to (eg. one opened by a
  link in an email which the provider sent to finish it), also after a
  reload while redeeming. Anyone can put it in a link, which can only
  complete the visitor's own login, and otherwise fails.
- Start external logins through mogh_ui (`externalLogin`, `LoginPage`),
  not the client's `externalLogin`: it notes (in `sessionStorage`, for
  30 minutes) that the tab left for the provider. Only on the page load
  which returns from a login the tab started does `useAuthState` show
  the server's error when redeeming fails, or the reason in a
  `login_error` / `link_error`. Otherwise (eg. a link carrying them) the
  redeem's error is only logged to the console, and a login error only
  says the login didn't complete. Either way a failed login removes its
  param from the url, and a user who isn't logged in lands on the login
  page without its auto redirect.
- After logging in, `LoginPage` goes on to `backto` only on the login
  route itself (`/login`, `/login/`). Shown anywhere else (eg. for the
  second factor of an external login which returned to
  `/login-providers/:id`) it stays on the page. The url an external
  login or second factor returns to keeps its fragment.
- `Config` shows one confirm dialog behind all of its Save buttons.
  Ctrl / Cmd + Enter (outside of text inputs) opens it while there are
  changes, and Enter in the open dialog saves (it opens with its Save
  button focused). `ConfirmUpdate` does the same for a single Save button,
  and with `confirmKeyListener={false}` Enter doesn't save: the dialog
  opens with its close button focused. When several are mounted, only
  the first one takes a key press, and none opens while a confirm dialog
  is open.
- `ConfirmModal` starts every open with an empty input: text typed for an
  earlier open doesn't confirm the next one.
- `useKeyListener` / `useShiftKeyListener` / `useCtrlKeyListener`: a
  handler returning `false` declines the press, which then keeps its
  browser default (eg. Enter on a focused button).
- The supporter badge and its settings talk to the app's supporter api
  (`mogh_supporter`'s `server::router`, mounted at `/supporter`) on
  their own: call `setSupporterUrl` before the first render, like
  `setAuthUrl`. `useSupporter({ app, releaseDate, rootKeys })` asks
  for the key in use once per page load and verifies it in the browser
  under `rootKeys`, the root public keys the app hardcodes (each app
  has its own, the libraries ship none),
  `SupporterBadge` renders it: a quiet "Become a supporter" (subtle,
  dimmed) without a valid key, else the name with the heart, or the
  organisation's icon (its branding, below). It goes next to the
  app's home button, takes the props of the button it is (eg.
  `visibleFrom`, to leave it out on a small screen), and its text is
  cut with an ellipsis where the topbar is short of room. Both have a
  hover card for the app's own words: `unsupportedText` on the offer
  (what supporting the app means; no card without it), and
  `supportedText` under the thanks on a supporter's badge (a node, or
  a function of the supporter). Don't say there that a key unlocks
  anything or expires.
  `releaseDate` is the `YYYY-MM-DD`
  of the build, set at build time, never the current date. The result
  stays in memory for the life of the page, never in storage.
  `SupporterKeyConfig` is the settings section for admins: what is
  configured (never the key itself), a field to paste a key into,
  and its removal; the badge updates without a reload.
- With the key of an organization or sponsor, `SupporterKeyConfig`
  also edits the branding, in a `Config` section of its own under the
  key's (its changes are listed in the confirm dialog before they are
  saved; an uploaded image shows there by its name and size): an icon
  in place of the heart (an image
  url, or an uploaded image of up to 256 KB), the icon's width and
  height, a link the badge opens in a new tab instead of the Mogh
  supporter page, a switch to hide the name for an icon which
  includes it, a switch to show the name in capital letters, and a
  switch to show icon and name in place of the app's home button. The topbar gets it from `useSupporterBrand({ app,
  releaseDate, rootKeys })`: `supporter` and `branding` go to
  `SupporterBadge`,
  and while `homeBrand` is set the app renders its home button from
  it (`SupporterBrandIcon` for the icon, `homeBrand.name` for the
  text, still linking to `/`), and the badge renders nothing. While
  `homeBrand.uppercaseName` is set the app shows the name in capitals
  (a `text-transform`, like its own name). While
  `homeBrand.hideName` is set the icon is the whole home button, with
  the name as its `aria-label`: it is only set with an icon, and not
  while the icon fails to load, so the name is never lost. The
  branding only shows for a key the browser verified as an
  organization's or sponsor's.
- `SupporterBrandIcon` shows the icon as high as the branding sets,
  else 20 pixels (`DEFAULT_ICON_HEIGHT` of mogh_supporter), wherever
  it shows, and as wide as the branding sets, else as the image is at
  that height. `maxWidth` caps the width for a narrow place, eg. the
  topbar of a small screen. An icon can be up to 56 pixels high, which
  fits a topbar of 62: `supporterIconHeight(brand)` is the height to
  make room for (a Mantine `Button` has a fixed height and clips what
  is higher).

## Development

```sh
npm install
npm run typecheck
npm test        # unit tests (node --test)
npm run build
```

The [example app](../example) uses the local build (`file:` dependency),
and its Playwright suite exercises the auth pages end to end.
