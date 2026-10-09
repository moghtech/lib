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
- The auth and supporter queries (`useUserId`, the provider / issuer
  lists, `useSupporter`, `useSupporterBranding`, `useSupporterKeyInfo`)
  share the refused token latch of that store with the app's own
  client: every request with a token the server refuses counts against
  its per IP auth rate limit, which logging in shares. A token the
  server refused (its own `401`, see `MoghAuth.isTokenRefusal`) is
  noted with `LOGIN_TOKENS.refuse`, and from then on these queries are
  disabled and send nothing until there is another token. So the app's
  client should note the refusals it sees there too
  (`LOGIN_TOKENS.refuse(jwt)`), and send `LOGIN_TOKENS.sendableJwt()`.
- `AccountsMenu` is the topbar's account menu over those tokens: the
  signed in accounts (switch, sign out in every tab), "Add Account"
  (`addAccountPath()`: `/login?backto=<here>&disableAutoLogin=true`, so
  a provider set to auto redirect doesn't answer for the account
  already signed in there), the profile and "Log Out All". The app
  passes its user (`{ id, username, avatar? }`), a hook looking up
  another account's username / avatar (`useAccountInfo`, eg. its
  `GetUsername`) and its cleanup for signed out users (`onSignOut`, eg.
  drafts kept in `localStorage`); the page reloads when this tab's user
  signed out. Under it: `useAccounts`, `useCurrentUserId`, and
  `useResetOnUserChange` (call it once at the top of the app: it drops
  the cached queries and mutation variables when the tab's user
  changes).
- The auth requests (`useLogin`, `useManageAuth`, the redeem of
  `useAuthState`) are forgotten once they settled and the caller's
  callbacks ran: their params (a password, a code, a credential) and
  answers (a token, TOTP recovery codes, a new key's secret) leave the
  hook's state and the query client's mutation cache at once
  (`gcTime: 0`), which would keep them for 5 minutes. Use an answer in
  `onSuccess` (or from the `mutateAsync` promise), not from `data` /
  `error`; a callback passed to `mutate` itself doesn't run.
- `AuthProfileSections({ user, refetchUser, loginExtra? })` is the auth
  part of a profile page: Login (username, and the password where local
  login is enabled), the linked providers (`LinkedLogins`) and 2FA
  (`EnrollPasskey`, `EnrollTotp`, skipping it for external logins). The
  app maps its user to `{ username, passwordSet, totpEnrolled,
  passkeyEnrolled, externalSkip2fa, linkedLogins }` and keeps its own
  sections around it (`loginExtra` adds to the Login section, eg.
  ending the user's sessions).
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
- Login providers and trusted issuers are edited on their pages:
  `LoginProvidersTable` / `TrustedIssuersTable` take the route of the
  app's `LoginProviderPage` / `TrustedIssuerPage` (`link`, eg.
  `` (id) => `/login-providers/${id}` ``), which the names link to and a
  new provider / issuer continues on. Each page checks its draft before
  saving (what the server would refuse), says why a save was refused,
  and then shows the errors at their fields. An emptied number (a
  maximum token age, a token lifetime) is such an error: it is never
  saved as 0, which is no limit at all.
- `Config` shows one confirm dialog behind all of its Save buttons.
  Ctrl / Cmd + Enter (outside of text inputs) opens it while there are
  changes, and Enter in the open dialog saves (it opens with its Save
  button focused). `ConfirmUpdate` does the same for a single Save button,
  and with `confirmKeyListener={false}` Enter doesn't save: the dialog
  opens with its close button focused. When several are mounted, only
  the first one takes a key press, and none opens while a confirm dialog
  is open.
- A `Config` field with `secret: true` (a webhook secret, a url
  carrying a token) is a masked input with a toggle to show it
  (`ConfigSecretInput`), so it isn't on screen whenever the page is,
  and the confirm dialog shows that it changed, never its values
  (`secretKeys` does the same for a field the app renders itself).
- `ConfigNumberInput` is the number input of a `Config` (its number
  fields use it), for a field of its own too: `min` / `max` /
  `allowDecimal={false}` (eg. an integer field of the api), and
  NumberInput's props (`rightSection` for a unit). Only a complete
  number in range reaches `onValueChange`, only when it changed:
  partial input ('' or '-') stays in the input, not saved as 0.
- Copying (`CopyButton`, `CopyText`, `ConfirmModal`'s click to copy) goes
  through `copyToClipboard(text, label)`: the browser only has a
  clipboard api in a secure context (https, or localhost), so on a page
  served over plain http nothing is copied and the notification says so
  (select the text instead), and "Copied" only shows once the browser
  took the text. `RevealOnce` shows what can only be shown once (a new
  secret, TOTP recovery codes) in read only inputs, selectable for that
  manual copy, each with a copy button, then Done. With `confirmSaved`
  Done asks whether they were saved first, and while they show the
  popover or modal around it holds open: it provides `HoldOpen` (from
  `useHoldOpen()`) and passes `closeOnClickOutside={!held}`,
  `closeOnEscape={!held}` (a modal also `withCloseButton={!held}`).
  The TOTP enrollment's recovery codes do.
- `DataTable` keys its rows (and their cells) by index unless it is
  given `getRowId` (eg. `(row) => row.id`): pass it for a table whose
  cells hold state of their own (an input with a draft, a selector),
  which otherwise stays at its index when a filter or the sorting moves
  another row there. With `selectOptions` the rows are keyed by its
  `selectKey`. Rows with `onRowClick` are focusable and open with Enter
  / Space as well.
- Every icon-only button mogh_ui renders has an accessible name (its
  `aria-label`), and `ThemeProvider`'s theme gives Mantine's close
  buttons of a `Modal`, `Drawer` or `Notification` theirs ("Close"),
  in the app's own dialogs too. `ConfirmIcon` shows the caller's icon:
  pass its `label`.
- `ConfirmModal` starts every open with an empty input: text typed for an
  earlier open doesn't confirm the next one. It runs one confirm at a
  time: from the click until `onConfirm` settled the button waits and
  the dialog stays open, then closes (or stays to retry a failure).
  With `opened` / `onClose` the caller controls it and no button of
  its own renders (eg. a dialog opened from a menu item, whose dropdown
  unmounts on the click). Without `confirmText` the click alone
  confirms.
- `SearchPicker({ picker, target, children, ... })` is a searchable
  picker: the `target` button opens a dropdown with a search input
  (named by `searchPlaceholder`) over the options (`Combobox.Option`s),
  which the caller filters by `picker.search` (`picker` is
  `useSearchCombobox()`), in the browser or in its query. `onClear`
  adds a clear button of its own next to the target (a button inside
  the target button is invalid, and only a mouse reaches it).
  `pickerTargetProps(combobox)` are the usual target's props,
  `usePickFirst` picks the first option once loaded.
- `useSingleFlight(fn)` runs an async action one call at a time: a call
  while one is in flight is dropped (resolves to `undefined`). A second
  press (a double click, a held Enter) can land before React renders
  the loading or disabled state of the first, and would send the
  request again. `ConfirmUpdate`'s dialog and the passkey enrollment
  use it.
- `EnableSwitch` with `toggleOnEnter`: Enter toggles it as Space does,
  through its own `onChange` / `onCheckedChange` (eg. a form's
  `getInputProps`), instead of submitting the form around it.
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
  `releaseDate` is the app's release date, never the current date:
  the `releaseDate` of its package.json, which its vite config defines
  with `mogh_supporter/vite` (a production build fails without one).
  The result stays in memory for the life of the page, never in
  storage.
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
  `SupporterBadge`, and `homeBrand` to `SupporterHomeButton({ brand,
  wordmark, logo })`, the topbar's home button: the app's logo and
  name, or while `homeBrand` is set the brand's icon (the app's logo
  while it has none) and name, still linking to `/`, and the badge
  renders nothing. The button makes room for an icon higher than
  itself, shows the name in capitals while `homeBrand.uppercaseName`
  is set (a `text-transform`, spaced like the app's name), and while
  `homeBrand.hideName` is set the icon is the whole home button, with
  the name as its `aria-label`: it is only set with an icon, and not
  while the icon fails to load, so the name is never lost. It takes
  the props of the button it is (eg. `visibleFrom="md"`), and
  `compact` is the small screen variant (the icon alone, at most
  `compactMaxWidth` wide). The branding only shows for a key the
  browser verified as an organization's or sponsor's.
- `SupporterBrandIcon` shows the icon as high as the branding sets,
  else 20 pixels (`DEFAULT_ICON_HEIGHT` of mogh_supporter), wherever
  it shows, and as wide as the branding sets, else as the image is at
  that height. `maxWidth` caps the width for a narrow place, eg. the
  topbar of a small screen. An icon can be up to 56 pixels high, which
  fits a topbar of 62: `supporterIconHeight(brand)` is the height to
  make room for (a Mantine `Button` has a fixed height and clips what
  is higher).

## Content Security Policy

A CSP is opt-in (mogh_server's `content_security_policy`, empty by
default). mogh_ui works under this one:

```
default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; worker-src 'self' blob:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'
```

- `style-src 'unsafe-inline'`: Mantine injects the theme's CSS variables
  as a `<style>` element, its components and Monaco set `style`
  attributes, and Monaco adds `<style>` elements of its own. With
  `style-src` falling back to `'self'` the pages render unstyled.
- `img-src data: https:`: the TOTP QR code is a `data:` image, and a
  supporter's branding icon is an image url on any host, or an uploaded
  image (`data:`). Avatars of login providers are https urls too.
- `worker-src 'self' blob:`: Monaco's workers.
- `connect-src`: `default-src 'self'` covers the app's own api and
  websockets. Add the origin of the auth / supporter api
  (`setAuthUrl` / `setSupporterUrl`) when it isn't the page's.
- Anything the app's own `index.html` inlines (eg. a script) needs its
  own source or hash.

## Development

```sh
npm install
npm run typecheck
npm test        # node --test (tests/*.test.ts), then vitest (tests/*.test.tsx)
npm run build
```

`tests/*.test.ts` run in node's own runner. The hook and component
tests are `tests/*.test.tsx`: vitest renders them with React in jsdom
(`npm run test:dom`), inside the providers of `tests/render.tsx`.

The [example app](../example) uses the local build (`file:` dependency),
and its Playwright suite exercises the auth pages end to end.
