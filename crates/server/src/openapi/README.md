# OpenAPI docs (`openapi` feature)

`openapi::serve_docs(title, &spec)` serves two routes:

- `/docs`: `docs.html`, the [Scalar](https://github.com/scalar/scalar)
  API reference, with `$title` filled in.
- `/docs/openapi.json`: the OpenAPI spec Scalar renders, anything
  serializing to an OpenAPI document (eg utoipa's `OpenApi`). It is
  serialized, gzipped and hashed once when the router is built, and
  served with a weak ETag and `Cache-Control: no-cache`, so browsers
  revalidate it (an empty 304) rather than re-download hundreds of KB
  on every load of the docs. This is why the spec is not inlined into
  the page.

`docs.html` configures Scalar through `data-configuration`:

- `hideModels: true` keeps the component schemas out of the sidebar
  and page (they still render inline on each operation). This is the
  main thing keeping the page responsive for a large spec.
- `proxyUrl: ""` disables Scalar's default request proxy
  (`proxy.scalar.com`), so "Send request" goes straight to the server.

## Bumping Scalar

The bundle is pinned to an exact version with a
[Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)
hash, so the page never changes underneath the apps (the unpinned CDN
URL resolves to whatever is latest). To bump it:

1. Pick the version, eg from
   <https://www.npmjs.com/package/@scalar/api-reference?activeTab=versions>.
2. Download the exact file the page loads, and hash it:

   ```sh
   VERSION=1.72.1
   curl -sL "https://cdn.jsdelivr.net/npm/@scalar/api-reference@$VERSION/dist/browser/standalone.js" -o standalone.js
   echo "sha384-$(openssl dgst -sha384 -binary standalone.js | openssl base64 -A)"
   ```

3. In `docs.html`, update the version in the script `src` and the
   `integrity` attribute.
4. `cargo test -p mogh_server --features openapi`, then run an app
   using it (eg `cargo run -p example_server`) and open `/docs` in a
   browser. The page must render, and the network tab should show
   `openapi.json` served gzipped, and revalidated (304) on reload.
   Check the browser console too, Scalar warns there about deprecated
   config options. Load the page once more under the
   `Content-Security-Policy` the page gets from `configure_app`
   (mogh_ui's policy plus `script-src` / `font-src`, see
   `docs_content_security_policy`): the console must show no refusal.
   If the new Scalar loads from another host (eg. its fonts), update
   the sources in `docs_content_security_policy`, its test and the
   README, and say so in the release notes: operators whose policy
   sets `script-src` / `font-src` itself must change it.
5. Release a new `mogh_server` and bump the apps.

Notes:

- Hash `dist/browser/standalone.js` (the minified file published in
  the npm package), **not** `standalone.min.js`. jsDelivr generates the
  latter on the fly with its own minifier, so its bytes can change
  without a version bump and fail the integrity check, which leaves a
  blank docs page.
- The page uses Scalar's HTML API (`<script id="api-reference"
  data-url=... data-configuration=...>`) to pass the spec URL and
  options. Check the release notes for changes to it when bumping a
  major version.
