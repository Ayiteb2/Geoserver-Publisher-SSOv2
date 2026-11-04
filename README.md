# GeoServer Publisher SSO (QGIS plugin)

The SSO edition of [GeoServer Publisher](https://github.com/Ayiteb2/geoserver-publisher). It publishes QGIS vector layers to GeoServer without an admin account, and adds **sign-in with Microsoft / Azure (OpenID Connect) SSO** for servers behind an SSO proxy.

It installs **side by side** with the original plugin: separate menu ("GeoServer Publisher SSO"), settings and log file.

## What's new compared to GeoServer Publisher 0.1.0

- **Sign in with Microsoft…** opens Microsoft Edge (or Chrome) at your GeoServer. You sign in as usual (account, MFA), and the plugin reuses that browser session for its requests.
- **Paste a session** instead: the *SSO session* field also accepts a `Cookie` header copied from your browser's developer tools.
- **No more false successes.** QGIS follows redirects silently, so an SSO sign-in page used to look like "HTTP 200". Any answer that is a sign-in page, an HTML page, or a redirect to another host (such as `login.microsoftonline.com`) is now reported as a **failure** with a hint.
- **Every REST publish is verified.** It only reports success if the new layer can be read back from GeoServer.
- If REST answers with a sign-in page, the plugin stops before exporting or uploading anything.

## Authentication options

Use whichever your server accepts; they can be combined.

| Option | When to use |
|---|---|
| Username / password | Works on most servers, including SSO-protected ones whose proxy also accepts Basic credentials |
| QGIS auth config | Same, with the password stored encrypted by QGIS |
| SSO session (Sign in with Microsoft, or paste) | Your organisation's SSO account, with no GeoServer password |

## How "Sign in with Microsoft" works

QGIS's built-in browser components can't display Microsoft's sign-in page. QtWebEngine has no Python bindings in standard QGIS builds, and QtWebKit renders the page blank. So the plugin:

1. Starts Edge (or Chrome) in a **separate profile** (`<QGIS profile>/geoserver_publisher_sso/browser_profile`). Remote debugging is enabled on `127.0.0.1` only, on a random port.
2. Opens the workspace's REST page (`<GeoServer URL>/rest/workspaces/<workspace>.json`) and waits while you sign in.
3. Once the window is back on the GeoServer host, it reads **only the cookies for that host**, through the Chrome DevTools Protocol.
4. Waits until the window has settled on a GeoServer page that is not a step of the sign-in itself, usually GeoServer's home page. Then it checks the session **once** against the workspace's REST endpoint.
5. When GeoServer accepts the session, it closes the browser window.

Where the cookies go:
- They're kept **in memory only**, for the current QGIS session.
- They're never written to settings.
- They're redacted from all logs.

The browser profile keeps the identity provider's "remember me" state, so later sign-ins are quicker. Delete that folder to forget it.

You must enter a **workspace** before signing in. The session is checked against that workspace's REST endpoint, because WFS is often open to anonymous users and can't prove you're signed in.

When the session expires, publishing fails with *"an SSO session was sent but not accepted"*. Click **Sign in with Microsoft…** again.

**Requirement on the server side:** GeoServer's REST API must accept the SSO session. That's typical when a reverse proxy does the SSO and forwards requests to GeoServer.

**GeoServer's own OpenID Connect extension** (`sec-oidc`; its sign-in redirect contains `.../web/login/oauth2/code/<filter>__oidc`) works, provided the session is never checked while the browser is still signing in. Each rejected check follows GeoServer's redirect and starts a new sign-in in that same session, which replaces the one the browser is completing. 0.2.1 and 0.2.2 checked every 4 seconds and kept saying *"GeoServer did not accept the session"*. 0.2.4 checks only after the window has settled, and only once per session. This was tested against GeoServer 3.0.2 with the `sec-oidc` extension and a Keycloak identity provider.

**Username/password with the OIDC extension:** when the OIDC filter comes before `basic` in GeoServer's `rest` filter chain, REST redirects even correct Basic credentials to the sign-in page (curl and browsers get a 302). In QGIS, publishing with credentials can still work. The first request goes to OWS, which accepts Basic and hands out a session cookie, and QGIS sends that cookie on to REST. For reliable Basic access to REST, the GeoServer admin can put `basic` **before** the OIDC filter in the `rest` chain.

Quick check in a normal browser:
1. Sign in to GeoServer.
2. Open `<GeoServer URL>/rest/workspaces/<workspace>.json`.

If you see JSON, the session works for REST.

### Paste a session manually

1. Sign in to GeoServer in your browser.
2. Press **F12**, open the **Network** tab, and reload the page.
3. Click a request to the GeoServer host.
4. Under **Request Headers**, copy the value of `Cookie`.
5. Paste it into the *SSO session* field.

## Modes

| Mode | What it does | Needs |
|---|---|---|
| REST: shapefile | Exports the layer, zips it, uploads it, creates or replaces the store and layer | REST access to the workspace |
| REST: GeoPackage | Same, as a GeoPackage (keeps field names longer than 10 characters) | REST access, plus GeoPackage support on the server |
| WFS-T append | Adds features to an **existing** layer | WFS-T write access only, no REST |

Options: selected features only, and uploading the QGIS style as SLD (set as the layer's default style).

## Install

1. Download `geoserver_publisher_sso.zip` from Releases.
2. In QGIS: **Plugins > Manage and Install Plugins > Install from ZIP**.
3. Open it from **Web > GeoServer Publisher SSO** or the toolbar button.

Requires QGIS 3.16 or newer, and Microsoft Edge or Google Chrome for browser sign-in. Tested on QGIS 3.44 with GeoServer 3.0.2 and Edge 156.

## GeoServer setup for a non-admin user

By default GeoServer allows REST only for `ROLE_ADMINISTRATOR`, so a workspace user gets **403 Forbidden** even when they can manage the workspace in the web admin.

**1. Data security** (`<data dir>/security/layers.properties`):

```
ne.*.a=editor_role
```

**2. REST security** (`<data dir>/security/rest.properties`): add these lines **above** the existing catch-all rules, then restart GeoServer.

```
/rest/workspaces/ne*;GET,HEAD,OPTIONS=ROLE_ADMINISTRATOR,editor_role
/rest/workspaces/ne/**;GET,HEAD,OPTIONS,POST,PUT,DELETE=ROLE_ADMINISTRATOR,editor_role
```

Replace `ne` and `editor_role` with your workspace and role.

## Logs

- In the dialog's log pane
- In the QGIS message log, tab "GeoServer Publisher SSO"
- In a file: `<QGIS profile>/geoserver_publisher_sso/geoserver_publisher_sso.log`

## How it was tested

These tests ran without a real Azure tenant:
- **Regression tests** against a local GeoServer 3.0.2 as the non-admin user: all modes, wrong password, anonymous, a missing layer.
- **SSO tests** through a local simulated SSO reverse proxy:
  - Anonymous requests get a 302 to a separate sign-in host.
  - Basic credentials pass through.
  - A session cookie is issued after sign-in.

The simulated-SSO results:
- Anonymous publishing now fails clearly instead of reporting false success.
- Basic credentials work.
- The real Edge sign-in captured the session.
- Publishing a shapefile with a style, and WFS-T append, both worked with only the session cookie.
- An expired cookie gives the "expired" hint.

- **OIDC tests** against GeoServer 3.0.2 with the `sec-oidc` extension (set up like the production server: OIDC filter first in the REST chain, PKCE, roles from a matching user name) and Keycloak as the identity provider. A real Edge sign-in through the plugin was accepted in about 5 seconds. A shapefile with style and a WFS-T append then worked with only the captured session. The 0.2.2 code, run against the same setup, reproduced the endless "did not accept the session".

The real Azure sign-in still needs testing on a machine with SSO.

## Known limits

- Shapefile field names are cut to 10 characters. Use GeoPackage to avoid this.
- WFS-T is append-only, needs the target layer to exist, and the source must use the same CRS as the target.
- SLD export from QGIS is experimental.
- Publishing runs on the main thread, so QGIS freezes during large uploads.
- Device-compliance (Conditional Access) policies may ask for extra verification in the separate browser profile, or block it.
- While the sign-in window is open, other programs on the same PC could connect to its local debugging port. The window closes as soon as sign-in is captured.
- "Remember password" stores the password unencrypted in QGIS settings. Prefer a QGIS auth configuration.
