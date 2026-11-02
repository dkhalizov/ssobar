# SSOBar

Minimal Leapp replacement: a native macOS menu bar app that keeps AWS IAM Identity Center (SSO)
role credentials in `~/.aws/credentials`, auto-refreshed. One Swift file, no dependencies.

- Click a session to activate it for its profile; this deactivates the other sessions on the same profile.
- Credentials are refreshed 10 min before they expire (`refreshMinutesBefore`), every minute and on wake.
- The SSO token is renewed silently with a refresh token. The browser opens only when the
  Identity Center session really ends, and at most once every 30 min on its own (or when you click).
- Only the profile sections it manages are touched. Everything else in the credentials file is kept.

Files:
- `~/.config/ssobar/config.json` holds the portal URL and sessions (edit via menu → Edit config…, auto-reloaded)
- `~/.config/ssobar/state.json` (0600) holds the OIDC client and tokens

```sh
./build.sh install      # build, copy to ~/Applications, start
./import-leapp.sh       # one-time import of Leapp SSO sessions (--force to overwrite)
```
