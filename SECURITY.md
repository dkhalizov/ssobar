# Security Policy

SSOBar handles AWS credentials, so security reports are very welcome.

**Please don't open a public issue for vulnerabilities.** Report them privately via
[GitHub Security Advisories](https://github.com/dkhalizov/ssobar/security/advisories/new).
You should get a response within a few days.

Supported versions: the latest release.

## What SSOBar stores

| File | Contents | Permissions |
| --- | --- | --- |
| `~/.config/ssobar/state.json` | SSO OIDC client registration, access and refresh tokens | `0600` |
| `~/.config/ssobar/config.json` | Portal URL, account IDs, role names, profile names | `0600` |
| `~/.aws/credentials` | Short-lived role credentials for active profiles | `0600` |

Network traffic goes only to `oidc.<region>.amazonaws.com` and `portal.sso.<region>.amazonaws.com` over HTTPS.
There is no telemetry.
