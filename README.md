# SSOBar

[![CI](https://github.com/dkhalizov/ssobar/actions/workflows/ci.yml/badge.svg)](https://github.com/dkhalizov/ssobar/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A tiny native macOS menu bar app that keeps **AWS IAM Identity Center (SSO)** role credentials in
`~/.aws/credentials` and refreshes them in the background.

It does one job and does it quickly: pick which SSO role backs which AWS profile, and never think about
expired credentials again. It is a lightweight alternative to Leapp for people who only use AWS SSO.

- **Native and small.** About 700 lines of Swift with no dependencies. It starts instantly and uses roughly 50 MB of RAM.
- **Works with every tool.** It writes plain static credentials, so anything that reads `~/.aws/credentials`
  works: old SDKs, Terraform, Docker volume mounts, IDE plugins and so on.
- **Few browser tabs.** It renews quietly with an SSO refresh token, and only opens the browser when your
  Identity Center session has really ended. Even then it opens **one** tab, and only while you're at the Mac
  ([details](#sleep-wake-and-browser-tabs)).

## Install

**From source** (recommended; needs only the Xcode Command Line Tools, `xcode-select --install`):

```sh
git clone https://github.com/dkhalizov/ssobar.git
cd ssobar
./build.sh install        # builds, copies to ~/Applications and starts it
```

**Prebuilt:** download `SSOBar-<version>.zip` from [Releases](https://github.com/dkhalizov/ssobar/releases),
unzip it and move `SSOBar.app` to `/Applications`. The app is ad-hoc signed but **not notarized**, so macOS
will block the first launch. Allow it in *System Settings → Privacy & Security → Open Anyway*, or run:

```sh
xattr -dr com.apple.quarantine /Applications/SSOBar.app
```

Requires macOS 14 Sonoma or later (Apple Silicon or Intel).

## Quick start

1. Start SSOBar. A key icon appears in the menu bar, and it creates `~/.config/ssobar/config.json`.
2. Choose **Edit config…** and set your portal URL and region:
   ```json
   { "startUrl": "https://my-company.awsapps.com/start/", "ssoRegion": "eu-west-1", "sessions": [] }
   ```
3. Choose **Discover roles from SSO…**. Approve the sign-in in the browser, and every account/role you can
   access is added under the `default` profile.
4. Edit the names and profiles to taste, then click a session in the menu to activate it.

```sh
aws sts get-caller-identity --profile live   # works, and keeps working
```

Coming from **Leapp**? Run `scripts/import-leapp.sh` once to import your AWS SSO sessions and profile
names (no secrets are copied). Quit Leapp and turn off its launch at login, so the two apps don't write to
the same file.

## Configuration

`~/.config/ssobar/config.json` is reloaded automatically when it changes. See
[`config.example.json`](config.example.json).

| Key | Default | Meaning |
| --- | --- | --- |
| `startUrl` | – | Your AWS access portal URL |
| `ssoRegion` | – | Region of your IAM Identity Center instance |
| `refreshMinutesBefore` | `10` | Renew role credentials this long before they expire |
| `credentialsFile` | `~/.aws/credentials` | File to write (symlinks are followed) |
| `sessions[].name` | – | Label shown in the menu |
| `sessions[].accountId` / `roleName` | – | The SSO account and permission set |
| `sessions[].profile` | – | Profile section to write, e.g. `default`, `live` |
| `sessions[].region` | `ssoRegion` | `region` written into the profile |
| `sessions[].active` | `false` | Toggled from the menu |

Only one session per profile can be active at a time. Activating one deactivates the others on that profile.

## How it works

```
 Browser approval (device code, rare)
          │
          ▼
 SSO OIDC ──► access token (~1 h) + refresh token ──► silently renewed
          │
          ▼
 SSO portal GetRoleCredentials (per active session, in parallel)
          │
          ▼
 ~/.aws/credentials   [profile] sections rewritten atomically, 0600
```

- **Checks:** every minute, and immediately after wake, unlock or a network change. Credentials are renewed
  `refreshMinutesBefore` minutes before they expire.
- **Plain HTTPS:** it talks only to `oidc.<region>.amazonaws.com` and `portal.sso.<region>.amazonaws.com`.
  Those APIs are authenticated by bearer token, so no AWS SDK and no request signing are needed.
- **Your credentials file is safe:** only the profile sections SSOBar manages are touched. Comments and other
  profiles are preserved, and the file is not rewritten when nothing changed.
- **Deactivating a session** removes its profile section.

### Sleep, wake and browser tabs

Many credential helpers misbehave around sleep and wake (a stack of sign-in tabs in the morning, or dead
credentials until you click something). SSOBar is explicit about it:

| Situation | Behaviour |
| --- | --- |
| Mac wakes, SSO session still valid | Silent refresh as soon as the network is up. No browser. |
| Network is not up yet after wake | Keeps the refresh token and retries when the network comes back. |
| SSO session ended while you were away | **No tab while you're idle or the screen is locked.** One tab when you're back. |
| You ignore that tab | No more tabs until the next wake, unlock or explicit click. The icon shows ⚠. |
| Several triggers at once (timer, wake, unlock, clicks) | One shared sign-in: one device code, one tab. |
| Network drops during browser approval | Keeps polling the same code. No second tab. |
| You click Sign out | Stays signed out. Nothing reopens on its own. |
| Second copy of the app launched | Exits immediately (one writer, one login). |
| AWS throttles the refresh call | The refresh token is kept and the call is retried. |

## Security

- **Tokens:** SSO tokens and the OIDC client registration are stored in `~/.config/ssobar/state.json` with
  `0600` permissions. Role credentials go to the credentials file, also `0600`. This is the same exposure
  as `aws sso login` (which caches tokens in `~/.aws/sso/cache`) and as static credentials files in general.
- **What is logged:** nothing. Secrets are never logged or shown in the UI.
- **Reporting:** see [SECURITY.md](SECURITY.md) to report a vulnerability.

## Alternatives

- **AWS CLI v2 `sso-session` profiles** need no app at all, if every tool you use supports SSO profiles natively.
- **[granted](https://github.com/common-fate/granted)** and **[aws-sso-cli](https://github.com/synfinatic/aws-sso-cli)**
  are powerful CLI-first tools.
- **[Leapp](https://github.com/Noovolari/leapp)** is full-featured and supports many providers (Electron).

Choose SSOBar if you want the credentials file always valid and a menu bar toggle, and nothing else.

## Uninstall

Quit from the menu, then:

```sh
rm -rf ~/Applications/SSOBar.app /Applications/SSOBar.app ~/.config/ssobar
```

Profiles SSOBar wrote stay in `~/.aws/credentials` until they expire; delete them if you like.

## License

[MIT](LICENSE). Not affiliated with Amazon Web Services. "AWS" is a trademark of Amazon.com, Inc.
