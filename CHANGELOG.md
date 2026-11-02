# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [SemVer](https://semver.org/).

## [1.0.0] - 2026-11-02

### Added
- Menu bar app: AWS IAM Identity Center roles mapped to `~/.aws/credentials` profiles, one active session per profile.
- Background refresh before expiry, on wake, on unlock and on network change.
- Silent SSO token renewal with a refresh token. Device-code browser sign-in only when the session has ended,
  at most one tab, and only while the user is present.
- Discover roles from SSO, Edit config (hot reload), Launch at login.
- `scripts/import-leapp.sh` to migrate AWS SSO sessions from Leapp.

[1.0.0]: https://github.com/dkhalizov/ssobar/releases/tag/v1.0.0
