# Contributing

Thanks for helping! SSOBar is deliberately small. It manages AWS IAM Identity Center credentials for the
shared credentials file, and nothing more. Please open an issue before starting on a larger feature, so we
can agree that it fits.

## Develop

```sh
./build.sh install   # build and run (needs only the Xcode Command Line Tools)
Tests/run.sh         # unit tests
```

- Everything is in `Sources/`: `main.swift` holds the app, SSO and refresh loop; `CredFile.swift` holds the INI editing.
- Keep it dependency-free and buildable with plain `swiftc`.
- Logic that can be pure should be pure and tested in `Tests/`.
- Never log or display secrets.
- Add a line to `CHANGELOG.md` under an `Unreleased` heading.

## Releasing (maintainers)

Bump `CFBundleShortVersionString` in `Info.plist`, update `CHANGELOG.md`, then
`git tag vX.Y.Z && git push --tags`. CI builds the universal app and attaches it to a GitHub release.
