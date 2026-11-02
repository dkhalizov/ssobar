#!/bin/sh
# Build SSOBar.app with plain swiftc (no Xcode project needed).
#
#   ./build.sh                 build for this Mac        -> build/SSOBar.app
#   ./build.sh install         build, copy to ~/Applications, (re)start
#   UNIVERSAL=1 ./build.sh     arm64 + x86_64 universal binary (used for releases)
set -eu
cd "$(dirname "$0")"

APP=build/SSOBar.app
BIN="$APP/Contents/MacOS/SSOBar"
MIN_MACOS=14.0
FLAGS="-O -swift-version 5 -module-name SSOBar"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"

if [ "${UNIVERSAL:-0}" = 1 ]; then
  for arch in arm64 x86_64; do
    swiftc $FLAGS -target "$arch-apple-macos$MIN_MACOS" Sources/*.swift -o "build/SSOBar-$arch"
  done
  lipo -create build/SSOBar-arm64 build/SSOBar-x86_64 -output "$BIN"
  rm build/SSOBar-arm64 build/SSOBar-x86_64
else
  swiftc $FLAGS -target "$(uname -m)-apple-macos$MIN_MACOS" Sources/*.swift -o "$BIN"
fi

cp Info.plist "$APP/Contents/"
codesign --force --sign - "$APP"   # ad-hoc signature (required on Apple Silicon)
echo "built $APP ($(lipo -archs "$BIN"))"

if [ "${1:-}" = install ]; then
  pkill -x SSOBar 2>/dev/null && sleep 1 || true
  mkdir -p ~/Applications
  rm -rf ~/Applications/SSOBar.app
  cp -R "$APP" ~/Applications/
  open ~/Applications/SSOBar.app
  echo "installed ~/Applications/SSOBar.app"
fi
