#!/bin/sh
# ./build.sh          -> build/SSOBar.app
# ./build.sh install  -> also install to ~/Applications and (re)start it
set -e
cd "$(dirname "$0")"
APP=build/SSOBar.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
swiftc -O -swift-version 5 -target "$(uname -m)-apple-macos14" Sources/main.swift -o "$APP/Contents/MacOS/SSOBar"
cp Info.plist "$APP/Contents/"
codesign --force --sign - "$APP"
echo "built $APP"
if [ "$1" = install ]; then
  pkill -x SSOBar 2>/dev/null || true
  mkdir -p ~/Applications
  rm -rf ~/Applications/SSOBar.app
  cp -R "$APP" ~/Applications/
  open ~/Applications/SSOBar.app
  echo "installed ~/Applications/SSOBar.app"
fi
