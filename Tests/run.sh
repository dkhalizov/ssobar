#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p build
swiftc -swift-version 5 -module-name SSOBarTests Sources/CredFile.swift Tests/main.swift -o build/credfile-tests
./build/credfile-tests
