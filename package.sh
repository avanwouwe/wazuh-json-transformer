#!/bin/bash

set -eu

PACKAGE_ID="wazuh-json-transformer"
BINARY_NAME="wazuh-json-transformer"
VERSION="1.0.0"
BUILD_ROOT="/tmp/wazuh-json-transformer-$(uuidgen)"
OUTPUT_PKG="$BINARY_NAME-$VERSION.pkg"

if [ ! -d "binaries/arm64" ] || [ ! -d "binaries/x86_64" ]; then
    echo "Error: Missing one or both architecture builds."
    exit 1
fi

mkdir -p "$BUILD_ROOT/root/usr/local/bin"
mkdir -p "$BUILD_ROOT/scripts"

# Install both architecture binaries, postinstall selects the right one
cp "binaries/arm64/$BINARY_NAME"  "$BUILD_ROOT/root/usr/local/bin/${BINARY_NAME}-arm64"
cp "binaries/x86_64/$BINARY_NAME" "$BUILD_ROOT/root/usr/local/bin/${BINARY_NAME}-x86_64"

cp postinstall "$BUILD_ROOT/scripts/"
chmod 755 "$BUILD_ROOT/scripts/postinstall"

pkgbuild --root "$BUILD_ROOT/root" \
         --identifier "$PACKAGE_ID" \
         --version "$VERSION" \
         --scripts "$BUILD_ROOT/scripts" \
         --install-location "/" \
         "$OUTPUT_PKG"

rm -rf "$BUILD_ROOT"

echo "Package created: $OUTPUT_PKG"