#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="ThreatDrivenDaC"
SRC_FILE="$ROOT_DIR/macos/ThreatDrivenDaC/Sources/ThreatDrivenDaCApp.swift"
DIST_DIR="$ROOT_DIR/dist"
APP_DIR="$DIST_DIR/$APP_NAME.app"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"

if ! command -v swiftc >/dev/null 2>&1; then
  echo "swiftc was not found. Install Xcode or Xcode Command Line Tools." >&2
  exit 1
fi

if [[ ! -f "$SRC_FILE" ]]; then
  echo "SwiftUI source file not found: $SRC_FILE" >&2
  exit 1
fi

mkdir -p "$MACOS_DIR"

swiftc "$SRC_FILE" \
  -parse-as-library \
  -framework SwiftUI \
  -framework AppKit \
  -o "$MACOS_DIR/$APP_NAME"

cat > "$CONTENTS_DIR/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>ThreatDrivenDaC</string>
  <key>CFBundleIdentifier</key>
  <string>com.local.ThreatDrivenDaC</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>ThreatDrivenDaC</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
PLIST

chmod +x "$MACOS_DIR/$APP_NAME"

echo "Built unsigned app: $APP_DIR"
echo "Open it with: open \"$APP_DIR\""
