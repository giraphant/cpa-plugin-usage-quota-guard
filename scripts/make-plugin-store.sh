#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-0.1.0}"
GOOS_VALUE="${GOOS_VALUE:-darwin}"
GOARCH_VALUE="${GOARCH_VALUE:-arm64}"
BASE_URL="${1:-${PLUGIN_STORE_BASE_URL:-http://127.0.0.1:8765}}"
BASE_URL="${BASE_URL%/}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist/plugin-store"
ARTIFACT_DIR="$DIST_DIR/artifacts"
EXT="so"
if [[ "$GOOS_VALUE" == "darwin" ]]; then
  EXT="dylib"
elif [[ "$GOOS_VALUE" == "windows" ]]; then
  EXT="dll"
fi

LIB_NAME="usage-quota-guard-v${VERSION}.${EXT}"
ZIP_NAME="usage-quota-guard-v${VERSION}-${GOOS_VALUE}-${GOARCH_VALUE}.zip"

mkdir -p "$ARTIFACT_DIR"
cd "$ROOT_DIR"

go test ./...
go build -buildmode=c-shared -o "$LIB_NAME" ./cmd/plugin
cp "$LIB_NAME" "$ARTIFACT_DIR/$LIB_NAME"
rm -f "$ARTIFACT_DIR/$ZIP_NAME"
(
  cd "$ARTIFACT_DIR"
  zip -q "$ZIP_NAME" "$LIB_NAME"
  rm -f "$LIB_NAME"
)
rm -f "$LIB_NAME" "usage-quota-guard-v${VERSION}.h"
SHA256="$(shasum -a 256 "$ARTIFACT_DIR/$ZIP_NAME" | awk '{print $1}')"
SIZE="$(wc -c < "$ARTIFACT_DIR/$ZIP_NAME" | tr -d ' ')"

cat > "$DIST_DIR/registry.json" <<JSON
{
  "schema_version": 2,
  "plugins": [
    {
      "id": "usage-quota-guard",
      "name": "Usage Quota Guard",
      "description": "Downstream API key usage quotas and scheduler-level route health guard for CLIProxyAPI.",
      "author": "giraphant",
      "version": "${VERSION}",
      "repository": "https://github.com/giraphant/cpa-plugin-usage-quota-guard",
      "homepage": "https://github.com/giraphant/cpa-plugin-usage-quota-guard",
      "license": "MIT",
      "tags": ["usage", "quota", "scheduler", "429", "codex"],
      "install": {
        "type": "direct",
        "artifacts": [
          {
            "goos": "${GOOS_VALUE}",
            "goarch": "${GOARCH_VALUE}",
            "url": "${BASE_URL}/artifacts/${ZIP_NAME}",
            "sha256": "${SHA256}",
            "size": ${SIZE}
          }
        ]
      }
    }
  ]
}
JSON

cat <<EOF
Wrote plugin store registry:
  $DIST_DIR/registry.json

Registry URL for local testing:
  ${BASE_URL}/registry.json

Artifact:
  $ARTIFACT_DIR/$ZIP_NAME
  sha256=$SHA256
  size=$SIZE
EOF
