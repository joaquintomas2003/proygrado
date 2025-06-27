#!/bin/zsh
set -e

PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins"
SRC_FILE="dissectors/int_md.lua"
DEST_FILE="$PLUGIN_DIR/int_md.lua"

echo "Borrando dissector antiguo"
rm -f "$DEST_FILE"

echo "Copiando nueva versión desde $SRC_FILE..."
cp "$SRC_FILE" "$DEST_FILE"
