# modules/01_extract_urls.sh
#!/usr/bin/env bash
set -euo pipefail

# Validate inputs
[[ -n "${INPUT_FILE:-}" && -f "$INPUT_FILE" ]] || { echo "[ERROR] INPUT_FILE missing or not found" >&2; exit 1; }
mkdir -p "$(dirname "$EXTRACTED_URLS")"

# Extract, normalize, dedupe
grep -oE 'https?://[[:alnum:].:/?&=%#_-]+' "$INPUT_FILE" \
  | sed 's/[[:punct:]]$//' \
  | sort -u > "$EXTRACTED_URLS"

echo "[INFO] Extracted $(wc -l < "$EXTRACTED_URLS") unique URLs to $EXTRACTED_URLS"
