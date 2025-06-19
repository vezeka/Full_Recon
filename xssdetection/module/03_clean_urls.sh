#!/bin/bash
# modules/03_clean_urls.sh - Version corrigée qui filtre vraiment
set -euo pipefail

# Validate
if [ -z "${REFLECTED_OUTPUT:-}" ] || [ ! -s "$REFLECTED_OUTPUT" ]; then
  echo "[ERROR] REFLECTED_OUTPUT missing or empty" >&2
  exit 1
fi

mkdir -p "$(dirname "$CLEANED_REFLECTED_URLS")"

echo "[INFO] Filtering URLs with reflection..."

# Extraire SEULEMENT les URLs qui ont reflection = true
grep '|true$' "$REFLECTED_OUTPUT" | cut -d'|' -f1 > "$CLEANED_REFLECTED_URLS" 2>/dev/null || touch "$CLEANED_REFLECTED_URLS"

# Statistiques
total_input=$(grep -v '^#' "$REFLECTED_OUTPUT" | wc -l || echo 0)
filtered_output=$(wc -l < "$CLEANED_REFLECTED_URLS" || echo 0)

echo "[INFO] Filtering complete:"
echo "[INFO] ├─ Input URLs: $total_input"
echo "[INFO] ├─ URLs with reflection: $filtered_output"
echo "[INFO] └─ Filtered: $((total_input - filtered_output)) URLs removed"

if [ "$filtered_output" -eq 0 ]; then
  echo "[WARN] No URLs with reflection found - check Module 02 results"
else
  echo "[INFO] URLs to test for XSS:"
  head -3 "$CLEANED_REFLECTED_URLS"
  [ "$filtered_output" -gt 3 ] && echo "... and $((filtered_output - 3)) more"
fi