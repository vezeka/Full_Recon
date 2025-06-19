# ===============================================
# validate_env.sh — Validation améliorée
# ===============================================

#!/bin/bash
source ./config.sh 2>/dev/null || {
  echo "[!] config.sh introuvable. Exécutez d'abord run.sh"
  exit 1
}

echo "🔍 Validation de l'environnement XSS Scanner"
echo "============================================="

# Fichiers requis de base
required_files=(
  "$INPUT_FILE"
  "$PAYLOAD_FILE"
)

# Fichiers optionnels (créés pendant le scan)
optional_files=(
  "$EXTRACTED_URLS"
  "$REFLECTED_OUTPUT"
  "$CLEANED_REFLECTED_URLS"
  "$XSS_CANDIDATES"
)

# Dossiers requis
required_dirs=(
  "$(dirname "$XSS_CANDIDATES")"
  "$SCREENSHOT_DIR"
  "$SCREENSHOTS_DIR"
  "$CHECKPOINT_DIR"
  "$LOCK_DIR"
  "$CACHE_DIR"
)

echo ""
echo "📂 Fichiers requis :"
for file in "${required_files[@]}"; do
  if [[ -f "$file" ]]; then
    echo "  ✅ $file"
  else
    echo "  ❌ $file"
  fi
done

echo ""
echo "📂 Fichiers de résultats :"
for file in "${optional_files[@]}"; do
  if [[ -f "$file" ]]; then
    lines=$(wc -l < "$file" 2>/dev/null || echo "0")
    echo "  ✅ $file ($lines lignes)"
  else
    echo "  ⏳ $file (sera créé)"
  fi
done

echo ""
echo "📁 Dossiers :"
for dir in "${required_dirs[@]}"; do
  if [[ -d "$dir" ]]; then
    echo "  ✅ $dir"
  else
    echo "  ⏳ $dir (sera créé)"
  fi
done

echo ""
echo "⚙️ Configuration modules améliorés :"
echo "  - Détection WAF: $WAF_DETECTION"
echo "  - Seuil exécutabilité: $MIN_EXECUTABILITY_SCORE"
echo "  - Test POST: $TEST_POST"
echo "  - Test Headers: $TEST_HEADERS"
echo "  - Max screenshots: $MAX_SCREENSHOTS"
echo "  - Auto-resume: $AUTO_RESUME"
echo "  - Log level: $LOG_LEVEL"

echo ""
echo "🛠️ Outils système :"
tools=("curl" "grep" "sed" "jq" "google-chrome" "chromium" "firefox")
for tool in "${tools[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "  ✅ $tool"
  else
    case "$tool" in
      "jq") echo "  ⚠️  $tool (optionnel - améliore les performances)" ;;
      "google-chrome"|"chromium"|"firefox") echo "  ⚠️  $tool (optionnel - pour screenshots)" ;;
      *) echo "  ❌ $tool (requis)" ;;
    esac
  fi
done

echo ""
if [[ -f "$XSS_CANDIDATES" ]] && [[ -s "$XSS_CANDIDATES" ]]; then
  xss_count=$(grep -v '^#' "$XSS_CANDIDATES" | wc -l)
  echo "🎯 Résultats actuels : $xss_count candidats XSS trouvés"
else
  echo "🎯 Aucun résultat XSS pour le moment"
fi

echo ""
echo "✅ Validation terminée"