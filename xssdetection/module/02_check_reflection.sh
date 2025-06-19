#!/bin/bash
# modules/02_check_reflection.sh - Version ultra-robuste
set -eo pipefail

# Validate
if [ -z "${EXTRACTED_URLS:-}" ] || [ ! -s "$EXTRACTED_URLS" ]; then
  echo "[ERROR] EXTRACTED_URLS missing or empty" >&2
  exit 1
fi

# Create output directory
mkdir -p "$(dirname "$REFLECTED_OUTPUT")"

# Configuration avec valeurs par défaut
THREADS="${THREADS:-5}"  # Réduire pour éviter les problèmes
USER_AGENT="${USER_AGENT:-Mozilla/5.0 (X11; Linux x86_64)}"
TIMEOUT="${TIMEOUT:-8}"  # Timeout plus court
LOG_LEVEL="${LOG_LEVEL:-INFO}"
MAX_PARALLEL="${MAX_PARALLEL:-3}"  # Limiter la parallélisation

# Fonction de logging simple
log_message() {
  local level="$1"
  local message="$2"
  local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  
  case "$LOG_LEVEL" in
    "ERROR") [ "$level" = "ERROR" ] || return ;;
    "WARN")  [ "$level" = "ERROR" ] || [ "$level" = "WARN" ] || return ;;
    "INFO")  [ "$level" = "ERROR" ] || [ "$level" = "WARN" ] || [ "$level" = "INFO" ] || return ;;
    "DEBUG") ;;
  esac
  
  echo "[$timestamp][$level] $message" >&2
}

# Test de réflexion simple et robuste
test_reflection() {
  local url="$1"
  local test_payloads="TEST123 XSS789"  # Payloads simples seulement
  local reflected=0
  local total=0
  
  for payload in $test_payloads; do
    total=$((total + 1))
    local test_url=""
    
    # Construction URL sécurisée
    if echo "$url" | grep -q '?'; then
      test_url="${url}&test=${payload}"
    else
      test_url="${url}?test=${payload}"
    fi
    
    # Test avec gestion d'erreur robuste
    local response=""
    local curl_exit=0
    
    # Utiliser timeout système + curl timeout
    if command -v timeout >/dev/null 2>&1; then
      response=$(timeout "$TIMEOUT" curl -s -m $((TIMEOUT-1)) -A "$USER_AGENT" --max-redirs 2 "$test_url" 2>/dev/null) || curl_exit=$?
    else
      response=$(curl -s -m "$TIMEOUT" -A "$USER_AGENT" --max-redirs 2 "$test_url" 2>/dev/null) || curl_exit=$?
    fi
    
    if [ $curl_exit -eq 0 ] && [ -n "$response" ]; then
      if echo "$response" | grep -qF "$payload"; then
        reflected=$((reflected + 1))
        log_message "DEBUG" "Reflection: $url + $payload = SUCCESS"
      fi
    else
      log_message "DEBUG" "Failed test: $url (exit: $curl_exit)"
    fi
    
    # Petite pause entre tests
    sleep 0.1
  done
  
  # Retourner le ratio
  if [ "$total" -gt 0 ]; then
    local ratio=$((reflected * 100 / total))
    echo "$reflected|$total|$ratio"
  else
    echo "0|0|0"
  fi
}

# Détection WAF basique et sûre
detect_waf_simple() {
  local url="$1"
  local waf_detected="NONE"
  
  # Headers seulement, pas de payload suspect
  local headers=""
  if headers=$(curl -s -I -m 3 -A "$USER_AGENT" "$url" 2>/dev/null); then
    local headers_lower=$(echo "$headers" | tr '[:upper:]' '[:lower:]')
    
    case "$headers_lower" in
      *cloudflare*|*cf-ray*) waf_detected="Cloudflare" ;;
      *incapsula*) waf_detected="Incapsula" ;;
      *akamai*) waf_detected="Akamai" ;;
      *aws*) waf_detected="AWS" ;;
      *modsecurity*) waf_detected="ModSecurity" ;;
    esac
  fi
  
  echo "$waf_detected"
}

# Traitement d'une URL (sans export de fonction)
process_single_url() {
  local url="$1"
  local temp_result="$2"
  
  log_message "DEBUG" "Testing: $url"
  
  # Test réflexion
  local reflection_result=$(test_reflection "$url")
  local reflected=$(echo "$reflection_result" | cut -d'|' -f1)
  local total=$(echo "$reflection_result" | cut -d'|' -f2)
  local ratio=$(echo "$reflection_result" | cut -d'|' -f3)
  
  # Test WAF
  local waf="NONE"
  if [ "${WAF_DETECTION:-true}" = "true" ]; then
    waf=$(detect_waf_simple "$url")
  fi
  
  # Décision
  local proceed="false"
  if [ "$reflected" -gt 0 ]; then
    proceed="true"
    log_message "INFO" "✅ Reflection: $url ($reflected/$total, $ratio%)"
  fi
  
  # Écrire résultat dans fichier temporaire
  echo "$url|$waf|$reflected|$total|$ratio|$proceed" >> "$temp_result"
}

# Traitement séquentiel robuste
process_sequential() {
  local input_file="$1"
  local temp_result="$2"
  local count=0
  local total=$(wc -l < "$input_file")
  
  while IFS= read -r url; do
    count=$((count + 1))
    
    # Affichage progression
    if [ $((count % 10)) -eq 0 ]; then
      log_message "INFO" "Progress: $count/$total URLs processed"
    fi
    
    # Traitement de l'URL
    process_single_url "$url" "$temp_result"
    
  done < "$input_file"
}

# Traitement par petits lots (plus sûr que xargs)
process_in_batches() {
  local input_file="$1"
  local temp_result="$2"
  local batch_size=5
  local temp_batch=$(mktemp)
  local batch_count=0
  
  # Diviser en lots
  split -l "$batch_size" "$input_file" "$temp_batch"_batch_
  
  # Traiter chaque lot
  for batch_file in "$temp_batch"_batch_*; do
    if [ -f "$batch_file" ]; then
      batch_count=$((batch_count + 1))
      log_message "DEBUG" "Processing batch $batch_count"
      
      # Traitement du lot en arrière-plan
      (
        while IFS= read -r url; do
          process_single_url "$url" "$temp_result"
        done < "$batch_file"
      ) &
      
      # Attendre si trop de processus
      local job_count=$(jobs -r | wc -l)
      while [ "$job_count" -ge "$MAX_PARALLEL" ]; do
        sleep 0.5
        job_count=$(jobs -r | wc -l)
      done
    fi
  done
  
  # Attendre tous les processus
  wait
  
  # Nettoyage
  rm -f "$temp_batch"_batch_*
}

# Main execution
log_message "INFO" "🔍 Starting reflection analysis (robust mode)..."
log_message "INFO" "├─ Input: $EXTRACTED_URLS"
log_message "INFO" "├─ Output: $REFLECTED_OUTPUT" 
log_message "INFO" "├─ Mode: Sequential/Batch processing"
log_message "INFO" "└─ URLs to test: $(wc -l < "$EXTRACTED_URLS")"

# Créer header
cat > "$REFLECTED_OUTPUT" << EOF
# Reflection Analysis Results - $(date)
# Format: URL|WAF|Reflected|Total|Ratio|Proceed
EOF

# Fichier temporaire pour résultats
temp_result=$(mktemp)

# Traitement selon la taille
url_count=$(wc -l < "$EXTRACTED_URLS")

if [ "$url_count" -le 20 ]; then
  log_message "INFO" "Using sequential processing (small dataset)"
  process_sequential "$EXTRACTED_URLS" "$temp_result"
elif [ "$url_count" -le 100 ]; then
  log_message "INFO" "Using batch processing (medium dataset)"
  process_in_batches "$EXTRACTED_URLS" "$temp_result"
else
  log_message "INFO" "Using sequential processing (large dataset, safer)"
  process_sequential "$EXTRACTED_URLS" "$temp_result"
fi

# Fusionner résultats
if [ -s "$temp_result" ]; then
  cat "$temp_result" >> "$REFLECTED_OUTPUT"
  
  # Créer fichier URLs filtrées
  filtered_urls=$(mktemp)
  grep '|true$' "$temp_result" | cut -d'|' -f1 > "$filtered_urls" || true
  
  if [ -s "$filtered_urls" ]; then
    mv "$filtered_urls" "${CLEANED_REFLECTED_URLS:-$PROJECT_ROOT/data/cleaned_reflected_urls.txt}"
  else
    touch "${CLEANED_REFLECTED_URLS:-$PROJECT_ROOT/data/cleaned_reflected_urls.txt}"
    rm -f "$filtered_urls"
  fi
else
  log_message "WARN" "No results generated"
  touch "${CLEANED_REFLECTED_URLS:-$PROJECT_ROOT/data/cleaned_reflected_urls.txt}"
fi

# Statistiques
total_urls=$(wc -l < "$EXTRACTED_URLS")
reflected_urls=$(grep '|true$' "$temp_result" 2>/dev/null | wc -l || echo 0)
waf_detected=$(grep -v '|NONE|' "$temp_result" 2>/dev/null | wc -l || echo 0)

log_message "INFO" "📊 Analysis complete:"
log_message "INFO" "├─ Total URLs: $total_urls"
log_message "INFO" "├─ Reflection found: $reflected_urls"
log_message "INFO" "├─ WAFs detected: $waf_detected"
log_message "INFO" "└─ Success rate: $([ "$total_urls" -gt 0 ] && echo $((reflected_urls * 100 / total_urls)) || echo 0)%"

# WAF report
if [ "$waf_detected" -gt 0 ] && [ -n "${WAF_REPORT:-}" ]; then
  mkdir -p "$(dirname "$WAF_REPORT")"
  grep -v '|NONE|' "$temp_result" | cut -d'|' -f1,2 > "$WAF_REPORT" 2>/dev/null || true
  log_message "INFO" "🛡️  WAF report: $WAF_REPORT"
fi

# Nettoyage
rm -f "$temp_result"

log_message "INFO" "✅ Reflection check completed successfully"