#!/usr/bin/env bash
# modules/04_inject_payloads.sh - Version améliorée (Étape 1)
# Auto-reexec in bash if not already running in bash
if [ -z "$BASH_VERSION" ]; then
  exec bash "$0" "$@"
fi
set -euo pipefail

# Resolve project root
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configurable paths and enhanced options
CLEANED_REFLECTED_URLS="${CLEANED_REFLECTED_URLS:-$PROJECT_ROOT/data/cleaned_reflected_urls.txt}"
PAYLOAD_FILE="${PAYLOAD_FILE:-$PROJECT_ROOT/payloads.txt}"
XSS_CANDIDATES="${XSS_CANDIDATES:-$PROJECT_ROOT/data/xss_candidates.txt}"
THREADS="${THREADS:-10}"
USER_AGENT="${USER_AGENT:-Mozilla/5.0 (X11; Linux x86_64)}"
RATE_LIMIT="${RATE_LIMIT:-10}"
CACHE_DIR="${CACHE_DIR:-$PROJECT_ROOT/data/cache}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
MAX_RETRIES="${MAX_RETRIES:-3}"
TIMEOUT="${TIMEOUT:-15}"
TEST_POST="${TEST_POST:-false}"
TEST_HEADERS="${TEST_HEADERS:-false}"
CUSTOM_HEADERS="${CUSTOM_HEADERS:-}"
MIN_EXECUTABILITY_SCORE="${MIN_EXECUTABILITY_SCORE:-40}"  # Seuil minimum pour considérer comme XSS valide

# Validate inputs
[ -s "$CLEANED_REFLECTED_URLS" ] || { echo "[ERROR] Missing or empty: $CLEANED_REFLECTED_URLS" >&2; exit 1; }
[ -s "$PAYLOAD_FILE" ]           || { echo "[ERROR] Missing or empty: $PAYLOAD_FILE" >&2; exit 1; }

mkdir -p "$(dirname "$XSS_CANDIDATES")" "$CACHE_DIR"
> "$XSS_CANDIDATES"

# WAF and Filter Detection
detect_waf() {
  local resp_headers="$1"
  local resp_body="$2" 
  local http_code="$3"
  local waf_detected=""
  
  # Header-based WAF detection
  case "$resp_headers" in
    *"cloudflare"*|*"cf-ray"*|*"__cfruid"*) waf_detected="Cloudflare" ;;
    *"x-sucuri-id"*|*"sucuri"*) waf_detected="Sucuri" ;;
    *"x-protected-by"*) waf_detected="$(echo "$resp_headers" | grep -i "x-protected-by" | cut -d: -f2 | tr -d ' ')" ;;
    *"server: aws"*|*"x-amzn-"*) waf_detected="AWS-WAF" ;;
    *"x-akamai-"*) waf_detected="Akamai" ;;
    *"barracuda"*) waf_detected="Barracuda" ;;
    *"binarysec"*) waf_detected="BinarySec" ;;
    *"blockdos"*) waf_detected="BlockDoS" ;;
    *"citrix"*) waf_detected="Citrix-NetScaler" ;;
    *"f5-bigip"*|*"bigip"*) waf_detected="F5-BigIP" ;;
    *"fortinet"*|*"fortigate"*) waf_detected="Fortinet" ;;
    *"incapsula"*|*"incap_ses"*) waf_detected="Incapsula" ;;
    *"mod_security"*|*"modsecurity"*) waf_detected="ModSecurity" ;;
    *"naxsi"*) waf_detected="Naxsi" ;;
    *"netscaler"*) waf_detected="NetScaler" ;;
    *"newdefend"*) waf_detected="NewDefend" ;;
    *"safe3"*) waf_detected="Safe3" ;;
    *"safedog"*) waf_detected="SafeDog" ;;
    *"secureiis"*) waf_detected="SecureIIS" ;;
    *"sophos"*) waf_detected="Sophos" ;;
    *"stingray"*) waf_detected="Stingray" ;;
    *"tencent"*) waf_detected="Tencent" ;;
    *"wallarm"*) waf_detected="Wallarm" ;;
    *"webknight"*) waf_detected="WebKnight" ;;
    *"wordfence"*) waf_detected="Wordfence" ;;
  esac
  
  # HTTP code-based detection
  case "$http_code" in
    403|406|409|418|429|501|503) 
      if [ -z "$waf_detected" ]; then
        waf_detected="Generic-WAF($http_code)"
      fi
      ;;
  esac
  
  # Body-based WAF detection (common error messages)
  if [ -z "$waf_detected" ]; then
    case "$resp_body" in
      *"blocked by security policy"*|*"security violation"*|*"access denied"*) 
        waf_detected="Generic-WAF(Policy)" ;;
      *"malicious"*|*"suspicious"*|*"threat"*) 
        waf_detected="Generic-WAF(Threat)" ;;
      *"cloudflare"*) waf_detected="Cloudflare" ;;
      *"incapsula"*) waf_detected="Incapsula" ;;
      *"mod_security"*|*"modsecurity"*) waf_detected="ModSecurity" ;;
      *"denied by"*|*"blocked by"*) waf_detected="Generic-WAF(Block)" ;;
    esac
  fi
  
  echo "${waf_detected:-NONE}"
}

# Filter Detection and Analysis
detect_filters() {
  local original_payload="$1"
  local reflected_payload="$2"
  local filters=""
  
  # Character-level filtering detection
  local special_chars="<>\"'(){}[];,&|*+="
  local removed_chars=""
  local escaped_chars=""
  
  for ((i=0; i<${#special_chars}; i++)); do
    char="${special_chars:$i:1}"
    if printf '%s' "$original_payload" | grep -qF -- "$char"; then
      if ! printf '%s' "$reflected_payload" | grep -qF -- "$char"; then
        removed_chars="$removed_chars$char"
      fi
    fi
  done
  
  # Encoding detection
  if printf '%s' "$reflected_payload" | grep -qF "&lt;"; then
    escaped_chars="${escaped_chars}HTML-encoded,"
  fi
  if printf '%s' "$reflected_payload" | grep -qF "%3C"; then
    escaped_chars="${escaped_chars}URL-encoded,"
  fi
  if printf '%s' "$reflected_payload" | grep -qF "\\x"; then
    escaped_chars="${escaped_chars}Hex-encoded,"
  fi
  
  # Length-based filtering
  local orig_len=${#original_payload}
  local refl_len=${#reflected_payload}
  local length_diff=$((orig_len - refl_len))
  
  # Build filter summary
  [ -n "$removed_chars" ] && filters="${filters}REMOVED:[$removed_chars];"
  [ -n "$escaped_chars" ] && filters="${filters}ENCODED:[$escaped_chars];"
  [ $length_diff -gt 0 ] && filters="${filters}TRUNCATED:[-${length_diff}chars];"
  [ $length_diff -lt 0 ] && filters="${filters}EXPANDED:[+${length_diff#-}chars];"
  
  # Pattern-based filtering detection
  if [ "$orig_len" -gt 0 ] && [ "$refl_len" -eq 0 ]; then
    filters="${filters}COMPLETELY_FILTERED;"
  elif printf '%s' "$reflected_payload" | grep -qE '\*+|X+|\?+'; then
    filters="${filters}MASKED;"
  fi
  
  echo "${filters:-NONE}"
}

# Enhanced logging function with levels
log_message() {
  local level="$1"
  local message="$2"
  local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  
  # Log level filtering
  case "$LOG_LEVEL" in
    "ERROR") [[ "$level" =~ ^(ERROR)$ ]] || return ;;
    "WARN")  [[ "$level" =~ ^(ERROR|WARN)$ ]] || return ;;
    "INFO")  [[ "$level" =~ ^(ERROR|WARN|INFO)$ ]] || return ;;
    "DEBUG") [[ "$level" =~ ^(ERROR|WARN|INFO|DEBUG)$ ]] || return ;;
  esac
  
  # Color coding for different levels
  local color=""
  case "$level" in
    "ERROR") color="\033[31m" ;;  # Red
    "WARN")  color="\033[33m" ;;  # Yellow
    "INFO")  color="\033[32m" ;;  # Green
    "DEBUG") color="\033[36m" ;;  # Cyan
  esac
  
  printf "${color}[$timestamp][$level]\033[0m %s\n" "$message" >&2
}

# Enhanced security headers analysis
analyze_security_headers() {
  local headers="$1"
  local analysis=""
  
  # CSP Analysis
  if printf '%s' "$headers" | grep -qi "content-security-policy"; then
    local csp=$(printf '%s' "$headers" | grep -i "content-security-policy" | cut -d: -f2-)
    if printf '%s' "$csp" | grep -qi "unsafe-inline"; then
      analysis="${analysis}CSP:WEAK(unsafe-inline);"
    elif printf '%s' "$csp" | grep -qi "script-src.*'self'"; then
      analysis="${analysis}CSP:MEDIUM(self-only);"
    else
      analysis="${analysis}CSP:STRONG;"
    fi
  else
    analysis="${analysis}CSP:NONE;"
  fi
  
  # X-XSS-Protection Analysis
  if printf '%s' "$headers" | grep -qi "x-xss-protection.*1.*mode=block"; then
    analysis="${analysis}XSS-PROT:BLOCK;"
  elif printf '%s' "$headers" | grep -qi "x-xss-protection.*1"; then
    analysis="${analysis}XSS-PROT:FILTER;"
  elif printf '%s' "$headers" | grep -qi "x-xss-protection.*0"; then
    analysis="${analysis}XSS-PROT:DISABLED;"
  else
    analysis="${analysis}XSS-PROT:NONE;"
  fi
  
  # X-Frame-Options Analysis
  if printf '%s' "$headers" | grep -qi "x-frame-options.*deny"; then
    analysis="${analysis}FRAME:DENY;"
  elif printf '%s' "$headers" | grep -qi "x-frame-options.*sameorigin"; then
    analysis="${analysis}FRAME:SAMEORIGIN;"
  else
    analysis="${analysis}FRAME:ALLOW;"
  fi
  
  # X-Content-Type-Options
  if printf '%s' "$headers" | grep -qi "x-content-type-options.*nosniff"; then
    analysis="${analysis}SNIFF:PROTECTED;"
  else
    analysis="${analysis}SNIFF:VULNERABLE;"
  fi
  
  echo "${analysis%?}"  # Remove trailing semicolon
}

# Advanced payload injection methods
inject_payload_advanced() {
  local base_url="$1"
  local query="$2"
  local payload="$3"
  local method="${4:-GET}"
  local urls=()
  
  IFS='&' read -ra params <<< "$query"
  
  case "$method" in
    "GET")
      # Method 1: Replace existing parameter values
      for i in "${!params[@]}"; do
        local param="${params[i]%%=*}"
        local new_params=("${params[@]}")
        new_params[i]="$param=$payload"
        urls+=("$base_url?$(IFS=\&; echo "${new_params[*]}")")
      done
      
      # Method 2: Add payload as new parameter
      urls+=("$base_url?$query&xss_test=$payload")
      
      # Method 3: Inject in multiple parameters
      if [ ${#params[@]} -gt 1 ]; then
        local multi_params=()
        for param_pair in "${params[@]}"; do
          local param="${param_pair%%=*}"
          multi_params+=("$param=$payload")
        done
        urls+=("$base_url?$(IFS=\&; echo "${multi_params[*]}")")
      fi
      ;;
      
    "POST")
      # POST method implementation
      local post_data=""
      for i in "${!params[@]}"; do
        local param="${params[i]%%=*}"
        local new_params=("${params[@]}")
        new_params[i]="$param=$payload"
        post_data="$(IFS=\&; echo "${new_params[*]}")"
        urls+=("POST:$base_url:$post_data")
      done
      ;;
  esac
  
  printf '%s\n' "${urls[@]}"
}

# Enhanced HTTP request function
make_request() {
  local method="$1"
  local url="$2"
  local data="$3"
  local custom_headers="$4"
  
  local curl_opts=(
    -s
    -A "$USER_AGENT"
    --compressed
    --max-time "$TIMEOUT"
    --retry "$MAX_RETRIES"
    --retry-delay 1
    -w "HTTPCODE:%{http_code}|SIZE:%{size_download}|TIME:%{time_total}"
  )
  
  # Add custom headers if specified
  if [ -n "$custom_headers" ]; then
    IFS=',' read -ra headers <<< "$custom_headers"
    for header in "${headers[@]}"; do
      curl_opts+=(-H "$header")
    done
  fi
  
  case "$method" in
    "GET")
      curl "${curl_opts[@]}" "$url"
      ;;
    "POST")
      curl "${curl_opts[@]}" -X POST -d "$data" "$url"
      ;;
    "PUT")
      curl "${curl_opts[@]}" -X PUT -d "$data" "$url"
      ;;
    "PATCH")
      curl "${curl_opts[@]}" -X PATCH -d "$data" "$url"
      ;;
  esac
}

# Header injection testing
test_header_injection() {
  local url="$1"
  local payload="$2"
  local results=()
  
  # Test common injectable headers
  local headers=(
    "X-Forwarded-For: $payload"
    "X-Real-IP: $payload"
    "X-Originating-IP: $payload"
    "X-Remote-IP: $payload"
    "X-Client-IP: $payload"
    "User-Agent: $payload"
    "Referer: $payload"
    "X-Custom: $payload"
  )
  
  for header in "${headers[@]}"; do
    local resp=$(make_request "GET" "$url" "" "$header")
    local body="${resp%HTTPCODE:*}"
    local metadata="${resp##*HTTPCODE:}"
    
    if printf '%s' "$body" | grep -qF -- "$payload"; then
      results+=("HEADER:${header%%:*}")
    fi
  done
  
  printf '%s\n' "${results[@]}"
}

# Caching functions
is_cached() {
  local url="$1"
  local f="$CACHE_DIR/$(echo "$url" | md5sum | cut -d' ' -f1)"
  [ -f "$f" ]
}

cache_url() {
  local url="$1"
  touch "$CACHE_DIR/$(echo "$url" | md5sum | cut -d' ' -f1)"
}

# Enhanced context analysis function
analyze_context() {
  local resp="$1" 
  local payload="$2"
  local context_info=""
  local encoded_variants=""
  
  # Escape special regex characters in payload for grep
  local escaped_payload=$(printf '%s\n' "$payload" | sed 's/[[\.*^$()+?{|\\]/\\&/g')
  
  # Check for various encodings of the payload
  local url_encoded=$(printf '%s' "$payload" | xxd -p | sed 's/../%&/g')
  local html_encoded=$(printf '%s' "$payload" | sed 's/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&#39;/g')
  
  # Context detection with safe literal string matching
  if printf '%s' "$resp" | grep -qF -- "$payload"; then
    # Use literal search with -- to prevent option interpretation
    if printf '%s' "$resp" | grep -q "<script[^>]*>" && printf '%s' "$resp" | grep -qF -- "$payload" && printf '%s' "$resp" | grep -q "</script>"; then
      # Inside JavaScript context
      if printf '%s' "$resp" | grep -qE "var\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[\"'].*[\"']" && printf '%s' "$resp" | grep -qF -- "$payload"; then
        context_info="JS_STRING_VAR"
      elif printf '%s' "$resp" | grep -qE "console\.(log|error|warn|info)" && printf '%s' "$resp" | grep -qF -- "$payload"; then
        context_info="JS_CONSOLE"
      elif printf '%s' "$resp" | grep -qE "(alert|confirm|prompt)" && printf '%s' "$resp" | grep -qF -- "$payload"; then
        context_info="JS_DIALOG"
      else
        context_info="JAVASCRIPT"
      fi
    elif printf '%s' "$resp" | grep -q "<style[^>]*>" && printf '%s' "$resp" | grep -qF -- "$payload" && printf '%s' "$resp" | grep -q "</style>"; then
      context_info="CSS_STYLE"
    elif printf '%s' "$resp" | grep -q "<!--" && printf '%s' "$resp" | grep -qF -- "$payload" && printf '%s' "$resp" | grep -q "-->"; then
      context_info="HTML_COMMENT"
    elif printf '%s' "$resp" | grep -qE "<[a-zA-Z][^>]*>" && printf '%s' "$resp" | grep -qF -- "$payload"; then
      # Check if inside HTML tag attributes
      if printf '%s' "$resp" | grep -qE "\son[a-zA-Z]+=[\"\']" && printf '%s' "$resp" | grep -qF -- "$payload"; then
        context_info="EVENT_HANDLER"
      elif printf '%s' "$resp" | grep -qE "\shref=[\"\']" && printf '%s' "$resp" | grep -qF -- "$payload"; then
        context_info="HREF_ATTRIBUTE"
      elif printf '%s' "$resp" | grep -qE "\ssrc=[\"\']" && printf '%s' "$resp" | grep -qF -- "$payload"; then
        context_info="SRC_ATTRIBUTE"
      elif printf '%s' "$resp" | grep -qE "=[\"'][^\"']*" && printf '%s' "$resp" | grep -qF -- "$payload"; then
        context_info="HTML_ATTRIBUTE"
      else
        context_info="HTML_TAG"
      fi
    elif printf '%s' "$resp" | grep -qE ">[^<]*" && printf '%s' "$resp" | grep -qF -- "$payload"; then
      context_info="HTML_TEXT"
    else
      context_info="HTML_CONTENT"
    fi
    
  else
    # Check for encoded versions
    if printf '%s' "$resp" | grep -qF -- "$html_encoded"; then
      context_info="HTML_ENCODED"
      encoded_variants="$html_encoded"
    elif printf '%s' "$resp" | grep -qF -- "$url_encoded"; then
      context_info="URL_ENCODED"
      encoded_variants="$url_encoded"
    else
      context_info="NOT_REFLECTED"
    fi
  fi
  
  # Additional context analysis - safe character checking
  local filter_detected=""
  local original_chars="<>\"'();&"
  local found_chars=""
  
  # Use literal string search to avoid regex issues
  for ((i=0; i<${#original_chars}; i++)); do
    char="${original_chars:$i:1}"
    if printf '%s' "$payload" | grep -qF -- "$char" && printf '%s' "$resp" | grep -qF -- "$char"; then
      found_chars="$found_chars$char"
    fi
  done
  
  if [ ${#found_chars} -lt ${#original_chars} ]; then
    filter_detected="FILTERED:missing($original_chars vs $found_chars)"
  fi
  
  # Return comprehensive context information
  echo "$context_info${encoded_variants:+|ENCODED:$encoded_variants}${filter_detected:+|$filter_detected}"
}

# Enhanced reflection detection with validation
detect_reflection_quality() {
  local resp="$1"
  local payload="$2"
  local quality="NONE"
  
  # Check exact reflection using safe method
  if printf '%s' "$resp" | grep -qF -- "$payload"; then
    quality="EXACT"
  else
    # Check partial reflection
    local payload_length=${#payload}
    local min_length=$((payload_length / 2))
    
    # Try to find largest reflected substring
    for ((len=payload_length-1; len>=min_length; len--)); do
      for ((start=0; start<=payload_length-len; start++)); do
        local substr="${payload:$start:$len}"
        if [ ${#substr} -ge 3 ] && printf '%s' "$resp" | grep -qF -- "$substr"; then
          quality="PARTIAL:$substr"
          break 2
        fi
      done
    done
  fi
  
  echo "$quality"
}

# Advanced XSS executability validation
validate_xss_executability() {
  local resp_body="$1"
  local payload="$2"
  local context="$3"
  local filters="$4"
  local security_headers="$5"
  local executability_score=0
  local validation_notes=""
  
  # Context-based executability check
  case "$context" in
    *"JAVASCRIPT"*|*"JS_"*)
      # JavaScript context - high chance of execution
      if [[ "$filters" == "NONE" ]]; then
        executability_score=90
        validation_notes="JS_CONTEXT:UNFILTERED"
      elif [[ "$filters" != *"REMOVED"* ]]; then
        executability_score=70
        validation_notes="JS_CONTEXT:ENCODED_ONLY"
      else
        executability_score=20
        validation_notes="JS_CONTEXT:FILTERED"
      fi
      ;;
      
    *"EVENT_HANDLER"*)
      # Event handler - very high execution probability
      if [[ "$filters" == "NONE" ]]; then
        executability_score=95
        validation_notes="EVENT_HANDLER:UNFILTERED"
      else
        executability_score=30
        validation_notes="EVENT_HANDLER:FILTERED"
      fi
      ;;
      
    *"HTML_TEXT"*)
      # HTML text context - needs script tags
      if printf '%s' "$payload" | grep -qE -- '<script|<img.*onerror|<svg.*onload'; then
        if [[ "$filters" == "NONE" ]]; then
          executability_score=85
          validation_notes="HTML_TEXT:SCRIPT_TAG"
        elif [[ "$filters" != *"REMOVED:.*<"* ]]; then
          executability_score=60
          validation_notes="HTML_TEXT:PARTIAL_FILTER"
        else
          executability_score=10
          validation_notes="HTML_TEXT:TAG_BLOCKED"
        fi
      else
        executability_score=5
        validation_notes="HTML_TEXT:NO_EXECUTABLE_TAG"
      fi
      ;;
      
    *"HTML_ATTRIBUTE"*|*"HREF_ATTRIBUTE"*|*"SRC_ATTRIBUTE"*)
      # Attribute context - depends on attribute type and payload
      if printf '%s' "$payload" | grep -qE -- 'javascript:|data:|vbscript:'; then
        executability_score=75
        validation_notes="ATTRIBUTE:PROTOCOL_HANDLER"
      elif printf '%s' "$payload" | grep -qE -- '".*onload=|".*onerror=|".*onclick='; then
        executability_score=80
        validation_notes="ATTRIBUTE:BREAK_OUT_EVENT"
      else
        executability_score=15
        validation_notes="ATTRIBUTE:NO_BREAKOUT"
      fi
      ;;
      
    *"HTML_COMMENT"*)
      # HTML comment - very low execution chance
      if printf '%s' "$payload" | grep -qE -- '--><script|--><img'; then
        executability_score=40
        validation_notes="COMMENT:BREAKOUT_ATTEMPT"
      else
        executability_score=5
        validation_notes="COMMENT:TRAPPED"
      fi
      ;;
      
    *"CSS_STYLE"*)
      # CSS context - limited execution vectors
      if printf '%s' "$payload" | grep -qE -- 'expression\(|javascript:|url\(data:'; then
        executability_score=50
        validation_notes="CSS:EXECUTION_VECTOR"
      else
        executability_score=10
        validation_notes="CSS:LIMITED_VECTOR"
      fi
      ;;
      
    *)
      # Unknown or encoded context
      executability_score=5
      validation_notes="UNKNOWN_CONTEXT"
      ;;
  esac
  
  # Security headers penalty
  case "$security_headers" in
    *"CSP:STRONG"*)
      executability_score=$((executability_score - 30))
      validation_notes="$validation_notes;CSP_BLOCKS"
      ;;
    *"CSP:MEDIUM"*)
      executability_score=$((executability_score - 15))
      validation_notes="$validation_notes;CSP_LIMITS"
      ;;
    *"XSS-PROT:BLOCK"*)
      executability_score=$((executability_score - 20))
      validation_notes="$validation_notes;XSS_FILTER_BLOCKS"
      ;;
  esac
  
  # Filter analysis penalty
  case "$filters" in
    *"COMPLETELY_FILTERED"*)
      executability_score=0
      validation_notes="$validation_notes;COMPLETELY_BLOCKED"
      ;;
    *"REMOVED:.*<>.*"*)
      executability_score=$((executability_score - 40))
      validation_notes="$validation_notes;TAGS_STRIPPED"
      ;;
    *"REMOVED:.*().*"*)
      executability_score=$((executability_score - 25))
      validation_notes="$validation_notes;FUNCTIONS_BLOCKED"
      ;;
  esac
  
  # Minimum threshold
  [ $executability_score -lt 0 ] && executability_score=0
  
  # Advanced payload analysis - SAFE VERSION
  local payload_quality=0
  if printf '%s' "$payload" | grep -qE -- '<script>.*</script>'; then
    payload_quality=30
  elif printf '%s' "$payload" | grep -qE -- '<img.*onerror.*>|<svg.*onload.*>'; then
    payload_quality=25
  elif printf '%s' "$payload" | grep -qE -- 'javascript:|on[a-z]+='; then
    payload_quality=20
  elif printf '%s' "$payload" | grep -qE -- 'alert\(|prompt\(|confirm\('; then
    payload_quality=15
  else
    payload_quality=5
  fi
  
  executability_score=$((executability_score + payload_quality))
  
  # Return score and validation notes
  echo "$executability_score|$validation_notes"
}

# Enhanced DOM-based XSS detection
detect_dom_xss() {
  local resp_body="$1"
  local payload="$2"
  local dom_vectors=""
  
  # Check for client-side JavaScript that handles user input
  if printf '%s' "$resp_body" | grep -qE -- 'document\.location|window\.location|location\.hash|location\.search'; then
    dom_vectors="${dom_vectors}LOCATION_BASED;"
  fi
  
  if printf '%s' "$resp_body" | grep -qE -- 'innerHTML|outerHTML|document\.write|eval\('; then
    dom_vectors="${dom_vectors}DOM_MANIPULATION;"
  fi
  
  if printf '%s' "$resp_body" | grep -qE -- 'postMessage|addEventListener.*message'; then
    dom_vectors="${dom_vectors}POSTMESSAGE;"
  fi
  
  if printf '%s' "$resp_body" | grep -qE -- 'localStorage|sessionStorage|history\.'; then
    dom_vectors="${dom_vectors}STORAGE_BASED;"
  fi
  
  echo "${dom_vectors:-NONE}"
}

# False positive filtering
is_false_positive() {
  local url="$1"
  local payload="$2"
  local resp_body="$3"
  local context="$4"
  
  # Common false positive patterns
  
  # 1. Payload in hidden fields or disabled inputs
  if printf '%s' "$resp_body" | grep -qE -- '<input[^>]*type="hidden"[^>]*value="[^"]*'"$(printf '%s' "$payload" | sed 's/[[\.*^$()+?{|\\]/\\&/g')"'[^"]*"'; then
    return 0  # False positive
  fi
  
  # 2. Payload in comments or meta tags (non-executable)
  if printf '%s' "$resp_body" | grep -qE -- '<!--[^>]*'"$(printf '%s' "$payload" | sed 's/[[\.*^$()+?{|\\]/\\&/g')"'[^>]*-->'; then
    return 0  # False positive
  fi
  
  # 3. Payload in JSON data (unless in dangerous context)
  if printf '%s' "$resp_body" | grep -qE -- '"[^"]*'"$(printf '%s' "$payload" | sed 's/[[\.*^$()+?{|\\]/\\&/g')"'[^"]*"' && [[ "$context" != *"JAVASCRIPT"* ]]; then
    return 0  # Likely false positive
  fi
  
  # 4. Payload completely URL-encoded or double-encoded
  if ! printf '%s' "$resp_body" | grep -qF -- "$payload" && printf '%s' "$resp_body" | grep -qF -- "$(printf '%s' "$payload" | xxd -p | sed 's/../%&/g')"; then
    return 0  # False positive (completely encoded)
  fi
  
  # 5. Error pages or debug information
  if printf '%s' "$resp_body" | grep -qiE -- 'error|exception|debug|stack trace|line [0-9]+'; then
    return 0  # Likely false positive
  fi
  
  return 1  # Not a false positive
}

# Enhanced DOM-based XSS detection
detect_dom_xss() {
  local resp_body="$1"
  local payload="$2"
  local dom_vectors=""
  
  # Check for client-side JavaScript that handles user input
  if printf '%s' "$resp_body" | grep -qE 'document\.location|window\.location|location\.hash|location\.search'; then
    dom_vectors="${dom_vectors}LOCATION_BASED;"
  fi
  
  if printf '%s' "$resp_body" | grep -qE 'innerHTML|outerHTML|document\.write|eval\('; then
    dom_vectors="${dom_vectors}DOM_MANIPULATION;"
  fi
  
  if printf '%s' "$resp_body" | grep -qE 'postMessage|addEventListener.*message'; then
    dom_vectors="${dom_vectors}POSTMESSAGE;"
  fi
  
  if printf '%s' "$resp_body" | grep -qE 'localStorage|sessionStorage|history\.'; then
    dom_vectors="${dom_vectors}STORAGE_BASED;"
  fi
  
  echo "${dom_vectors:-NONE}"
}

# False positive filtering
is_false_positive() {
  local url="$1"
  local payload="$2"
  local resp_body="$3"
  local context="$4"
  
  # Common false positive patterns
  
  # 1. Payload in hidden fields or disabled inputs
  if printf '%s' "$resp_body" | grep -qE '<input[^>]*type="hidden"[^>]*value="[^"]*'"$(printf '%s' "$payload" | sed 's/[[\.*^$()+?{|\\]/\\&/g')"'[^"]*"'; then
    return 0  # False positive
  fi
  
  # 2. Payload in comments or meta tags (non-executable)
  if printf '%s' "$resp_body" | grep -qE '<!--[^>]*'"$(printf '%s' "$payload" | sed 's/[[\.*^$()+?{|\\]/\\&/g')"'[^>]*-->'; then
    return 0  # False positive
  fi
  
  # 3. Payload in JSON data (unless in dangerous context)
  if printf '%s' "$resp_body" | grep -qE '"[^"]*'"$(printf '%s' "$payload" | sed 's/[[\.*^$()+?{|\\]/\\&/g')"'[^"]*"' && [[ "$context" != *"JAVASCRIPT"* ]]; then
    return 0  # Likely false positive
  fi
  
  # 4. Payload completely URL-encoded or double-encoded
  if ! printf '%s' "$resp_body" | grep -qF "$payload" && printf '%s' "$resp_body" | grep -qF "$(printf '%s' "$payload" | xxd -p | sed 's/../%&/g')"; then
    return 0  # False positive (completely encoded)
  fi
  
  # 5. Error pages or debug information
  if printf '%s' "$resp_body" | grep -qiE 'error|exception|debug|stack trace|line [0-9]+'; then
    return 0  # Likely false positive
  fi
  
  return 1  # Not a false positive
}

# Main worker function with complete advanced testing
process_pair() {
  local url="$1"
  local base="${url%%\?*}"
  local query="${url#*\?}"
  local payload
  local results_found=0

  [ "$url" = "$query" ] && return

  # Process each payload with advanced injection methods
  while IFS= read -r payload || [[ -n "$payload" ]]; do
    # Ignorer les lignes vides et les commentaires
    [[ -z "$payload" ]] || [[ "$payload" =~ ^[[:space:]]*# ]] && continue
    
    log_message "DEBUG" "Testing payload: $payload"  # ← CETTE LIGNE ÉTAIT MANQUANTE!
    
    # GET method testing (enhanced)
        local test_urls=()
        while IFS= read -r url; do
          [[ -n "$url" ]] && test_urls+=("$url")
        done < <(inject_payload_advanced "$base" "$query" "$payload" "GET")
    
    for test_url in "${test_urls[@]}"; do
      is_cached "$test_url" && continue
      
      sleep "$(awk "BEGIN {printf \"%.3f\", 1/$RATE_LIMIT}")"
      
      log_message "DEBUG" "Testing URL: $test_url"
      
      # Make request and parse response
      local full_response=$(make_request "GET" "$test_url" "" "$CUSTOM_HEADERS")
      
      # Parse metadata safely
      if [[ "$full_response" == *"HTTPCODE:"* ]]; then
        local resp_body="${full_response%HTTPCODE:*}"
        local metadata="${full_response##*HTTPCODE:}"
        
        # Parse metadata
        local code=$(echo "$metadata" | grep -o 'HTTPCODE:[0-9]*' | cut -d: -f2)
        local size=$(echo "$metadata" | grep -o 'SIZE:[0-9]*' | cut -d: -f2)
        local time=$(echo "$metadata" | grep -o 'TIME:[0-9.]*' | cut -d: -f2)
        
        # Set defaults if parsing failed
        code="${code:-000}"
        size="${size:-0}" 
        time="${time:-0.000}"
      else
        # Fallback if response format is unexpected
        log_message "WARN" "Unexpected response format for $test_url"
        resp_body="$full_response"
        code="000"
        size="0"
        time="0.000"
      fi
      
      # Get full headers for analysis
      local resp_headers=$(curl -s -I -A "$USER_AGENT" --max-time 5 "$test_url" 2>/dev/null | tr '\r\n' ' ' | tr '[:upper:]' '[:lower:]')
      
      # WAF Detection
      local waf_detected=$(detect_waf "$resp_headers" "$resp_body" "$code")
      
      # Check for blocking
      if [[ "$code" =~ ^[45] ]] || [ "${size:-0}" -eq 0 ]; then
        log_message "WARN" "Potential blocking: HTTP $code, WAF: $waf_detected, Size: ${size:-0}"
        cache_url "$test_url"
        continue
      fi
      
      # Enhanced reflection detection
      local reflection_quality=$(detect_reflection_quality "$resp_body" "$payload")
      
      if [[ "$reflection_quality" != "NONE" ]]; then
        # Detailed analysis
        local reflected_content="$payload"
        if [[ "$reflection_quality" == PARTIAL:* ]]; then
          reflected_content="${reflection_quality#PARTIAL:}"
        fi
        
        local context=$(analyze_context "$resp_body" "$payload")
        local filters_detected=$(detect_filters "$payload" "$reflected_content")
        local security_analysis=$(analyze_security_headers "$resp_headers")
        
        # FALSE POSITIVE CHECK
        if is_false_positive "$test_url" "$payload" "$resp_body" "$context"; then
          log_message "DEBUG" "❌ False positive detected for $test_url - skipping"
          cache_url "$test_url"
          continue
        fi
        
        # EXECUTABILITY VALIDATION
        local executability_result=$(validate_xss_executability "$resp_body" "$payload" "$context" "$filters_detected" "$security_analysis")
        local executability_score=$(echo "$executability_result" | cut -d'|' -f1)
        local validation_notes=$(echo "$executability_result" | cut -d'|' -f2)
        
        # DOM-based XSS detection
        local dom_vectors=$(detect_dom_xss "$resp_body" "$payload")
        
        # THRESHOLD CHECK - Only save if above minimum executability score
        if [ "$executability_score" -lt "$MIN_EXECUTABILITY_SCORE" ]; then
          log_message "DEBUG" "🔍 Low executability score ($executability_score < $MIN_EXECUTABILITY_SCORE) for $test_url - discarding"
          log_message "DEBUG" "├─ Context: $context"
          log_message "DEBUG" "├─ Filters: $filters_detected"
          log_message "DEBUG" "└─ Notes: $validation_notes"
          cache_url "$test_url"
          continue
        fi
        
        # Calculate risk score (now includes executability)
        local risk_score=$executability_score
        
        # Adjust risk based on additional factors
        [ "$dom_vectors" != "NONE" ] && risk_score=$((risk_score + 15))
        [ "$waf_detected" = "NONE" ] && risk_score=$((risk_score + 10))
        
        local risk_level="LOW"
        [ $risk_score -ge 50 ] && risk_level="MEDIUM"
        [ $risk_score -ge 70 ] && risk_level="HIGH"
        [ $risk_score -ge 90 ] && risk_level="CRITICAL"
        
        log_message "INFO" "🎯 VALIDATED XSS FOUND ($risk_level): $test_url"
        log_message "INFO" "├─ Payload: $payload"
        log_message "INFO" "├─ Quality: $reflection_quality"
        log_message "INFO" "├─ Context: $context"
        log_message "INFO" "├─ Filters: $filters_detected"
        log_message "INFO" "├─ WAF: $waf_detected"
        log_message "INFO" "├─ Security: $security_analysis"
        log_message "INFO" "├─ Executability: $executability_score ($validation_notes)"
        log_message "INFO" "├─ DOM Vectors: $dom_vectors"
        log_message "INFO" "├─ Final Risk: $risk_score ($risk_level)"
        log_message "INFO" "├─ Response: ${size}bytes in ${time}s"
        log_message "INFO" "└─ HTTP Code: $code"
        
        # Enhanced output format (13 columns with executability data)
        printf "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n" \
          "$test_url" \
          "$payload" \
          "$reflection_quality" \
          "$context" \
          "$filters_detected" \
          "$waf_detected" \
          "$security_analysis" \
          "$executability_score" \
          "$validation_notes" \
          "$dom_vectors" \
          "$risk_level" \
          "$code" \
          "$size" >> "$XSS_CANDIDATES"
        
        results_found=$((results_found + 1))
      fi
      
      cache_url "$test_url"
    done
    
# POST method testing (if enabled)
    if [ "$TEST_POST" = "true" ]; then
      local post_tests=()
      while IFS= read -r url; do
        [[ -n "$url" ]] && post_tests+=("$url")
      done < <(inject_payload_advanced "$base" "$query" "$payload" "POST")
      
      for post_test in "${post_tests[@]}"; do
        if [[ "$post_test" == POST:* ]]; then
          local post_url=$(echo "$post_test" | cut -d: -f2)
          local post_data=$(echo "$post_test" | cut -d: -f3-)
          
          is_cached "POST:$post_url:$post_data" && continue
          
          sleep "$(awk "BEGIN {printf \"%.3f\", 1/$RATE_LIMIT}")"
          
          log_message "DEBUG" "Testing POST: $post_url with data: $post_data"
          
          local post_response=$(make_request "POST" "$post_url" "$post_data" "$CUSTOM_HEADERS")
          local post_body="${post_response%HTTPCODE:*}"
          
          if printf '%s' "$post_body" | grep -qF -- "$payload"; then
            log_message "INFO" "🎯 POST XSS FOUND: $post_url"
            printf "POST:%s|%s|POST_REFLECTION|%s\n" "$post_url" "$payload" "$post_data" >> "$XSS_CANDIDATES"
            results_found=$((results_found + 1))
          fi
          
          cache_url "POST:$post_url:$post_data"
        fi
      done
    fi
    
    # Header injection testing (if enabled)
    if [ "$TEST_HEADERS" = "true" ]; then
      local header_results=()
      while IFS= read -r result; do
        [[ -n "$result" ]] && header_results+=("$result")
      done < <(test_header_injection "$base" "$payload")
      
      for header_result in "${header_results[@]}"; do
        log_message "INFO" "🎯 HEADER XSS FOUND: $base via $header_result"
        printf "%s|%s|HEADER_REFLECTION|%s\n" "$base" "$payload" "$header_result" >> "$XSS_CANDIDATES"
        results_found=$((results_found + 1))
      done
    fi
    
  done < "$PAYLOAD_FILE"  # ← CETTE LIGNE DOIT ÊTRE ICI, pas dans le bloc des headers!
  
  if [ $results_found -gt 0 ]; then
    log_message "INFO" "Found $results_found potential XSS candidates for $url"
  fi
}

# Export functions for parallel execution
export -f is_cached cache_url analyze_context detect_reflection_quality detect_waf detect_filters analyze_security_headers inject_payload_advanced make_request test_header_injection validate_xss_executability detect_dom_xss is_false_positive process_pair log_message
export USER_AGENT XSS_CANDIDATES PAYLOAD_FILE CACHE_DIR RATE_LIMIT LOG_LEVEL MAX_RETRIES TIMEOUT TEST_POST TEST_HEADERS CUSTOM_HEADERS MIN_EXECUTABILITY_SCORE

# Main execution with enhanced reporting
TASKS="$(mktemp)"
while IFS= read -r url; do
  echo "$url" >> "$TASKS"
done < "$CLEANED_REFLECTED_URLS"

# Display configuration
log_message "INFO" "🚀 Advanced XSS Scanner Starting..."
log_message "INFO" "├─ URLs to test: $(wc -l < "$CLEANED_REFLECTED_URLS")"
log_message "INFO" "├─ Payloads: $(wc -l < "$PAYLOAD_FILE")"
log_message "INFO" "├─ Threads: $THREADS"
log_message "INFO" "├─ Rate limit: $RATE_LIMIT req/sec"
log_message "INFO" "├─ Timeout: ${TIMEOUT}s"
log_message "INFO" "├─ Log level: $LOG_LEVEL"
log_message "INFO" "├─ POST testing: $TEST_POST"
log_message "INFO" "├─ Header testing: $TEST_HEADERS"
log_message "INFO" "├─ Custom headers: ${CUSTOM_HEADERS:-NONE}"
log_message "INFO" "└─ Executability threshold: $MIN_EXECUTABILITY_SCORE"

# Create header for output file
printf "# Advanced XSS Scanner Results - %s\n" "$(date)" > "$XSS_CANDIDATES"
printf "# Format: URL|Payload|Quality|Context|Filters|WAF|Security|ExecScore|ValidationNotes|DOM|Risk|Code|Size\n" >> "$XSS_CANDIDATES"
printf "# Minimum executability threshold: %d\n" "$MIN_EXECUTABILITY_SCORE" >> "$XSS_CANDIDATES"

# Start parallel processing
start_time=$(date +%s)
xargs -d '\n' -n1 -P "$THREADS" bash -c 'process_pair "$@"' _ < "$TASKS"
end_time=$(date +%s)
rm -f "$TASKS"

# Final statistics
total_time=$((end_time - start_time))
total_candidates=$(grep -v '^#' "$XSS_CANDIDATES" 2>/dev/null | wc -l || echo 0)

log_message "INFO" "📊 Scan completed in ${total_time}s"
if [ "$total_candidates" -gt 0 ]; then
  log_message "INFO" "🎯 Found $total_candidates potential XSS candidates"
  log_message "INFO" "📁 Results saved to: $XSS_CANDIDATES"
  
  # Risk level breakdown
  local high_risk=$(grep -c "|HIGH|" "$XSS_CANDIDATES" 2>/dev/null || echo 0)
  local medium_risk=$(grep -c "|MEDIUM|" "$XSS_CANDIDATES" 2>/dev/null || echo 0)
  local low_risk=$(grep -c "|LOW|" "$XSS_CANDIDATES" 2>/dev/null || echo 0)
  local critical_risk=$(grep -c "|CRITICAL|" "$XSS_CANDIDATES" 2>/dev/null || echo 0)
  
  log_message "INFO" "📈 Risk breakdown:"
  log_message "INFO" "├─ 🔴 Critical: $critical_risk"
  log_message "INFO" "├─ 🟠 High: $high_risk" 
  log_message "INFO" "├─ 🟡 Medium: $medium_risk"
  log_message "INFO" "└─ 🟢 Low: $low_risk"
else
  log_message "WARN" "⚠️  No XSS candidates found"
fi

log_message "INFO" "✅ Advanced XSS injection phase completed"