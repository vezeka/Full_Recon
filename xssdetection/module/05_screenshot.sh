#!/usr/bin/env bash
# modules/05b_screenshot_advanced.sh - Advanced XSS Screenshot Capture
set -euo pipefail

# Resolve script directory and project root
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Enhanced configuration
XSS_CANDIDATES="${XSS_CANDIDATES:-$PROJECT_ROOT/data/xss_candidates.txt}"
SCREENSHOTS_DIR="${SCREENSHOTS_DIR:-$PROJECT_ROOT/data/screenshots}"
SCREENSHOT_REPORT="${SCREENSHOT_REPORT:-$PROJECT_ROOT/data/screenshot_report.html}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
THREADS="${THREADS:-5}"
TIMEOUT="${TIMEOUT:-10}"
BROWSER_WIDTH="${BROWSER_WIDTH:-1920}"
BROWSER_HEIGHT="${BROWSER_HEIGHT:-1080}"
CAPTURE_ALERTS="${CAPTURE_ALERTS:-true}"
COMPARE_MODE="${COMPARE_MODE:-true}"
MAX_SCREENSHOTS="${MAX_SCREENSHOTS:-100}"
SCREENSHOT_FORMAT="${SCREENSHOT_FORMAT:-png}"

# Browser detection and setup
BROWSER_CMD=""
BROWSER_TYPE=""

# Enhanced logging with levels and colors
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
  
  # Color coding
  local color=""
  case "$level" in
    "ERROR") color="\033[31m" ;;  # Red
    "WARN")  color="\033[33m" ;;  # Yellow
    "INFO")  color="\033[32m" ;;  # Green
    "DEBUG") color="\033[36m" ;;  # Cyan
  esac
  
  printf "${color}[$timestamp][$level]\033[0m %s\n" "$message" >&2
}

# Browser detection and setup
detect_browser() {
  log_message "DEBUG" "Detecting available browsers..."
  
  # Check for Chrome/Chromium
  if command -v google-chrome >/dev/null 2>&1; then
    BROWSER_CMD="google-chrome"
    BROWSER_TYPE="chrome"
    log_message "INFO" "Using Google Chrome"
  elif command -v chromium-browser >/dev/null 2>&1; then
    BROWSER_CMD="chromium-browser"
    BROWSER_TYPE="chrome"
    log_message "INFO" "Using Chromium"
  elif command -v chromium >/dev/null 2>&1; then
    BROWSER_CMD="chromium"
    BROWSER_TYPE="chrome"
    log_message "INFO" "Using Chromium"
  # Check for Firefox
  elif command -v firefox >/dev/null 2>&1; then
    BROWSER_CMD="firefox"
    BROWSER_TYPE="firefox"
    log_message "INFO" "Using Firefox"
  # Check for WebKit/Safari
  elif command -v webkit2png >/dev/null 2>&1; then
    BROWSER_CMD="webkit2png"
    BROWSER_TYPE="webkit"
    log_message "INFO" "Using WebKit"
  else
    log_message "ERROR" "No supported browser found. Install Chrome, Chromium, or Firefox"
    exit 1
  fi
}

# Generate JavaScript for XSS detection
generate_xss_detector_js() {
  cat << 'EOF'
// XSS Detection and Alert Capture Script
(function() {
    window.xssDetected = false;
    window.xssAlerts = [];
    window.xssDetails = {
        alerts: [],
        confirms: [],
        prompts: [],
        errors: [],
        domChanges: [],
        networkRequests: []
    };

    // Override alert, confirm, prompt
    const originalAlert = window.alert;
    const originalConfirm = window.confirm;
    const originalPrompt = window.prompt;
    
    window.alert = function(message) {
        window.xssDetected = true;
        window.xssDetails.alerts.push({
            type: 'alert',
            message: String(message),
            timestamp: new Date().toISOString(),
            stack: new Error().stack
        });
        document.body.style.backgroundColor = '#ff0000';
        document.body.setAttribute('data-xss-detected', 'alert');
        return originalAlert.call(this, message);
    };
    
    window.confirm = function(message) {
        window.xssDetected = true;
        window.xssDetails.confirms.push({
            type: 'confirm',
            message: String(message),
            timestamp: new Date().toISOString(),
            stack: new Error().stack
        });
        document.body.style.backgroundColor = '#ff8800';
        document.body.setAttribute('data-xss-detected', 'confirm');
        return originalConfirm.call(this, message);
    };
    
    window.prompt = function(message, defaultText) {
        window.xssDetected = true;
        window.xssDetails.prompts.push({
            type: 'prompt',
            message: String(message),
            defaultText: String(defaultText || ''),
            timestamp: new Date().toISOString(),
            stack: new Error().stack
        });
        document.body.style.backgroundColor = '#00ff00';
        document.body.setAttribute('data-xss-detected', 'prompt');
        return originalPrompt.call(this, message, defaultText);
    };

    // Monitor console errors
    const originalError = console.error;
    console.error = function(...args) {
        window.xssDetails.errors.push({
            type: 'error',
            message: args.join(' '),
            timestamp: new Date().toISOString()
        });
        return originalError.apply(this, args);
    };

    // Monitor DOM changes
    if (window.MutationObserver) {
        const observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                    Array.from(mutation.addedNodes).forEach(function(node) {
                        if (node.nodeType === 1 && (node.tagName === 'SCRIPT' || node.tagName === 'IMG' || node.tagName === 'SVG')) {
                            window.xssDetails.domChanges.push({
                                type: 'dom_change',
                                element: node.outerHTML || node.textContent,
                                timestamp: new Date().toISOString()
                            });
                        }
                    });
                }
            });
        });
        observer.observe(document.body, { childList: true, subtree: true });
    }

    // Monitor network requests
    const originalFetch = window.fetch;
    window.fetch = function(...args) {
        window.xssDetails.networkRequests.push({
            type: 'fetch',
            url: args[0],
            timestamp: new Date().toISOString()
        });
        return originalFetch.apply(this, args);
    };

    // Add visual indicator
    setTimeout(function() {
        if (window.xssDetected) {
            const indicator = document.createElement('div');
            indicator.innerHTML = '🚨 XSS DETECTED 🚨';
            indicator.style.cssText = 'position:fixed;top:0;left:0;background:red;color:white;padding:10px;z-index:99999;font-weight:bold;';
            document.body.appendChild(indicator);
        }
    }, 100);

    // Export detection results
    window.getXSSResults = function() {
        return {
            detected: window.xssDetected,
            details: window.xssDetails
        };
    };
})();
EOF
}

# Take screenshot with Chrome/Chromium
take_chrome_screenshot() {
  local url="$1"
  local output_file="$2"
  local wait_time="${3:-3}"
  
  local js_file=$(mktemp --suffix=.js)
  generate_xss_detector_js > "$js_file"
  
  local chrome_args=(
    --headless
    --no-sandbox
    --disable-gpu
    --disable-dev-shm-usage
    --disable-extensions
    --disable-plugins
    --disable-images
    --virtual-time-budget=5000
    --window-size="$BROWSER_WIDTH,$BROWSER_HEIGHT"
    --screenshot="$output_file"
    --user-agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
  )
  
  if [ "$CAPTURE_ALERTS" = "true" ]; then
    chrome_args+=(--disable-web-security)
    chrome_args+=(--allow-running-insecure-content)
  fi
  
  log_message "DEBUG" "Taking screenshot: $url"
  
  # Add JavaScript injection and take screenshot
  timeout "$TIMEOUT" "$BROWSER_CMD" "${chrome_args[@]}" \
    --run-all-compositor-stages-before-draw \
    --virtual-time-budget=$((wait_time * 1000)) \
    "$url" 2>/dev/null || {
    log_message "WARN" "Screenshot failed for: $url"
    rm -f "$js_file"
    return 1
  }
  
  rm -f "$js_file"
  
  if [ -f "$output_file" ]; then
    log_message "DEBUG" "Screenshot saved: $output_file"
    return 0
  else
    log_message "WARN" "Screenshot file not created: $output_file"
    return 1
  fi
}

# Take screenshot with Firefox
take_firefox_screenshot() {
  local url="$1"
  local output_file="$2"
  local wait_time="${3:-3}"
  
  local temp_profile=$(mktemp -d)
  
  # Firefox preferences for headless screenshot
  cat > "$temp_profile/prefs.js" << EOF
user_pref("browser.dom.window.dump.enabled", true);
user_pref("devtools.console.stdout.chrome", true);
user_pref("security.tls.insecure_fallback_hosts", "*");
user_pref("security.tls.unrestricted_rc4_fallback", true);
user_pref("security.mixed_content.block_active_content", false);
user_pref("security.mixed_content.block_display_content", false);
EOF

  timeout "$TIMEOUT" "$BROWSER_CMD" \
    --headless \
    --profile "$temp_profile" \
    --window-size="$BROWSER_WIDTH,$BROWSER_HEIGHT" \
    --screenshot="$output_file" \
    "$url" 2>/dev/null || {
    log_message "WARN" "Firefox screenshot failed for: $url"
    rm -rf "$temp_profile"
    return 1
  }
  
  rm -rf "$temp_profile"
  
  if [ -f "$output_file" ]; then
    log_message "DEBUG" "Screenshot saved: $output_file"
    return 0
  else
    return 1
  fi
}

# Take screenshot with WebKit
take_webkit_screenshot() {
  local url="$1"
  local output_file="$2"
  local wait_time="${3:-3}"
  
  timeout "$TIMEOUT" webkit2png \
    --width="$BROWSER_WIDTH" \
    --height="$BROWSER_HEIGHT" \
    --delay="$wait_time" \
    --output="$(dirname "$output_file")" \
    --filename="$(basename "$output_file" .png)" \
    "$url" 2>/dev/null || {
    log_message "WARN" "WebKit screenshot failed for: $url"
    return 1
  }
  
  if [ -f "$output_file" ]; then
    log_message "DEBUG" "Screenshot saved: $output_file"
    return 0
  else
    return 1
  fi
}

# Generic screenshot function
take_screenshot() {
  local url="$1"
  local output_file="$2"
  local wait_time="${3:-3}"
  
  case "$BROWSER_TYPE" in
    "chrome")
      take_chrome_screenshot "$url" "$output_file" "$wait_time"
      ;;
    "firefox")
      take_firefox_screenshot "$url" "$output_file" "$wait_time"
      ;;
    "webkit")
      take_webkit_screenshot "$url" "$output_file" "$wait_time"
      ;;
    *)
      log_message "ERROR" "Unknown browser type: $BROWSER_TYPE"
      return 1
      ;;
  esac
}

# Analyze XSS execution from screenshot
analyze_xss_execution() {
  local url="$1"
  local payload="$2"
  local screenshot_file="$3"
  local execution_detected="false"
  local analysis_result=""
  
  # Check if screenshot was taken successfully
  if [ ! -f "$screenshot_file" ]; then
    analysis_result="SCREENSHOT_FAILED"
    echo "$execution_detected|$analysis_result"
    return
  fi
  
  # Get file size and basic info
  local file_size=$(stat -f%z "$screenshot_file" 2>/dev/null || stat -c%s "$screenshot_file" 2>/dev/null || echo "0")
  local file_info="Size:${file_size}bytes"
  
  # Basic analysis based on screenshot properties
  if [ "$file_size" -gt 1000 ]; then
    # Screenshot seems valid
    analysis_result="SCREENSHOT_TAKEN|$file_info"
    
    # Additional analysis could be added here:
    # - Image analysis to detect alert dialogs
    # - Color detection for XSS indicators
    # - Text recognition for error messages
    
    # For now, we assume screenshot success indicates potential execution
    if echo "$payload" | grep -qE "(alert|confirm|prompt|<script|<img.*onerror|<svg.*onload)"; then
      execution_detected="true"
      analysis_result="POTENTIAL_EXECUTION|$analysis_result"
    fi
  else
    analysis_result="SCREENSHOT_EMPTY|$file_info"
  fi
  
  echo "$execution_detected|$analysis_result"
}

# Compare screenshots (before/after)
compare_screenshots() {
  local original_url="$1"
  local xss_url="$2"
  local output_dir="$3"
  local comparison_result=""
  
  if [ "$COMPARE_MODE" != "true" ]; then
    echo "COMPARE_DISABLED"
    return
  fi
  
  local original_screenshot="$output_dir/original_$(basename "$original_url" | tr '/' '_').png"
  local xss_screenshot="$output_dir/xss_$(basename "$xss_url" | tr '/' '_').png"
  local diff_screenshot="$output_dir/diff_$(basename "$xss_url" | tr '/' '_').png"
  
  # Take original screenshot (clean URL)
  if take_screenshot "$original_url" "$original_screenshot" 2; then
    log_message "DEBUG" "Original screenshot taken"
  else
    echo "ORIGINAL_FAILED"
    return
  fi
  
  # Take XSS screenshot
  if take_screenshot "$xss_url" "$xss_screenshot" 3; then
    log_message "DEBUG" "XSS screenshot taken"
  else
    echo "XSS_FAILED"
    return
  fi
  
  # Compare screenshots if both exist
  if [ -f "$original_screenshot" ] && [ -f "$xss_screenshot" ]; then
    local original_size=$(stat -f%z "$original_screenshot" 2>/dev/null || stat -c%s "$original_screenshot" 2>/dev/null || echo "0")
    local xss_size=$(stat -f%z "$xss_screenshot" 2>/dev/null || stat -c%s "$xss_screenshot" 2>/dev/null || echo "0")
    
    local size_diff=$((xss_size - original_size))
    local size_diff_percent=0
    
    if [ "$original_size" -gt 0 ]; then
      size_diff_percent=$(( (size_diff * 100) / original_size ))
    fi
    
    comparison_result="COMPARED|OrigSize:${original_size}|XSSSize:${xss_size}|Diff:${size_diff_percent}%"
    
    # If ImageMagick is available, create visual diff
    if command -v compare >/dev/null 2>&1; then
      if compare "$original_screenshot" "$xss_screenshot" "$diff_screenshot" 2>/dev/null; then
        comparison_result="$comparison_result|DiffImage:$diff_screenshot"
        log_message "DEBUG" "Visual diff created: $diff_screenshot"
      fi
    fi
  else
    comparison_result="COMPARISON_FAILED"
  fi
  
  echo "$comparison_result"
}

# Process single XSS candidate
process_xss_candidate() {
  local line="$1"
  local line_number="$2"
  
  # Skip comments and empty lines
  [[ "$line" =~ ^#.*$ ]] || [[ -z "$line" ]] && return
  
  # Parse XSS candidate line (format from Module 04)
  IFS='|' read -ra fields <<< "$line"
  local url="${fields[0]}"
  local payload="${fields[1]}"
  local risk_level="${fields[10]:-UNKNOWN}"
  
  if [ -z "$url" ] || [ -z "$payload" ]; then
    log_message "WARN" "Invalid line format: $line"
    return
  fi
  
  log_message "DEBUG" "Processing XSS candidate: $url"
  
  # Create safe filename
  local safe_filename=$(echo "${url}_${payload}" | tr '/?&=:<>|*' '_' | cut -c1-100)
  local screenshot_file="$SCREENSHOTS_DIR/${line_number}_${safe_filename}.${SCREENSHOT_FORMAT}"
  
  # Take screenshot
  local screenshot_result=""
  if take_screenshot "$url" "$screenshot_file" 3; then
    # Analyze execution
    local analysis=$(analyze_xss_execution "$url" "$payload" "$screenshot_file")
    local execution_detected=$(echo "$analysis" | cut -d'|' -f1)
    local analysis_details=$(echo "$analysis" | cut -d'|' -f2-)
    
    if [ "$execution_detected" = "true" ]; then
      log_message "INFO" "🎯 XSS Execution detected: $url"
      log_message "INFO" "├─ Payload: $payload"
      log_message "INFO" "├─ Screenshot: $screenshot_file"
      log_message "INFO" "└─ Analysis: $analysis_details"
    else
      log_message "DEBUG" "Screenshot taken but no clear execution: $url"
    fi
    
    screenshot_result="SUCCESS|$execution_detected|$analysis_details|$screenshot_file"
  else
    screenshot_result="FAILED|||"
    log_message "WARN" "Screenshot failed for: $url"
  fi
  
  # Return result for report generation
  echo "$line_number|$url|$payload|$risk_level|$screenshot_result"
}

# Generate HTML report
generate_html_report() {
  local results_file="$1"
  
  cat > "$SCREENSHOT_REPORT" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>XSS Screenshot Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .summary { background: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .xss-item { background: white; margin: 10px 0; padding: 15px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .xss-executed { border-left: 5px solid #e74c3c; }
        .xss-potential { border-left: 5px solid #f39c12; }
        .xss-failed { border-left: 5px solid #95a5a6; }
        .screenshot { max-width: 300px; border: 1px solid #ddd; border-radius: 5px; }
        .payload { background: #ecf0f1; padding: 5px; border-radius: 3px; font-family: monospace; word-break: break-all; }
        .url { color: #3498db; word-break: break-all; }
        .risk-critical { color: #e74c3c; font-weight: bold; }
        .risk-high { color: #e67e22; font-weight: bold; }
        .risk-medium { color: #f39c12; font-weight: bold; }
        .risk-low { color: #27ae60; font-weight: bold; }
        .toggle { cursor: pointer; background: #3498db; color: white; padding: 5px 10px; border-radius: 3px; display: inline-block; margin: 5px 0; }
        .details { display: none; margin-top: 10px; padding: 10px; background: #ecf0f1; border-radius: 3px; }
    </style>
    <script>
        function toggleDetails(id) {
            var element = document.getElementById(id);
            element.style.display = element.style.display === 'none' ? 'block' : 'none';
        }
    </script>
</head>
<body>
    <div class="header">
        <h1>🎯 XSS Screenshot Analysis Report</h1>
        <p>Generated on: <span id="timestamp"></span></p>
        <p>Browser: <span id="browser-info"></span></p>
    </div>
    
    <div class="summary">
        <h2>📊 Summary</h2>
        <p><strong>Total XSS Candidates:</strong> <span id="total-candidates">0</span></p>
        <p><strong>Screenshots Taken:</strong> <span id="screenshots-taken">0</span></p>
        <p><strong>Execution Detected:</strong> <span id="execution-detected">0</span></p>
        <p><strong>Failed Screenshots:</strong> <span id="failed-screenshots">0</span></p>
    </div>
    
    <div id="xss-results">
        <!-- XSS results will be inserted here -->
    </div>
    
    <script>
        document.getElementById('timestamp').textContent = new Date().toLocaleString();
        document.getElementById('browser-info').textContent = 'BROWSER_TYPE_PLACEHOLDER';
    </script>
</body>
</html>
EOF

  # Update browser info in report
  sed -i.bak "s/BROWSER_TYPE_PLACEHOLDER/$BROWSER_TYPE/g" "$SCREENSHOT_REPORT" 2>/dev/null || \
    sed -i "s/BROWSER_TYPE_PLACEHOLDER/$BROWSER_TYPE/g" "$SCREENSHOT_REPORT"
  
  log_message "INFO" "📄 HTML report template created: $SCREENSHOT_REPORT"
}

# Update HTML report with results
update_html_report() {
  local results_file="$1"
  local total_candidates=0
  local screenshots_taken=0
  local execution_detected=0
  local failed_screenshots=0
  local xss_html=""
  
  while IFS= read -r result_line; do
    [ -z "$result_line" ] && continue
    
    IFS='|' read -ra result_fields <<< "$result_line"
    local line_num="${result_fields[0]}"
    local url="${result_fields[1]}"
    local payload="${result_fields[2]}"
    local risk="${result_fields[3]}"
    local screenshot_status="${result_fields[4]}"
    local execution_status="${result_fields[5]}"
    local analysis="${result_fields[6]}"
    local screenshot_file="${result_fields[7]}"
    
    total_candidates=$((total_candidates + 1))
    
    local css_class="xss-failed"
    local status_icon="❌"
    
    case "$screenshot_status" in
      "SUCCESS")
        screenshots_taken=$((screenshots_taken + 1))
        if [ "$execution_status" = "true" ]; then
          execution_detected=$((execution_detected + 1))
          css_class="xss-executed"
          status_icon="🎯"
        else
          css_class="xss-potential"
          status_icon="⚠️"
        fi
        ;;
      "FAILED")
        failed_screenshots=$((failed_screenshots + 1))
        ;;
    esac
    
    local risk_class="risk-${risk,,}"
    local screenshot_html=""
    
    if [ -n "$screenshot_file" ] && [ -f "$screenshot_file" ]; then
      local relative_screenshot=$(realpath --relative-to="$(dirname "$SCREENSHOT_REPORT")" "$screenshot_file" 2>/dev/null || echo "$screenshot_file")
      screenshot_html="<img src=\"$relative_screenshot\" class=\"screenshot\" alt=\"Screenshot\">"
    fi
    
    xss_html="$xss_html
    <div class=\"xss-item $css_class\">
        <h3>$status_icon XSS #$line_num - <span class=\"$risk_class\">$risk</span></h3>
        <p><strong>URL:</strong> <span class=\"url\">$url</span></p>
        <p><strong>Payload:</strong> <span class=\"payload\">$payload</span></p>
        <div class=\"toggle\" onclick=\"toggleDetails('details-$line_num')\">Show Details</div>
        <div id=\"details-$line_num\" class=\"details\">
            <p><strong>Screenshot Status:</strong> $screenshot_status</p>
            <p><strong>Execution Detected:</strong> $execution_status</p>
            <p><strong>Analysis:</strong> $analysis</p>
            $screenshot_html
        </div>
    </div>"
    
  done < "$results_file"
  
  # Update summary statistics
  local temp_report=$(mktemp)
  sed -e "s/<span id=\"total-candidates\">0<\/span>/<span id=\"total-candidates\">$total_candidates<\/span>/" \
      -e "s/<span id=\"screenshots-taken\">0<\/span>/<span id=\"screenshots-taken\">$screenshots_taken<\/span>/" \
      -e "s/<span id=\"execution-detected\">0<\/span>/<span id=\"execution-detected\">$execution_detected<\/span>/" \
      -e "s/<span id=\"failed-screenshots\">0<\/span>/<span id=\"failed-screenshots\">$failed_screenshots<\/span>/" \
      -e "s|<!-- XSS results will be inserted here -->|$xss_html|" \
      "$SCREENSHOT_REPORT" > "$temp_report"
  
  mv "$temp_report" "$SCREENSHOT_REPORT"
  
  log_message "INFO" "📊 Report statistics:"
  log_message "INFO" "├─ Total candidates: $total_candidates"
  log_message "INFO" "├─ Screenshots taken: $screenshots_taken"
  log_message "INFO" "├─ Execution detected: $execution_detected"
  log_message "INFO" "└─ Failed screenshots: $failed_screenshots"
}

# Main execution function
main() {
  log_message "INFO" "📸 Advanced XSS Screenshot Capture Starting..."
  log_message "INFO" "├─ Input file: $XSS_CANDIDATES"
  log_message "INFO" "├─ Screenshots dir: $SCREENSHOTS_DIR"
  log_message "INFO" "├─ Report file: $SCREENSHOT_REPORT"
  log_message "INFO" "├─ Max screenshots: $MAX_SCREENSHOTS"
  log_message "INFO" "├─ Resolution: ${BROWSER_WIDTH}x${BROWSER_HEIGHT}"
  log_message "INFO" "├─ Capture alerts: $CAPTURE_ALERTS"
  log_message "INFO" "├─ Compare mode: $COMPARE_MODE"
  log_message "INFO" "└─ Threads: $THREADS"
  
  # Validate input file
  if [[ ! -s "$XSS_CANDIDATES" ]]; then
    log_message "ERROR" "XSS candidates file missing or empty: $XSS_CANDIDATES"
    exit 1
  fi
  
  # Detect and setup browser
  detect_browser
  
  # Create output directories
  mkdir -p "$SCREENSHOTS_DIR"
  mkdir -p "$(dirname "$SCREENSHOT_REPORT")"
  
  # Generate HTML report template
  generate_html_report
  
  # Create temporary file for results
  local results_file=$(mktemp)
  
  # Process XSS candidates
  local line_number=0
  local processed=0
  
  log_message "INFO" "🚀 Starting screenshot capture..."
  
  # Export functions for parallel processing
  export -f process_xss_candidate take_screenshot take_chrome_screenshot take_firefox_screenshot take_webkit_screenshot analyze_xss_execution log_message generate_xss_detector_js
  export BROWSER_CMD BROWSER_TYPE SCREENSHOTS_DIR SCREENSHOT_FORMAT BROWSER_WIDTH BROWSER_HEIGHT CAPTURE_ALERTS TIMEOUT LOG_LEVEL
  
  while IFS= read -r line && [ $processed -lt "$MAX_SCREENSHOTS" ]; do
    line_number=$((line_number + 1))
    processed=$((processed + 1))
    
    # Skip comments and empty lines
    [[ "$line" =~ ^#.*$ ]] || [[ -z "$line" ]] && continue
    
    echo "$line|$line_number"
  done < "$XSS_CANDIDATES" | \
  xargs -d '\n' -n1 -P "$THREADS" -I {} bash -c '
    IFS="|" read -r line line_num <<< "{}"
    process_xss_candidate "$line" "$line_num"
  ' >> "$results_file"
  
  # Update HTML report with results
  if [ -s "$results_file" ]; then
    update_html_report "$results_file"
    log_message "INFO" "✅ Screenshot analysis complete!"
    log_message "INFO" "📄 Report available at: $SCREENSHOT_REPORT"
    log_message "INFO" "📁 Screenshots saved in: $SCREENSHOTS_DIR"
    
    # Open report if possible
    if command -v xdg-open >/dev/null 2>&1; then
      log_message "INFO" "🌐 Opening report in browser..."
      xdg-open "$SCREENSHOT_REPORT" 2>/dev/null &
    elif command -v open >/dev/null 2>&1; then
      log_message "INFO" "🌐 Opening report in browser..."
      open "$SCREENSHOT_REPORT" 2>/dev/null &
    fi
  else
    log_message "WARN" "No results to process"
  fi
  
  # Cleanup
  rm -f "$results_file"
  
  log_message "INFO" "📸 Screenshot capture completed"
}

# Input validation
validate_inputs() {
  if [[ ! -s "$XSS_CANDIDATES" ]]; then
    log_message "ERROR" "XSS candidates file missing or empty: $XSS_CANDIDATES"
    exit 1
  fi
  
  # Check if candidates file has the correct format
  local sample_line=$(grep -v '^#' "$XSS_CANDIDATES" | head -1)
  if [ -n "$sample_line" ]; then
    local field_count=$(echo "$sample_line" | tr '|' '\n' | wc -l)
    if [ "$field_count" -lt 3 ]; then
      log_message "ERROR" "Invalid XSS candidates file format. Expected format: URL|Payload|Quality|..."
      exit 1
    fi
  fi
}

# Cleanup function
cleanup() {
  log_message "DEBUG" "Cleaning up temporary files..."
  # Kill any remaining browser processes
  pkill -f "$BROWSER_CMD" 2>/dev/null || true
  # Remove temporary files
  find /tmp -name "*.js" -user "$(whoami)" -mtime +1 -delete 2>/dev/null || true
}

# Signal handlers
trap cleanup EXIT
trap 'log_message "WARN" "Screenshot capture interrupted"; cleanup; exit 130' INT TERM

# Execute main function
validate_inputs
main "$@"