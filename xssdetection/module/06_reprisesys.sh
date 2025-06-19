#!/usr/bin/env bash
# modules/08_resume.sh - Advanced Resume System for XSS Scanner
set -euo pipefail

# Resolve script directory and project root
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configuration
CHECKPOINT_DIR="${CHECKPOINT_DIR:-$PROJECT_ROOT/data/checkpoints}"
LOCK_DIR="${LOCK_DIR:-$PROJECT_ROOT/data/locks}"
STATE_FILE="${STATE_FILE:-$CHECKPOINT_DIR/scan_state.json}"
PROGRESS_FILE="${PROGRESS_FILE:-$CHECKPOINT_DIR/progress.txt}"
RESUME_LOG="${RESUME_LOG:-$PROJECT_ROOT/data/resume.log}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
AUTO_RESUME="${AUTO_RESUME:-true}"
CHECKPOINT_INTERVAL="${CHECKPOINT_INTERVAL:-100}"  # Save every N URLs
MAX_LOCK_AGE="${MAX_LOCK_AGE:-3600}"  # 1 hour in seconds
CLEANUP_OLD_CHECKPOINTS="${CLEANUP_OLD_CHECKPOINTS:-true}"
BACKUP_RESULTS="${BACKUP_RESULTS:-true}"

# Session information
SCAN_ID=""
SCAN_START_TIME=""
CURRENT_MODULE=""
CURRENT_STEP=""
TOTAL_URLS=""
PROCESSED_URLS=""

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
  
  # Log to both stderr and resume log
  printf "${color}[$timestamp][$level]\033[0m %s\n" "$message" >&2
  echo "[$timestamp][$level] $message" >> "$RESUME_LOG"
}

# Generate unique scan ID
generate_scan_id() {
  echo "scan_$(date +%Y%m%d_%H%M%S)_$$"
}

# Initialize scan session
init_scan_session() {
  local module_name="$1"
  local total_items="${2:-0}"
  
  SCAN_ID=$(generate_scan_id)
  SCAN_START_TIME=$(date '+%Y-%m-%d %H:%M:%S')
  CURRENT_MODULE="$module_name"
  TOTAL_URLS="$total_items"
  PROCESSED_URLS=0
  
  # Create directories
  mkdir -p "$CHECKPOINT_DIR" "$LOCK_DIR"
  
  # Initialize state file
  cat > "$STATE_FILE" << EOF
{
  "scan_id": "$SCAN_ID",
  "start_time": "$SCAN_START_TIME",
  "current_module": "$CURRENT_MODULE",
  "total_urls": $TOTAL_URLS,
  "processed_urls": $PROCESSED_URLS,
  "current_step": "",
  "status": "running",
  "last_checkpoint": "$(date -Iseconds)",
  "processed_items": [],
  "failed_items": [],
  "skipped_items": [],
  "configuration": {
    "checkpoint_interval": $CHECKPOINT_INTERVAL,
    "auto_resume": $AUTO_RESUME,
    "log_level": "$LOG_LEVEL"
  }
}
EOF

  # Initialize progress file
  cat > "$PROGRESS_FILE" << EOF
# XSS Scanner Progress Tracking
# Scan ID: $SCAN_ID
# Started: $SCAN_START_TIME
# Module: $CURRENT_MODULE
# Format: STATUS|URL|TIMESTAMP|DETAILS
EOF

  log_message "INFO" "🚀 Scan session initialized"
  log_message "INFO" "├─ Scan ID: $SCAN_ID"
  log_message "INFO" "├─ Module: $CURRENT_MODULE"
  log_message "INFO" "├─ Total items: $TOTAL_URLS"
  log_message "INFO" "└─ State file: $STATE_FILE"
}

# Create lock file to prevent concurrent scans
create_lock() {
  local lock_file="$LOCK_DIR/${CURRENT_MODULE}.lock"
  local lock_content="$SCAN_ID|$$|$(date -Iseconds)"
  
  # Check for existing lock
  if [ -f "$lock_file" ]; then
    local existing_lock=$(cat "$lock_file")
    local lock_pid=$(echo "$existing_lock" | cut -d'|' -f2)
    local lock_time=$(echo "$existing_lock" | cut -d'|' -f3)
    local lock_age=$(($(date +%s) - $(date -d "$lock_time" +%s 2>/dev/null || echo 0)))
    
    # Check if lock is stale
    if [ $lock_age -gt $MAX_LOCK_AGE ] || ! kill -0 "$lock_pid" 2>/dev/null; then
      log_message "WARN" "Removing stale lock (age: ${lock_age}s, PID: $lock_pid)"
      rm -f "$lock_file"
    else
      log_message "ERROR" "Another scan is already running (PID: $lock_pid)"
      log_message "ERROR" "Lock file: $lock_file"
      log_message "ERROR" "Use 'force-unlock' option to override"
      exit 1
    fi
  fi
  
  # Create new lock
  echo "$lock_content" > "$lock_file"
  log_message "DEBUG" "Lock created: $lock_file"
  
  # Setup trap to remove lock on exit
  trap "remove_lock '$lock_file'" EXIT INT TERM
}

# Remove lock file
remove_lock() {
  local lock_file="$1"
  if [ -f "$lock_file" ]; then
    rm -f "$lock_file"
    log_message "DEBUG" "Lock removed: $lock_file"
  fi
}

# Update scan state
update_state() {
  local status="$1"
  local current_item="${2:-}"
  local details="${3:-}"
  
  PROCESSED_URLS=$((PROCESSED_URLS + 1))
  
  # Update JSON state using jq if available, otherwise use sed
  if command -v jq >/dev/null 2>&1; then
    local temp_state=$(mktemp)
    jq --arg status "$status" \
       --arg processed "$PROCESSED_URLS" \
       --arg checkpoint "$(date -Iseconds)" \
       --arg item "$current_item" \
       --arg details "$details" \
       '.status = $status | 
        .processed_urls = ($processed | tonumber) | 
        .last_checkpoint = $checkpoint |
        .current_item = $item |
        .last_details = $details' "$STATE_FILE" > "$temp_state"
    mv "$temp_state" "$STATE_FILE"
  else
    # Fallback: simple sed replacement
    sed -i.bak \
      -e "s/\"processed_urls\": [0-9]*/\"processed_urls\": $PROCESSED_URLS/" \
      -e "s/\"status\": \"[^\"]*\"/\"status\": \"$status\"/" \
      -e "s/\"last_checkpoint\": \"[^\"]*\"/\"last_checkpoint\": \"$(date -Iseconds)\"/" \
      "$STATE_FILE" 2>/dev/null || \
    sed -i \
      -e "s/\"processed_urls\": [0-9]*/\"processed_urls\": $PROCESSED_URLS/" \
      -e "s/\"status\": \"[^\"]*\"/\"status\": \"$status\"/" \
      -e "s/\"last_checkpoint\": \"[^\"]*\"/\"last_checkpoint\": \"$(date -Iseconds)\"/" \
      "$STATE_FILE"
  fi
  
  # Update progress file
  echo "$status|$current_item|$(date -Iseconds)|$details" >> "$PROGRESS_FILE"
  
  # Create checkpoint if interval reached
  if [ $((PROCESSED_URLS % CHECKPOINT_INTERVAL)) -eq 0 ]; then
    create_checkpoint
  fi
}

# Create checkpoint
create_checkpoint() {
  local checkpoint_file="$CHECKPOINT_DIR/checkpoint_${SCAN_ID}_$(date +%Y%m%d_%H%M%S).json"
  
  # Copy current state to checkpoint
  cp "$STATE_FILE" "$checkpoint_file"
  
  # Backup results if enabled
  if [ "$BACKUP_RESULTS" = "true" ]; then
    local backup_dir="$CHECKPOINT_DIR/backups"
    mkdir -p "$backup_dir"
    
    # Backup main result files
    for file in "$PROJECT_ROOT/data"/*.txt "$PROJECT_ROOT/data"/*.json; do
      if [ -f "$file" ]; then
        cp "$file" "$backup_dir/$(basename "$file").backup_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
      fi
    done
  fi
  
  log_message "DEBUG" "Checkpoint created: $checkpoint_file"
  
  # Cleanup old checkpoints if enabled
  if [ "$CLEANUP_OLD_CHECKPOINTS" = "true" ]; then
    find "$CHECKPOINT_DIR" -name "checkpoint_*.json" -mtime +7 -delete 2>/dev/null || true
  fi
}

# Check for existing scan to resume
check_resume_possibility() {
  local module_name="$1"
  
  if [ ! -f "$STATE_FILE" ] || [ "$AUTO_RESUME" != "true" ]; then
    return 1
  fi
  
  # Parse existing state
  local existing_module=""
  local existing_status=""
  local last_checkpoint=""
  
  if command -v jq >/dev/null 2>&1; then
    existing_module=$(jq -r '.current_module // empty' "$STATE_FILE" 2>/dev/null || echo "")
    existing_status=$(jq -r '.status // empty' "$STATE_FILE" 2>/dev/null || echo "")
    last_checkpoint=$(jq -r '.last_checkpoint // empty' "$STATE_FILE" 2>/dev/null || echo "")
  else
    existing_module=$(grep '"current_module"' "$STATE_FILE" | cut -d'"' -f4 2>/dev/null || echo "")
    existing_status=$(grep '"status"' "$STATE_FILE" | cut -d'"' -f4 2>/dev/null || echo "")
    last_checkpoint=$(grep '"last_checkpoint"' "$STATE_FILE" | cut -d'"' -f4 2>/dev/null || echo "")
  fi
  
  # Check if resume is applicable
  if [ "$existing_module" = "$module_name" ] && [ "$existing_status" = "running" ]; then
    log_message "INFO" "📍 Previous scan found for module: $module_name"
    log_message "INFO" "├─ Last checkpoint: $last_checkpoint"
    log_message "INFO" "└─ Resuming scan..."
    return 0
  fi
  
  return 1
}

# Get list of processed items for resume
get_processed_items() {
  local processed_file=$(mktemp)
  
  if [ -f "$PROGRESS_FILE" ]; then
    # Extract successfully processed URLs
    grep "^SUCCESS\|^COMPLETED\|^PROCESSED" "$PROGRESS_FILE" | cut -d'|' -f2 > "$processed_file"
    log_message "DEBUG" "Found $(wc -l < "$processed_file") already processed items"
  fi
  
  echo "$processed_file"
}

# Filter input file to exclude processed items
filter_for_resume() {
  local input_file="$1"
  local output_file="$2"
  local processed_file="$3"
  
  if [ -s "$processed_file" ]; then
    # Use grep to exclude already processed items
    grep -v -F -f "$processed_file" "$input_file" > "$output_file" 2>/dev/null || cp "$input_file" "$output_file"
    
    local original_count=$(wc -l < "$input_file")
    local remaining_count=$(wc -l < "$output_file")
    local skipped_count=$((original_count - remaining_count))
    
    log_message "INFO" "📊 Resume filtering:"
    log_message "INFO" "├─ Original items: $original_count"
    log_message "INFO" "├─ Already processed: $skipped_count"
    log_message "INFO" "└─ Remaining to process: $remaining_count"
  else
    cp "$input_file" "$output_file"
  fi
}

# Mark scan as completed
mark_completed() {
  local status="${1:-completed}"
  
  if [ -f "$STATE_FILE" ]; then
    # Update final status
    if command -v jq >/dev/null 2>&1; then
      local temp_state=$(mktemp)
      jq --arg status "$status" \
         --arg end_time "$(date -Iseconds)" \
         '.status = $status | .end_time = $end_time' "$STATE_FILE" > "$temp_state"
      mv "$temp_state" "$STATE_FILE"
    else
      sed -i.bak "s/\"status\": \"[^\"]*\"/\"status\": \"$status\"/" "$STATE_FILE" 2>/dev/null || \
      sed -i "s/\"status\": \"[^\"]*\"/\"status\": \"$status\"/" "$STATE_FILE"
    fi
    
    # Final progress entry
    echo "$status||$(date -Iseconds)|Scan completed" >> "$PROGRESS_FILE"
    
    log_message "INFO" "✅ Scan marked as $status"
  fi
}

# Show scan status
show_status() {
  if [ ! -f "$STATE_FILE" ]; then
    log_message "INFO" "No active scan found"
    return
  fi
  
  log_message "INFO" "📊 Current Scan Status:"
  
  if command -v jq >/dev/null 2>&1; then
    local scan_id=$(jq -r '.scan_id // "unknown"' "$STATE_FILE")
    local start_time=$(jq -r '.start_time // "unknown"' "$STATE_FILE")
    local current_module=$(jq -r '.current_module // "unknown"' "$STATE_FILE")
    local total_urls=$(jq -r '.total_urls // 0' "$STATE_FILE")
    local processed_urls=$(jq -r '.processed_urls // 0' "$STATE_FILE")
    local status=$(jq -r '.status // "unknown"' "$STATE_FILE")
    local last_checkpoint=$(jq -r '.last_checkpoint // "unknown"' "$STATE_FILE")
    
    log_message "INFO" "├─ Scan ID: $scan_id"
    log_message "INFO" "├─ Module: $current_module"
    log_message "INFO" "├─ Status: $status"
    log_message "INFO" "├─ Started: $start_time"
    log_message "INFO" "├─ Progress: $processed_urls/$total_urls"
    log_message "INFO" "├─ Last checkpoint: $last_checkpoint"
    
    if [ "$total_urls" -gt 0 ]; then
      local progress_percent=$((processed_urls * 100 / total_urls))
      log_message "INFO" "└─ Completion: ${progress_percent}%"
    fi
  else
    cat "$STATE_FILE"
  fi
}

# Clean up old data
cleanup_old_data() {
  local days="${1:-7}"
  
  log_message "INFO" "🧹 Cleaning up data older than $days days..."
  
  # Cleanup checkpoints
  find "$CHECKPOINT_DIR" -name "*.json" -mtime +$days -delete 2>/dev/null || true
  find "$CHECKPOINT_DIR/backups" -name "*backup*" -mtime +$days -delete 2>/dev/null || true
  
  # Cleanup old locks
  find "$LOCK_DIR" -name "*.lock" -mtime +1 -delete 2>/dev/null || true
  
  # Cleanup old logs
  if [ -f "$RESUME_LOG" ]; then
    tail -n 10000 "$RESUME_LOG" > "$RESUME_LOG.tmp" && mv "$RESUME_LOG.tmp" "$RESUME_LOG"
  fi
  
  log_message "INFO" "✅ Cleanup completed"
}

# Force unlock (remove all locks)
force_unlock() {
  log_message "WARN" "🔓 Force unlocking all scan locks..."
  rm -f "$LOCK_DIR"/*.lock 2>/dev/null || true
  log_message "INFO" "✅ All locks removed"
}

# Reset scan state
reset_scan() {
  log_message "WARN" "🔄 Resetting scan state..."
  rm -f "$STATE_FILE" "$PROGRESS_FILE"
  rm -f "$LOCK_DIR"/*.lock 2>/dev/null || true
  log_message "INFO" "✅ Scan state reset"
}

# Main resume manager functions
resume_module() {
  local module_name="$1"
  local input_file="$2"
  local total_items="${3:-$(wc -l < "$input_file" 2>/dev/null || echo 0)}"
  
  # Create lock
  CURRENT_MODULE="$module_name"
  create_lock
  
  # Check if we can resume
  if check_resume_possibility "$module_name"; then
    # Resume existing scan
    local processed_file=$(get_processed_items)
    local filtered_input=$(mktemp)
    
    filter_for_resume "$input_file" "$filtered_input" "$processed_file"
    
    # Update scan with remaining items
    TOTAL_URLS=$(wc -l < "$filtered_input")
    
    echo "$filtered_input"
    rm -f "$processed_file"
  else
    # Start new scan
    init_scan_session "$module_name" "$total_items"
    echo "$input_file"
  fi
}

# Wrapper functions for each module
resume_url_extraction() {
  local input_file="$1"
  resume_module "extract_urls" "$input_file"
}

resume_reflection_check() {
  local input_file="$1"
  resume_module "check_reflection" "$input_file"
}

resume_url_cleaning() {
  local input_file="$1"
  resume_module "clean_urls" "$input_file"
}

resume_payload_injection() {
  local input_file="$1"
  resume_module "inject_payloads" "$input_file"
}

resume_screenshot_capture() {
  local input_file="$1"
  resume_module "screenshot_capture" "$input_file"
}

# Command line interface
case "${1:-}" in
  "init")
    init_scan_session "${2:-manual}" "${3:-0}"
    ;;
  "status")
    show_status
    ;;
  "cleanup")
    cleanup_old_data "${2:-7}"
    ;;
  "force-unlock")
    force_unlock
    ;;
  "reset")
    reset_scan
    ;;
  "mark-completed")
    mark_completed "${2:-completed}"
    ;;
  "resume-extraction")
    resume_url_extraction "$2"
    ;;
  "resume-reflection")
    resume_reflection_check "$2"
    ;;
  "resume-cleaning")
    resume_url_cleaning "$2"
    ;;
  "resume-injection")
    resume_payload_injection "$2"
    ;;
  "resume-screenshots")
    resume_screenshot_capture "$2"
    ;;
  *)
    echo "Usage: $0 {init|status|cleanup|force-unlock|reset|mark-completed}"
    echo "       $0 {resume-extraction|resume-reflection|resume-cleaning|resume-injection|resume-screenshots} <input_file>"
    echo ""
    echo "Commands:"
    echo "  init <module> <total>     - Initialize new scan session"
    echo "  status                    - Show current scan status"
    echo "  cleanup [days]           - Clean up old data (default: 7 days)"
    echo "  force-unlock             - Remove all scan locks"
    echo "  reset                    - Reset scan state completely"
    echo "  mark-completed [status]  - Mark scan as completed"
    echo ""
    echo "Resume functions:"
    echo "  resume-* <input_file>    - Resume or start module with smart filtering"
    echo ""
    echo "Environment variables:"
    echo "  AUTO_RESUME=true         - Enable automatic resume"
    echo "  CHECKPOINT_INTERVAL=100  - Checkpoint frequency"
    echo "  MAX_LOCK_AGE=3600       - Lock timeout (seconds)"
    echo "  LOG_LEVEL=INFO          - Logging verbosity"
    exit 1
    ;;
esac