# Variables dynamiques de configuration — Générée automatiquement
INPUT_FILE="/home/yau/Recon/INTI_wolt/info/parameters/status_200.txt"

# Dossiers temporaires
DATA_DIR="/home/yau/Script/xssdetection/data"
SCREENSHOT_DIR="/home/yau/Script/xssdetection/screenshots"

# Fichiers de sortie
EXTRACTED_URLS="/home/yau/Script/xssdetection/data/extracted_urls.txt"
REFLECTED_OUTPUT="/home/yau/Script/xssdetection/data/reflected_output.txt"
CLEANED_REFLECTED_URLS="/home/yau/Script/xssdetection/data/cleaned_reflected_urls.txt"
XSS_CANDIDATES="/home/yau/Script/xssdetection/data/xss_candidates.txt"
WAF_REPORT="/home/yau/Script/xssdetection/data/waf_analysis.txt"
SCREENSHOT_REPORT="/home/yau/Script/xssdetection/data/screenshot_report.html"
SCREENSHOTS_DIR="/home/yau/Script/xssdetection/data/screenshots"

# Fichiers système reprise
CHECKPOINT_DIR="/home/yau/Script/xssdetection/data/checkpoints"
LOCK_DIR="/home/yau/Script/xssdetection/data/locks"
RESUME_LOG="/home/yau/Script/xssdetection/data/resume.log"

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
CACHE_DIR="/home/yau/Script/xssdetection/data/cache"

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
LOG_LEVEL=INFO

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
