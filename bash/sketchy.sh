#!/bin/bash

# Sketchy.sh - A lightweight security scanner for repositories
# By Adversis, LLC - https://adversis.io - Think hostile. Build unbreakable.
# Security scanner for downloaded files and repositories
# Enhanced with detection patterns from GuardDog (Apache 2.0 License)
# Original GuardDog source: https://github.com/DataDog/guarddog
# Usage: sketchy.sh [path] [--high-only | --medium-up]

SCAN_PATH="${1:-.}"
FILTER_LEVEL="ALL"

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --high-only)
            FILTER_LEVEL="HIGH"
            ;;
        --medium-up)
            FILTER_LEVEL="MEDIUM"
            ;;
        --help)
            echo "Usage: $0 [path] [--high-only | --medium-up]"
            echo "  path         Path to scan (default: current directory)"
            echo "  --high-only  Only show HIGH RISK findings"
            echo "  --medium-up  Show MEDIUM and HIGH RISK findings"
            exit 0
            ;;
    esac
done

# If first arg is a filter, use current directory as scan path
if [[ "$1" == --* ]]; then
    SCAN_PATH="."
fi

ISSUES_FOUND=0
TEMP_REPORT="sketchy_report_$$.txt"

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🔍 Scanning: $SCAN_PATH${NC}"
echo "================================"

# Function to print matched line with context
print_match() {
    local severity="$1"
    local risk_level="$2"
    local description="$3"
    local file="$4"
    local pattern="$5"
    local rel_path="${file#$SCAN_PATH/}"
    
    # Check if pattern matches first
    if ! grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        return 1
    fi
    
    # Apply filter after confirming match exists
    if [[ "$FILTER_LEVEL" == "HIGH" ]] && [[ "$risk_level" != "HIGH RISK" ]]; then
        return 0  # Return success but don't print
    fi
    if [[ "$FILTER_LEVEL" == "MEDIUM" ]] && [[ "$risk_level" == "LOW RISK" ]]; then
        return 0  # Return success but don't print
    fi
    
    # Get matches with line numbers
    grep -n -E "$pattern" "$file" 2>/dev/null | head -3 | while IFS=: read -r line_num line_content; do
        # Truncate line to 80 chars if needed
        if [ ${#line_content} -gt 80 ]; then
            line_preview="${line_content:0:80}..."
        else
            line_preview="$line_content"
        fi
        
        echo -e "${severity} ${risk_level} - ${description}${NC}" | tee -a "$TEMP_REPORT"
        echo -e "${BLUE}  File: ${rel_path}:${line_num}${NC}" | tee -a "$TEMP_REPORT"
        echo -e "  Preview: ${line_preview}" | tee -a "$TEMP_REPORT"
        echo "" | tee -a "$TEMP_REPORT"
    done
    
    # Return 0 since we found a match
    return 0
}

# Function to check file
check_file() {
    local file="$1"
    local rel_path="${file#$SCAN_PATH/}"
    
    # Skip binary files and common safe extensions
    if file "$file" | grep -q "binary\|image\|audio\|video" 2>/dev/null; then
        return
    fi
    
    # ===== GUARDDOG-INSPIRED DETECTIONS =====
    # Based on GuardDog's analyzer patterns (Apache 2.0)
    
    # cmd-overwrite: Overwriting common shell commands
    pattern="(ls|dir|cat|find|grep|which|curl|wget)\s*=\s*['\"]|alias\s+(ls|dir|cat|find|grep|which|curl|wget)="
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$RED" "HIGH RISK" "[GuardDog] Command overwrite detected" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # code-execution: Various code execution patterns
    pattern="(exec\(open\(|exec\(compile\(|eval\(compile\(|__import__\(['\"]os['\"]\)|__import__\(['\"]subprocess['\"]\))"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$RED" "HIGH RISK" "[GuardDog] Code execution pattern" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # download-executable: Downloading and executing files
    pattern="(urllib\.request\.urlretrieve|wget.*&&.*chmod|curl.*\|.*sh|requests\.get.*open.*wb)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$RED" "HIGH RISK" "[GuardDog] Download and execute pattern" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # steganography: Hidden payloads in images/data
    pattern="(PIL\.Image.*extract|steganography|stegano|from.*PIL.*import|cv2\.imread.*decode)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "[GuardDog] Potential steganography" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # silent-process-execution: Hidden process execution
    pattern="(subprocess\..*stdout\s*=\s*subprocess\.DEVNULL|subprocess\..*stderr\s*=\s*subprocess\.DEVNULL|os\.devnull|> /dev/null 2>&1)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "[GuardDog] Silent process execution" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # exfiltrate-sensitive-data: Accessing sensitive files
    pattern="(\.ssh/|\.aws/|\.docker/|\.kube/|\.gnupg/|\.password-store/|id_rsa|id_dsa|credentials|\.env)"
    if grep -E "$pattern" "$file" 2>/dev/null | grep -E "(requests\.|urllib\.|curl|wget|POST|upload)" 2>/dev/null | head -1 | grep -q .; then
        print_match "$RED" "HIGH RISK" "[GuardDog] Sensitive data exfiltration" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # suspicious-npm-script: Dangerous npm lifecycle hooks
    if [[ "$file" == *package.json ]]; then
        pattern="(preinstall|postinstall|preuninstall|postuninstall).*(&& rm|&& curl|&& wget|\|\| curl|\|\| wget|node -e|eval)"
        if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
            print_match "$RED" "HIGH RISK" "[GuardDog] Suspicious npm script" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
    fi
    
    # dll-hijacking: Windows DLL hijacking attempts
    pattern="(ctypes\.windll|ctypes\.WinDLL|kernel32\.dll|LoadLibrary|GetProcAddress)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "[GuardDog] Potential DLL hijacking" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # bidirectional-characters: Unicode bidi override characters (invisible backdoors)
    # Using hexdump as portable alternative to grep -P
    if [[ "$FILTER_LEVEL" != "HIGH" ]] || [[ "$FILTER_LEVEL" == "HIGH" ]]; then  # HIGH RISK - always show if not LOW filter
        if hexdump -C "$file" 2>/dev/null | grep -E "(e2 80 aa|e2 80 ab|e2 80 ac|e2 80 ad|e2 80 ae|e2 81 a6|e2 81 a7|e2 81 a8|e2 81 a9)" 2>/dev/null | head -1 | grep -q .; then
            echo -e "${RED}  HIGH RISK - [GuardDog] Bidirectional Unicode characters (possible invisible code)${NC}" | tee -a "$TEMP_REPORT"
            echo -e "${BLUE}  File: ${rel_path}${NC}" | tee -a "$TEMP_REPORT"
            echo -e "  Preview: [Contains potentially invisible Unicode - manual review required]" | tee -a "$TEMP_REPORT"
            echo "" | tee -a "$TEMP_REPORT"
            ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
    fi
    
    # homograph-characters: Lookalike Unicode characters
    # Using file and strings as portable alternative to grep -P for Cyrillic detection
    if [[ "$FILTER_LEVEL" == "ALL" ]]; then  # SUSPICIOUS - only show if no filter
        if file "$file" 2>/dev/null | grep -q "UTF-8\|Unicode" && strings "$file" 2>/dev/null | grep -E "[а-яА-Я]" | grep -v "^[[:space:]]*#" | head -1 | grep -q .; then
            echo -e "${PURPLE}  SUSPICIOUS - [GuardDog] Cyrillic characters in code (possible homograph attack)${NC}" | tee -a "$TEMP_REPORT"
            echo -e "${BLUE}  File: ${rel_path}${NC}" | tee -a "$TEMP_REPORT"
            ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
    fi
    
    # shady-links: Suspicious URL patterns
    pattern="(bit\.ly|tinyurl|short\.link|rebrand\.ly|t\.me|discord\.gg|pastebin\.com|hastebin\.com)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "[GuardDog] Suspicious shortened/paste URL" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # ===== SOPHISTICATED OBFUSCATION DETECTION =====
    
    # Unicode and non-ASCII characters (often used to hide malicious code)
    # Using od (octal dump) as portable alternative to grep -P
    if [[ "$FILTER_LEVEL" == "ALL" ]]; then  # SUSPICIOUS - only show if no filter
        if od -An -tx1 "$file" 2>/dev/null | grep -E "([89a-f][0-9a-f])" | head -1 | grep -q .; then
            echo -e "${PURPLE}  SUSPICIOUS - Non-ASCII/Unicode characters detected${NC}" | tee -a "$TEMP_REPORT"
            echo -e "${BLUE}  File: ${rel_path}${NC}" | tee -a "$TEMP_REPORT"
            echo -e "  Preview: [Contains non-printable characters - investigate manually]" | tee -a "$TEMP_REPORT"
            echo "" | tee -a "$TEMP_REPORT"
            ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
    fi
    
    # Character code construction (chr(), fromCharCode, hex/octal escapes)
    pattern="(chr\s*\([0-9]+\)|String\.fromCharCode|Buffer\([^)]+\)\.toString|\\\\x[0-9a-f]{2}|\\\\[0-7]{3})"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "String obfuscation via character codes" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # DNS operations (commonly used for stealthy exfiltration)
    pattern="(dns\.resolve|dns\.lookup|getaddrinfo|socket\.gethostby|nslookup|dig\s+)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$RED" "HIGH RISK" "DNS operations (possible data exfiltration)" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Environment variable access (credential stealing)
    pattern="(process\.env|os\.environ|getenv|ENV\[|environ\[)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        # Check if it's accessing sensitive env vars
        if grep -E "(AWS|KEY|TOKEN|SECRET|PASSWORD|CRED|API)" "$file" 2>/dev/null | grep -E "(process\.env|os\.environ|getenv)" 2>/dev/null | head -1 | grep -q .; then
            print_match "$RED" "HIGH RISK" "Accessing sensitive environment variables" "$file" "(AWS|KEY|TOKEN|SECRET|PASSWORD|CRED|API).*(process\.env|os\.environ|getenv)" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
        else
            print_match "$YELLOW" "LOW RISK" "Environment variable access" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
    fi
    
    # Package manager invocation from within code
    pattern="(pip\s+install|npm\s+install|yarn\s+add|gem\s+install|cargo\s+install)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$RED" "HIGH RISK" "Package manager invoked from code" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Time-based triggers (delayed payload activation)
    pattern="(setTimeout\s*\([^,]+,\s*[0-9]{6,}|time\.sleep\s*\([0-9]{4,}|datetime.*days\s*[><=]|cron|schedule\.)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "Time-based trigger detected" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Dynamic import patterns (often used to hide dependencies)
    pattern="(__import__|importlib\.import_module|require\(['\"].*['\"]\.replace|require\(.*\+|dynamic import)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "Dynamic module loading" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # High-risk network operations (excluding localhost/127.0.0.1)
    local pattern="(curl|wget|nc|netcat|telnet|ssh|scp|rsync)\s+[^|>]*\.(ru|cn|tk|ml|ga|cf)|https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
    if grep -E -i "$pattern" "$file" 2>/dev/null | grep -vE 'https?://127\.|https?://localhost' | head -1 | grep -q .; then
        print_match "$RED" "HIGH RISK" "Suspicious network operation" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # WebSocket connections (alternative C2 channel)
    pattern="(WebSocket|ws\s*:\/\/|wss\s*:\/\/|socket\.io|SockJS)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "WebSocket connection detected" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Base64 encoded suspicious content
    pattern="(base64\s+-d|base64\s+--decode|atob\(|Buffer\.from\([^,]+,\s*['\"]base64|b64decode|base64\.b64decode)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "Base64 decoding detected" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Eval and dynamic code execution
    pattern="(\beval\s*\(|\bexec\s*\(|subprocess\.call|subprocess\.run|subprocess\.Popen|os\.system|shell_exec|system\(|passthru\()"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "Dynamic code execution" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Reverse shells
    pattern="(bash\s+-i|/bin/sh\s+-i|nc\s+.*\s+-e\s+/bin/|mkfifo\s+/tmp/|telnet\s+.*\s+.*\s+\||socket\.socket\(.*SOCK_STREAM)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$RED" "HIGH RISK" "Potential reverse shell" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Cryptocurrency miners
    pattern="(xmrig|cgminer|bfgminer|ethminer|minergate|nicehash|stratum\+tcp://|monero|ethereum.*wallet)"
    if grep -E -i "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$RED" "HIGH RISK" "Potential crypto miner" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Suspicious file operations
    pattern="(rm\s+-rf\s+/|chmod\s+777|chmod\s+\+s|setuid|setgid)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "Dangerous file operation" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Hidden files being created
    pattern="(touch\s+\.|echo.*>\s*\.|cat.*>\s*\.|\\\$HOME/\.)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "LOW RISK" "Hidden file operations" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Obfuscated JavaScript
    if [[ "$file" == *.js ]] || [[ "$file" == *.ts ]]; then
        pattern="(\\\x[0-9a-f]{2}|\\\u[0-9a-f]{4}|String\.fromCharCode|unescape\(|document\.write\(|eval\(.*unescape)"
        if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
            print_match "$YELLOW" "MEDIUM RISK" "Potentially obfuscated JavaScript" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
    fi
    
    # Python specific risks
    if [[ "$file" == *.py ]]; then
        pattern="(compile\(|\_\_import\_\_|importlib\.import_module|pickle\.loads|marshal\.loads|codecs\.decode|exec\(.*decode)"
        if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
            print_match "$YELLOW" "MEDIUM RISK" "Dynamic imports or deserialization" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
        
        # GuardDog: Python-specific jinja2 injection
        pattern="(jinja2\.Template|render_template_string|autoescape\s*=\s*False)"
        if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
            print_match "$YELLOW" "MEDIUM RISK" "[GuardDog] Potential template injection" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
    fi
    
    # Suspicious URLs being constructed dynamically
    pattern="(['\"]https?['\"].*\+|url\s*=.*\+.*['\"]://|\.join\([^)]*https?)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "LOW RISK" "URL string concatenation" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Git hooks manipulation
    pattern="(\.git/hooks/|git.*hooks.*pre-commit|git.*hooks.*post-checkout|git.*hooks.*pre-push|git.*hooks.*post-merge)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "Git hooks manipulation" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Shell profile persistence (bashrc, zshrc, profile)
    pattern="(~/\.bashrc|~/\.zshrc|~/\.bash_profile|~/\.profile|~/\.zprofile|\.config/fish/config\.fish|/etc/profile|/etc/bash\.bashrc)"
    if grep -E "$pattern" "$file" 2>/dev/null | grep -E "(echo|cat|>>|tee)" 2>/dev/null | head -1 | grep -q .; then
        print_match "$RED" "HIGH RISK" "Shell profile modification for persistence" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Browser credential/cookie theft
    pattern="(Chrome/Default/Cookies|Chrome/Default/Login Data|firefox.*cookies\.sqlite|Safari.*Cookies|Cookies\.binarycookies|Chrome.*Local Storage|Firefox.*storage)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$RED" "HIGH RISK" "Browser credential/cookie theft" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Cloud CLI credential theft
    pattern="(~/\.aws/credentials|~/\.aws/config|accessTokens\.json|~/\.azure|~/\.config/gcloud|application_default_credentials|~/\.kube/config|\.dockercfg|\.docker/config\.json)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$RED" "HIGH RISK" "Cloud CLI credential access" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Cloud metadata endpoint access (IMDSv1)
    pattern="(169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|instance-data|/latest/meta-data|/computeMetadata/|/metadata/instance)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$RED" "HIGH RISK" "Cloud metadata endpoint access (possible credential theft)" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Cron job persistence
    pattern="(crontab\s+-l|crontab\s+-e|\|\s*crontab|/etc/crontab|/etc/cron\.|/var/spool/cron|@reboot|@daily|@hourly)"
    if grep -E "$pattern" "$file" 2>/dev/null | grep -E "(curl|wget|bash|sh|python|exec)" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "Cron job persistence mechanism" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # macOS LaunchAgent/LaunchDaemon persistence
    pattern="(LaunchAgents|LaunchDaemons|launchctl\s+load|launchctl\s+submit|com\.apple\.|RunAtLoad|StartInterval)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "macOS Launch persistence" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Systemd service persistence
    pattern="(/etc/systemd/system|systemctl\s+enable|systemctl\s+daemon-reload|WantedBy=multi-user\.target|\[Service\]|\[Unit\])"
    if grep -E "$pattern" "$file" 2>/dev/null | grep -E "(ExecStart|curl|wget|bash)" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "Systemd service persistence" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Docker socket abuse
    pattern="(/var/run/docker\.sock|--unix-socket.*docker\.sock|docker\s+-H\s+unix://|DOCKER_HOST.*unix://)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "Docker socket abuse (container escape)" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Kubernetes service account token access
    pattern="(/var/run/secrets/kubernetes\.io/serviceaccount|/serviceaccount/token|kube-api|kubectl.*--token)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$RED" "HIGH RISK" "Kubernetes service account token access" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # SSH key theft
    pattern="(~/\.ssh/id_rsa|~/\.ssh/id_ed25519|~/\.ssh/id_dsa|~/\.ssh/id_ecdsa|ssh-keygen|~/.ssh/authorized_keys)"
    if grep -E "$pattern" "$file" 2>/dev/null | grep -E "(cat|cp|curl|wget|POST|upload)" 2>/dev/null | head -1 | grep -q .; then
        print_match "$RED" "HIGH RISK" "SSH key theft" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # History file harvesting
    pattern="(\.bash_history|\.zsh_history|\.sh_history|\.mysql_history|\.psql_history|\.sqlite_history)"
    if grep -E "$pattern" "$file" 2>/dev/null | grep -E "(grep|cat|strings|upload|POST)" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "History file harvesting" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Git credential harvesting
    pattern="(\.git-credentials|credential\.helper|GIT_ASKPASS|\.netrc|\.gitconfig.*password)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$RED" "HIGH RISK" "Git credential harvesting" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Database credential files
    pattern="(\.pgpass|\.my\.cnf|\.mongocreds|\.redis-cli|tnsnames\.ora|\.cassandra/cqlshrc)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$RED" "HIGH RISK" "Database credential file access" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # NPM/PyPI token theft
    pattern="(\.npmrc.*authToken|\.pypirc|\.gem/credentials|\.cargo/credentials|\.config/hub)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$RED" "HIGH RISK" "Package registry token theft" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Anti-debugging/VM detection
    pattern="(IsDebuggerPresent|CheckRemoteDebugger|ptrace.*PTRACE_TRACEME|/proc/self/status.*TracerPid)"
    if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "Anti-debugging/analysis techniques" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # VM detection
    pattern="(/sys/class/dmi/id/product_name|/sys/hypervisor|VirtualBox|VMware|QEMU|Hyper-V|/proc/scsi/scsi.*VBOX)"
    if grep -E "$pattern" "$file" 2>/dev/null | grep -v "^[[:space:]]*#" | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "VM/Sandbox detection" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Dockerfile-specific checks
    if [[ "$file" == *Dockerfile* ]]; then
        # RUN with curl/wget piped to shell
        pattern="RUN\s+.*(curl|wget).*\|.*(sh|bash)|RUN\s+.*(curl|wget).*-O.*&&.*chmod.*\+x"
        if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
            print_match "$YELLOW" "MEDIUM RISK" "Dockerfile downloading and executing remote code" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
        
        # Exposing sensitive data in ENV
        pattern="ENV\s+.*(PASSWORD|SECRET|TOKEN|KEY|PRIVATE|API_KEY|ACCESS_KEY)"
        if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
            print_match "$RED" "HIGH RISK" "Dockerfile exposing secrets in ENV" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
        
        # Dangerous ENTRYPOINT/CMD
        pattern="(ENTRYPOINT|CMD).*(\"|').*(nc\s|netcat|/bin/sh|bash\s+-i|curl.*\|)"
        if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
            print_match "$YELLOW" "MEDIUM RISK" "Dockerfile suspicious ENTRYPOINT/CMD" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
    fi
    
    # GitHub Actions workflow checks
    if [[ "$file" == *.yml ]] || [[ "$file" == *.yaml ]]; then
        # Secret exfiltration in workflows
        pattern="\$\{\{\s*secrets\.[A-Z_]+\s*\}\}.*(\||curl|wget|base64)"
        if grep -E "$pattern" "$file" 2>/dev/null | head -1 | grep -q .; then
            print_match "$RED" "HIGH RISK" "GitHub Actions secret exfiltration" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
        
        # GitHub token exposure
        pattern="\$\{\{\s*(github\.token|secrets\.GITHUB_TOKEN)\s*\}\}"
        if grep -E "$pattern" "$file" 2>/dev/null | grep -E "(echo|cat|curl|wget|POST)" 2>/dev/null | head -1 | grep -q .; then
            print_match "$RED" "HIGH RISK" "GitHub token exposure in workflow" "$file" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
    fi
}

# Check for YARA if available (optional enhancement)
if command -v yara &> /dev/null; then
    echo "YARA detected - enhanced scanning available"
    # Note: Would need to download GuardDog's YARA rules separately
fi

# Check for suspicious filenames
echo "Checking for suspicious files..."
while IFS= read -r file; do
    if [[ "$FILTER_LEVEL" != "HIGH" ]]; then  # MEDIUM risk - show unless HIGH filter
        echo -e "${YELLOW}  MEDIUM RISK - Suspicious file type: ${file#$SCAN_PATH/}${NC}" | tee -a "$TEMP_REPORT"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
done < <(find "$SCAN_PATH" -type f \( \
    -name "*.exe" -o \
    -name "*.dll" -o \
    -name "*.bat" -o \
    -name "*.cmd" -o \
    -name "*.scr" -o \
    -name "*.vbs" -o \
    -name "*.ps1" -o \
    -name "*.pyc" -o \
    -name "*.pyo" -o \
    -name "*.so" -o \
    -name "*.dylib" \
\) 2>/dev/null)

# Check for SUID/SGID files
if find "$SCAN_PATH" -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | grep -q .; then
    if [[ "$FILTER_LEVEL" != "NONE" ]]; then  # HIGH RISK - always show unless explicitly filtered
        echo -e "${RED}  HIGH RISK - SUID/SGID files found${NC}" | tee -a "$TEMP_REPORT"
        find "$SCAN_PATH" -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; 2>/dev/null
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
fi

# Scan all text files
echo "Scanning file contents..."
# Use process substitution to avoid subshell issue with while loop
while IFS= read -r file; do
    check_file "$file"
done < <(find "$SCAN_PATH" -type f -size -1M \( \
    -name "*.sh" -o \
    -name "*.bash" -o \
    -name "*.zsh" -o \
    -name "*.fish" -o \
    -name "*.py" -o \
    -name "*.rb" -o \
    -name "*.pl" -o \
    -name "*.php" -o \
    -name "*.js" -o \
    -name "*.ts" -o \
    -name "*.jsx" -o \
    -name "*.tsx" -o \
    -name "*.java" -o \
    -name "*.c" -o \
    -name "*.cpp" -o \
    -name "*.go" -o \
    -name "*.rs" -o \
    -name "*.lua" -o \
    -name "*.yml" -o \
    -name "*.yaml" -o \
    -name "*.json" -o \
    -name "*.xml" -o \
    -name "*.conf" -o \
    -name "*.config" -o \
    -name "*.txt" -o \
    -name "Makefile" -o \
    -name "*Dockerfile*" -o \
    -name "*-compose*" -o \
    -name "Containerfile" -o \
    -name ".gitignore" -o \
    -name ".env*" -o \
    -name "setup.py" -o \
    -name "setup.cfg" -o \
    -name "pyproject.toml" -o \
    -name "requirements*.txt" \
\) 2>/dev/null)

# Check package files for suspicious patterns
if [ -f "$SCAN_PATH/package.json" ]; then
    echo "Checking package.json..."
    
    # Check for lifecycle scripts (GuardDog pattern)
    pattern="(preinstall|postinstall|preuninstall|postuninstall|prepare|prepublish)"
    if grep -E "$pattern" "$SCAN_PATH/package.json" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "npm lifecycle scripts detected" "$SCAN_PATH/package.json" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Check for suspicious dependencies
    if grep -E "(\"[^\"]+\"\s*:\s*\"(http|git|file):)" "$SCAN_PATH/package.json" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "Non-registry dependency source" "$SCAN_PATH/package.json" "(http|git|file):" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
fi

if [ -f "$SCAN_PATH/setup.py" ]; then
    echo "Checking Python setup files..."
    pattern="(subprocess|os\.system|exec|eval|urllib|requests\.get|cmdclass)"
    if grep -E "$pattern" "$SCAN_PATH/setup.py" 2>/dev/null | head -1 | grep -q .; then
        print_match "$YELLOW" "MEDIUM RISK" "Suspicious operations in setup.py" "$SCAN_PATH/setup.py" "$pattern" && ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
fi

# Check for typosquatting indicators (expanded from GuardDog)
if [ -f "$SCAN_PATH/package.json" ] || [ -f "$SCAN_PATH/setup.py" ] || [ -f "$SCAN_PATH/pyproject.toml" ]; then
    echo "Checking for potential typosquatting..."
    
    # Common typosquatting patterns from GuardDog
    for file in "$SCAN_PATH/package.json" "$SCAN_PATH/setup.py" "$SCAN_PATH/pyproject.toml"; do
        if [ -f "$file" ]; then
            # Expanded list based on GuardDog's top package list
            if grep -E "(colourama|python-dateutil|python-dateutils|djnago|reqeusts|beautifulsoup4|numpyy|pilllow|tensorfIow|requets|beautifu1soup|scikit_learn|opencv_python|flask-security|djago|padas|numby|matplot1ib|selenum|pytohn|urlib3|openssl-python)" "$file" 2>/dev/null | head -1 | grep -q .; then
                if [[ "$FILTER_LEVEL" != "NONE" ]]; then  # HIGH RISK
                    echo -e "${RED}  HIGH RISK - Potential typosquatted package name detected${NC}" | tee -a "$TEMP_REPORT"
                    echo -e "${BLUE}  File: ${file#$SCAN_PATH/}${NC}" | tee -a "$TEMP_REPORT"
                    ISSUES_FOUND=$((ISSUES_FOUND + 1))
                fi
            fi
        fi
    done
fi

# Summary
echo "================================"
if [ $ISSUES_FOUND -eq 0 ]; then
    echo -e "${GREEN}✅ Scan complete. No suspicious patterns detected.${NC}"
else
    echo -e "${RED}⚠️  Scan complete. Found $ISSUES_FOUND potential issue(s).${NC}"
fi

# Clean up
rm -f "$TEMP_REPORT"

exit $ISSUES_FOUND
