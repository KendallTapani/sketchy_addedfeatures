# New Features in This Version

This document describes the features and improvements added to sketchy beyond the original version.

## Comparison to Original

I mainly wanted the cloning hook but got carried away, this version adds:

✅ **60+ detection patterns (Mainly Windows stuff)** (vs ~20 in original)  
✅ **Git hook integration** (new)  
✅ **Advanced filtering** (new)  
✅ **.sketchyignore support** (new)  
✅ **Windows-specific patterns** (new)  
✅ **Cloud/container patterns** (new)  
✅ **CI/CD workflow detection** (new)  
✅ **Pattern statistics** (new)  
✅ **Category filtering** (new)  
✅ **Improved code quality** (refactored)  

## Backward Compatibility

- All original patterns still work
- Bash script version still available in `sketchy/bash/`
- Same command-line interface (with additions)
- Compatible with existing workflows


## Major Features

### 1. Git Hook Integration

**Automatic Installation Prompt**
- On first run, sketchy prompts to install a git hook
- Hook automatically scans repositories after `git clone`
- Supports both local repository and global template installation

**Smart Hook Detection**
- Automatically finds sketchy executable in repository root
- Falls back to PATH if not found locally
- Non-blocking - clone succeeds even if issues found

**Installation Options**
- **Local**: Hook only for current repository
- **Global**: Hook for all future git clones (recommended)

### 2. Advanced Filtering

**Risk Level Filtering**
- `-high-only`: Show only HIGH RISK findings
- `-medium-up`: Show MEDIUM and HIGH RISK findings
- Default: Show all risk levels

**Category Filtering**
- `-category <category>`: Filter by specific category
- Categories: `supply-chain`, `credential-theft`, `persistence`, `obfuscation`, `network`, `execution`, `cloud`
- Useful for focused security reviews

**Pattern Statistics**
- `-stats`: Shows which patterns matched most frequently
- Displays patterns with no matches
- Helps understand codebase security posture

### 3. .sketchyignore Support

**Ignore File**
- Similar to `.gitignore` format
- Supports glob patterns, directory patterns, and negation
- Searches up directory tree automatically

**Features**
- Glob patterns: `*.log`, `test/*.py`
- Directory patterns: `node_modules/`
- Negation: `!test/important.py` (un-ignore specific files)
- Comments: Lines starting with `#`

### 4. Enhanced Pattern Detection

**60+ Detection Patterns** (expanded from original)

**Windows-Specific Patterns**
- Windows Task Scheduler persistence
- Windows Registry manipulation
- Windows Service installation
- Windows Startup folder manipulation
- WMI event subscription persistence
- Process injection techniques
- Process hollowing
- Reflective DLL loading
- PowerShell obfuscation and download cradles
- Certificate store manipulation
- Windows Defender exclusion
- Firewall rule manipulation
- LOLBins (Living Off The Land binaries)

**Cloud & Container Patterns**
- Cloud metadata endpoint access (AWS, Azure, GCP)
- Docker socket abuse
- Kubernetes service account token access
- Dockerfile-specific risks (secrets in ENV, suspicious RUN commands)

**CI/CD Patterns**
- GitHub Actions secret exfiltration
- GitHub token exposure in workflows
- Workflow file analysis

**Advanced Persistence**
- Cron job persistence
- Systemd service persistence
- macOS LaunchAgent/LaunchDaemon persistence
- Shell profile modifications (.bashrc, .zshrc, etc.)

**Network Exfiltration**
- DNS tunneling
- ICMP-based exfiltration
- WebSocket connections for C2
- Suspicious network operations (with localhost filtering)

**Obfuscation Detection**
- Multiple encoding/decoding chains
- Compressed payload execution
- Character code construction
- JavaScript obfuscation
- PowerShell obfuscation

### 5. Smart Localhost Filtering

**Network Pattern Intelligence**
- Automatically excludes `localhost` and `127.0.0.1` from network patterns
- Prevents false positives from legitimate local development
- Still detects suspicious external network calls

### 6. File Type-Specific Patterns

**Dockerfile Detection**
- Detects suspicious RUN commands with curl/wget piped to shell
- Identifies secrets exposed in ENV variables
- Flags dangerous ENTRYPOINT/CMD configurations

**GitHub Actions Detection**
- Scans workflow files for secret exfiltration
- Detects GitHub token exposure
- Validates workflow file structure

**Language-Specific Patterns**
- JavaScript/TypeScript obfuscation
- Python deserialization and template injection
- PowerShell download and execute patterns

## Detection Categories

### Execution Patterns
- Command overwrites
- Code execution (exec, eval, etc.)
- Download and execute
- Reverse shells
- Cryptocurrency miners
- Process injection
- Process hollowing
- Reflective DLL loading

### Credential Theft
- SSH key theft
- AWS/Azure/GCP credential access
- Browser cookie/password theft
- Git credential harvesting
- Database credential access
- Package registry token theft
- History file harvesting

### Persistence Mechanisms
- Git hooks manipulation
- Shell profile modifications
- Cron job persistence
- Systemd service persistence
- macOS Launch persistence
- Windows Task Scheduler
- Windows Registry manipulation
- Windows Service installation
- WMI event subscriptions

### Network & Exfiltration
- Suspicious network operations
- DNS operations and tunneling
- ICMP exfiltration
- WebSocket connections
- Cloud metadata endpoint access

### Obfuscation
- Base64 encoding/decoding
- Character code construction
- Multiple encoding chains
- Compressed payloads
- Unicode tricks (bidirectional, Cyrillic)
- JavaScript obfuscation
- PowerShell obfuscation

### Supply Chain
- npm lifecycle script abuse
- Package manager in code
- Typosquatting detection
- Suspicious dependencies

### Cloud & Containers
- Docker socket abuse
- Kubernetes token access
- Cloud metadata endpoints
- Dockerfile risks

### Anti-Analysis
- Anti-debugging techniques
- VM/Sandbox detection

## Technical Improvements

### Code Simplification
- Extracted complex logic into focused helper functions
- Improved readability and maintainability
- Better separation of concerns
- Fixed bugs (negation in ignore patterns)

### Cross-Platform Support
- Windows (AMD64, ARM64)
- Linux (AMD64, ARM64, ARMv7)
- macOS (Intel, Apple Silicon)
- BSD variants

### Performance
- Fast compiled Go binary
- Efficient file scanning
- Smart binary file detection
- Optimized pattern matching
