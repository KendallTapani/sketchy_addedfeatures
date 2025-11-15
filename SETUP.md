# Setup Guide

Quick setup instructions to get sketchy running and install the git hook.

## Setup Steps

### 1. Run Sketchy (First Time)

```bash
cd sketchy
.\sketchy.exe
```

When prompted, type `y` to install the git hook, then choose option `2` (Global).

### 2. Configure Git (If You Chose Global Hook)

After installation, run the command shown (it will look like this):

```bash
git config --global init.templateDir ~/.git-template
```

### 3. Test the Hook

Clone a test repository to verify the hook works:

```bash
cd ..
git clone https://github.com/octocat/Hello-World.git test-scan
```

You should see sketchy run automatically after the clone completes!

## Manual Hook Installation

If you skipped the prompt:

```bash
cd sketchy
.\sketchy.exe install-hook
```

Choose option `2` (Global), then run the git config command shown.

## Test Scanning

```bash
cd sketchy
.\sketchy.exe -path test-files/test
```

Should find 60+ issues.

## That's It!

Your setup is complete. The hook will now automatically scan all repositories you clone.
