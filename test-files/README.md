# Test Files

This directory contains test files used to verify sketchy's detection capabilities.

## Structure

- `test/` - Basic test files for common malicious patterns
- `test-files/` - Advanced test files including Dockerfiles, GitHub Actions workflows, and complex attack patterns

## Running Tests

From the `sketchy/` directory:

```bash
# Run all tests
make test

# Scan test directory
make run

# Scan with high-risk only
make run-high
```

Or directly:

```bash
# From sketchy directory
./sketchy.exe -path test-files/test/
./sketchy.exe -path test-files/test-files/
```

## Test Files Description

### test/
- `test_malicious.py` - Common Python malicious patterns
- `test_localhost.py` - Tests localhost filtering (should NOT trigger on 127.0.0.1)
- `test_windows.ps1` - Windows PowerShell patterns
- `test_windows_advanced.ps1` - Advanced Windows attack patterns
- `test_windows_batch.bat` - Windows batch file patterns
- `test_windows_csharp.cs` - C# Windows patterns

### test-files/
- `test_malicious.py` - Advanced Python patterns
- `test_advanced_malicious.py` - Complex multi-stage attack patterns
- `test_Dockerfile` - Dockerfile-specific risks
- `test_workflow.yml` - GitHub Actions workflow risks

## Note

These test files contain intentionally malicious-looking patterns for testing purposes. They are safe to scan but should not be executed.

