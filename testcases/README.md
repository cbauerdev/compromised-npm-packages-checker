# Test Cases

This directory contains various test cases to validate the compromised-npm-packages-checker functionality.

## Test Structure

- `safe/` - Test cases with no compromised packages
- `compromised/` - Test cases with known compromised packages
- `mixed/` - Test cases with both safe and compromised packages
- `edge-cases/` - Special cases and edge scenarios

## Running Tests

```bash
# Test safe packages (should return exit code 0)
node ../check-compromised-packages.js safe/clean-package.json
node ../check-compromised-packages.js safe/clean-lockfile.json

# Test compromised packages (should return exit code 1)
node ../check-compromised-packages.js compromised/chalk-attack.json
node ../check-compromised-packages.js compromised/ctrl-packages.json

# Test mixed scenarios
node ../check-compromised-packages.js mixed/partial-compromise.json
```

## Test Results

Each test case includes:
- Input file (package.json or package-lock.json)
- Expected outcome (safe/compromised)
- Expected packages to be detected
- Exit code expectation