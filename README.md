# Compromised NPM Packages Checker

A Node.js security tool that identifies compromised NPM packages by comparing installed package versions against a curated database of known malicious releases. This tool performs version-specific detection to avoid false positives from safe versions of the same packages.

## What This Tool Does

- **Version-specific detection**: Compares installed package versions against a database of 252+ confirmed compromised package versions from multiple NPM supply chain attacks (including Shai-Hulud, s1ngularity, and popular packages campaigns)
- **Comprehensive scanning**: Analyzes both `package.json` (dependencies, devDependencies, peerDependencies, optionalDependencies) and `package-lock.json` (complete dependency tree)
- **NPM lockfile compatibility**: Supports both npm v6 (`dependencies` structure) and npm v7+ (`packages` structure) lockfile formats
- **Semver range handling**: Processes common version ranges (`^`, `~`, exact versions) without external dependencies
- **CI/CD integration**: Returns appropriate exit codes (0 for safe, 1 for compromised packages found)
- **External data source**: Loads compromised package data from `compromised.json` for easy maintenance and updates

## What This Tool Does Not Do

- **Runtime analysis**: Does not detect suspicious postinstall scripts, hash anomalies, or behavioral supply chain indicators beyond version matching
- **Complete security coverage**: Does not replace comprehensive security scanners, SAST tools, or runtime protection mechanisms  
- **Real-time threat detection**: Security coverage is limited to the currency of the maintained compromised package database
- **Dependency vulnerability scanning**: Does not identify known CVEs or security advisories unrelated to supply chain compromise

## Platform Compatibility

- **Cross-platform**: Runs on Windows, Linux, and macOS
- **Zero external dependencies**: Uses only Node.js built-in modules (`fs`, `path`, `https`)
- **Flexible deployment**: Direct execution, NPX usage, or module integration
- **CI/CD ready**: Designed for automated pipeline integration with proper exit codes

## Installation & Prerequisites

**Requirements:**
- Node.js 12.0.0 or higher

**Required files:**
- `check-compromised-packages.js` - Main script
- `compromised.json` - Database of compromised packages

### Method 1: Clone Repository (Recommended)

```bash
git clone <repository-url>
cd compromised-npm-packages-checker
chmod +x check-compromised-packages.js
```

### Method 2: Direct Download

```bash
curl -O https://raw.githubusercontent.com/your-repo/compromised-npm-packages-checker/main/check-compromised-packages.js
curl -O https://raw.githubusercontent.com/your-repo/compromised-npm-packages-checker/main/compromised.json
chmod +x check-compromised-packages.js
```

### Method 3: NPX (After Publishing)

```bash
npx compromised-npm-packages-checker package-lock.json
```

## Usage

### Basic Usage

```bash
node check-compromised-packages.js <path-to-package-file>
```

### Examples

```bash
# Scan package.json (direct dependencies)
node check-compromised-packages.js package.json

# Scan package-lock.json (complete dependency tree - recommended)
node check-compromised-packages.js package-lock.json

# Disable emoji output for CI/CD environments
node check-compromised-packages.js --no-emoji package-lock.json

# Scan files in subdirectories
node check-compromised-packages.js frontend/package-lock.json
node check-compromised-packages.js backend/package.json
```

### Command Line Options

```bash
--no-emoji    Disable emoji output for CI/CD environments
--help, -h    Show usage information
```

## Output Examples

### Safe Project
```
Analyzing: package-lock.json
==================================================
✅ No compromised packages found!
```

### Compromised Packages Detected
```
Analyzing: package-lock.json
==================================================
⚠️  3 compromised package(s) found:

   1. chalk
      Installed Version: 5.6.1
      Status: COMPROMISED
      Compromised Versions: 5.6.1
      Path: node_modules/chalk

   2. debug  
      Installed Version: 4.4.2
      Status: COMPROMISED
      Compromised Versions: 4.4.2
      Path: node_modules/debug

   3. @ctrl/tinycolor
      Installed Version: 4.1.1
      Status: COMPROMISED
      Compromised Versions: 4.1.1, 4.1.2
      Path: node_modules/@ctrl/tinycolor

⚠️  SECURITY ADVISORY: These packages contain malicious code.
   Recommended action: Update to a safe version or remove the package.
```

### CI/CD Mode (--no-emoji)
```
Analyzing: package-lock.json
==================================================
[WARNING] 2 compromised package(s) found:

   1. chalk
      Installed Version: 5.6.1
      Status: COMPROMISED
      Compromised Versions: 5.6.1
      Path: node_modules/chalk

[WARNING] SECURITY ADVISORY: These packages contain malicious code.
   Recommended action: Update to a safe version or remove the package.
```

## Exit Codes

- **0**: No compromised packages found or help displayed
- **1**: Compromised packages detected, file not found, or error occurred

## CI/CD Integration

### GitHub Actions Example
```yaml
- name: Check for compromised packages
  run: |
    node check-compromised-packages.js --no-emoji package-lock.json
    if [ $? -eq 1 ]; then
      echo "::error::Compromised NPM packages detected"
      exit 1
    fi
```

### Shell Script Integration
```bash
#!/bin/bash
node check-compromised-packages.js --no-emoji package-lock.json
if [ $? -eq 1 ]; then
    echo "Build failed: Compromised packages detected"
    exit 1
fi
echo "Security check passed"
```

## Database Updates

The tool uses an external `compromised.json` file containing the package database:

```bash
# Update to latest compromised packages list
node update-compromised-list.js

# This downloads the latest list from GitHub and updates compromised.json
# Previous version is backed up as compromised-old.json.bak
```

**Current Database Coverage:**
- **239 compromised packages** from Shai-Hulud supply chain attacks
- **Critical packages**: `chalk@5.6.1`, `debug@4.4.2` (September 8, 2025 attack with 2+ billion weekly downloads)
- **Extended campaign**: `@ctrl/*`, `@nativescript-community/*`, `@teselagen/*`, `@crowdstrike/*`, `@operato/*`, `@things-factory/*` namespaces
- **Data source**: [Cobenian/shai-hulud-detect](https://github.com/Cobenian/shai-hulud-detect)

## Technical Implementation

### Supported Package File Formats

- **package.json**: Scans `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`
- **package-lock.json v6**: Processes `dependencies` structure recursively
- **package-lock.json v7+**: Processes flat `packages` structure

### Version Range Processing

The tool handles common semver ranges without external dependencies:

- **Exact versions**: `1.2.3`
- **Caret ranges**: `^1.2.3` (extracts base version)
- **Tilde ranges**: `~1.2.3` (extracts base version)
- **Complex ranges**: Simplified processing focused on primary version

## Limitations

### Detection Scope
- **Version-based only**: Only detects packages matching exact compromised versions in the database
- **No behavioral analysis**: Does not analyze package behavior, file contents, or network activity
- **No CVE detection**: Does not identify traditional vulnerabilities or security advisories
- **Database dependency**: Detection accuracy depends on database currency and completeness

### Technical Constraints
- **Lockfile dependency**: Most accurate results require `package-lock.json` analysis
- **Network independence**: Does not query external APIs or registries during scanning
- **Static analysis**: No dynamic code execution or sandbox analysis

### Maintenance Requirements
- **Manual updates**: Compromised package database requires manual updates via `update-compromised-list.js`
- **External dependency**: Relies on upstream [Cobenian/shai-hulud-detect](https://github.com/Cobenian/shai-hulud-detect) for data accuracy

## Module Integration

The tool can be imported as a Node.js module:

```javascript
const { checkForCompromisedPackages, isVersionCompromised } = require('./check-compromised-packages.js');

const result = checkForCompromisedPackages('package-lock.json');
if (!result.safe) {
  console.log(`Found ${result.total} compromised packages`);
  result.found.forEach(pkg => {
    console.log(`${pkg.name}@${pkg.version} is compromised`);
  });
}
```

## Testing

The project includes a comprehensive test suite covering various scenarios:

```bash
# Run all tests
cd testcases
node run-tests.js

# Run individual test categories
node ../check-compromised-packages.js safe/clean-package.json        # Should return 0
node ../check-compromised-packages.js compromised/chalk-attack.json  # Should return 1
node ../check-compromised-packages.js mixed/partial-compromise.json  # Should return 1
```

**Test Coverage:**
- ✅ Safe packages (no compromised versions)
- ⚠️ Compromised packages (various attack vectors)
- 🔄 Mixed scenarios (partial compromise)
- 🧩 Edge cases (empty dependencies, complex versions)
- 📦 Both npm v6 and v7+ lockfile formats

## Contributing

- **Database updates**: Submit discoveries to [Cobenian/shai-hulud-detect](https://github.com/Cobenian/shai-hulud-detect)
- **Bug reports**: Create issues with reproduction steps and environment details
- **Feature requests**: Propose enhancements with specific use cases

## License

MIT License - See LICENSE file for details.

---

**Security Notice**: This tool provides point-in-time detection based on known compromised package versions. It should be used as part of a comprehensive security strategy including dependency scanning, SAST, runtime protection, and regular security audits.
