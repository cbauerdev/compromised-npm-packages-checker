#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

// Global configuration
let COMPROMISED_PACKAGES = {};
let USE_EMOJIS = true;
let LOG_FILE = null;

/**
 * Parse a semantic version string into its components
 * @param {string} version - Version string (e.g., "1.2.3")
 * @returns {Object|null} - Object with major, minor, patch numbers or null if invalid
 */
function parseVersion(version) {
  if (!version || typeof version !== 'string') return null;

  const match = version.match(/^(\d+)\.(\d+)\.(\d+)(?:-.*)?(?:\+.*)?$/);
  if (!match) return null;

  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2], 10),
    patch: parseInt(match[3], 10)
  };
}

/**
 * Compare two semantic versions
 * @param {Object} v1 - First version object
 * @param {Object} v2 - Second version object
 * @returns {number} - -1 if v1 < v2, 0 if equal, 1 if v1 > v2
 */
function compareVersions(v1, v2) {
  if (v1.major !== v2.major) return v1.major - v2.major;
  if (v1.minor !== v2.minor) return v1.minor - v2.minor;
  return v1.patch - v2.patch;
}

/**
 * Check if an installed version satisfies a semver range and matches compromised versions
 * @param {string} versionRange - Version range from package.json (e.g., "^1.2.3", "~1.2.3", "1.2.3")
 * @param {string[]} compromisedVersions - Array of known compromised versions
 * @returns {boolean} - True if any satisfying version is compromised
 */
function isVersionCompromised(versionRange, compromisedVersions) {
  if (!versionRange || !compromisedVersions || compromisedVersions.length === 0) {
    return false;
  }

  // Remove whitespace
  const range = versionRange.trim();

  // Handle exact version (no prefix)
  if (/^\d+\.\d+\.\d+/.test(range)) {
    const exactVersion = range.match(/^(\d+\.\d+\.\d+)/)[1];
    return compromisedVersions.includes(exactVersion);
  }

  // Handle caret range (^1.2.3 allows 1.x.x but not 2.0.0)
  if (range.startsWith('^')) {
    const versionMatch = range.substring(1).match(/^(\d+\.\d+\.\d+)/);
    if (!versionMatch) return false;
    const baseVersionStr = versionMatch[1];

    const baseVersion = parseVersion(baseVersionStr);
    if (!baseVersion) return false;

    // Check if any compromised version satisfies the caret range
    return compromisedVersions.some(compromisedVer => {
      const compVer = parseVersion(compromisedVer);
      if (!compVer) return false;

      // Caret allows same major version
      return compVer.major === baseVersion.major &&
        compareVersions(compVer, baseVersion) >= 0;
    });
  }

  // Handle tilde range (~1.2.3 allows 1.2.x but not 1.3.0)
  if (range.startsWith('~')) {
    const versionMatch = range.substring(1).match(/^(\d+\.\d+\.\d+)/);
    if (!versionMatch) return false;
    const baseVersionStr = versionMatch[1];

    const baseVersion = parseVersion(baseVersionStr);
    if (!baseVersion) return false;

    // Check if any compromised version satisfies the tilde range
    return compromisedVersions.some(compromisedVer => {
      const compVer = parseVersion(compromisedVer);
      if (!compVer) return false;

      // Tilde allows same major.minor version
      return compVer.major === baseVersion.major &&
        compVer.minor === baseVersion.minor &&
        compVer.patch >= baseVersion.patch;
    });
  }

  // Handle other prefixes (>=, >, etc.) - treat as exact for simplicity
  const versionMatch = range.match(/(\d+\.\d+\.\d+)/);
  if (versionMatch) {
    return compromisedVersions.includes(versionMatch[1]);
  }

  return false;
}

/**
 * Load compromised packages from external JSON file
 * @param {string} jsonPath - Path to compromised.json file
 * @returns {Object} - Compromised packages object
 */
function loadCompromisedPackages(jsonPath) {
  try {
    const fullPath = path.resolve(jsonPath);
    const jsonContent = fs.readFileSync(fullPath, 'utf8');
    const data = JSON.parse(jsonContent);
    return data.packages || {};
  } catch (error) {
    console.error(`Error loading compromised packages from ${jsonPath}:`, error.message);
    process.exit(1);
  }
}

/**
 * Parse npm v6 lockfile dependencies recursively
 * @param {Object} deps - Dependencies object from npm v6 lockfile
 * @param {string} prefix - Current path prefix for nested dependencies
 * @returns {Object} - Flattened dependencies object
 */
function parseV6Dependencies(deps, prefix = '') {
  const result = {};

  if (!deps || typeof deps !== 'object') return result;

  Object.keys(deps).forEach(packageName => {
    const packageInfo = deps[packageName];
    const packagePath = prefix ? `${prefix}/node_modules/${packageName}` : `node_modules/${packageName}`;

    if (packageInfo.version) {
      result[packagePath] = {
        version: packageInfo.version,
        ...packageInfo
      };
    }

    // Recursively process nested dependencies
    if (packageInfo.dependencies) {
      const nestedDeps = parseV6Dependencies(packageInfo.dependencies, packagePath);
      Object.assign(result, nestedDeps);
    }
  });

  return result;
}

/**
 * Analyzes a package.json or package-lock.json for compromised packages
 * @param {string} filePath - Path to the file to be analyzed
 * @returns {Object} Analysis result object
 */
function checkForCompromisedPackages(filePath) {
  const successIcon = USE_EMOJIS ? '✅' : '[OK]';
  const warningIcon = USE_EMOJIS ? '⚠️' : '[WARNING]';

  // Display analysis header
  console.log(`\nAnalyzing: ${filePath}`);
  console.log("=".repeat(50));

  try {
    // Read and parse the file
    const fileContent = fs.readFileSync(filePath, "utf8");
    const packageData = JSON.parse(fileContent);

    // Initialize result object
    const result = {
      file: filePath,
      found: [],
      total: 0,
      safe: true,
    };

    // Analyze differently based on file type
    if (path.basename(filePath).includes("package-lock.json")) {
      let packagesToCheck = {};

      // Handle npm v7+ format (packages field)
      if (packageData.packages) {
        packagesToCheck = packageData.packages;
      }
      // Handle npm v6 format (dependencies field)
      else if (packageData.dependencies) {
        packagesToCheck = parseV6Dependencies(packageData.dependencies);
      }

      // Check all packages in lockfile
      Object.keys(packagesToCheck).forEach((packagePath) => {
        // Extract package name from path
        const packageName = packagePath.replace(/^node_modules\//, '').replace(/\/node_modules\/.*$/, '');

        if (COMPROMISED_PACKAGES[packageName]) {
          const installedVersion = packagesToCheck[packagePath].version || "unknown";
          const compromisedVersions = COMPROMISED_PACKAGES[packageName];

          if (isVersionCompromised(installedVersion, compromisedVersions)) {
            result.found.push({
              name: packageName,
              path: packagePath,
              version: installedVersion,
              compromisedVersions: compromisedVersions,
              status: "COMPROMISED"
            });
          }
        }
      });
    } else {
      // package.json: search through different dependency types
      const dependencyTypes = [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
      ];

      dependencyTypes.forEach((depType) => {
        if (packageData[depType]) {
          Object.keys(packageData[depType]).forEach((packageName) => {
            if (COMPROMISED_PACKAGES[packageName]) {
              const versionRange = packageData[depType][packageName];
              const compromisedVersions = COMPROMISED_PACKAGES[packageName];

              if (isVersionCompromised(versionRange, compromisedVersions)) {
                result.found.push({
                  name: packageName,
                  version: versionRange,
                  type: depType,
                  compromisedVersions: compromisedVersions,
                  status: "COMPROMISED"
                });
              }
            }
          });
        }
      });
    }

    // Update result totals and safety status
    result.total = result.found.length;
    result.safe = result.total === 0;

    return result;
  } catch (error) {
    // Return error result if file parsing fails
    return {
      file: filePath,
      error: error.message,
      safe: false,
    };
  }
}

/**
 * Displays the analysis results in a formatted way
 * @param {Object} result - Analysis result object
 */
function displayResults(result) {
  const successIcon = USE_EMOJIS ? '✅' : '[OK]';
  const warningIcon = USE_EMOJIS ? '⚠️' : '[WARNING]';

  // Handle error cases
  if (result.error) {
    console.log(`Error analyzing ${result.file}:`);
    console.log(`   ${result.error}`);
    return;
  }

  // Display success or warning messages
  if (result.safe) {
    console.log(`${successIcon} No compromised packages found!`);
  } else {
    console.log(`${warningIcon} ${result.total} compromised package(s) found:`);
    console.log();

    // List each found compromised package with details
    result.found.forEach((pkg, index) => {
      console.log(`   ${index + 1}. ${pkg.name}`);
      console.log(`      Installed Version: ${pkg.version}`);
      console.log(`      Status: ${pkg.status}`);
      console.log(`      Compromised Versions: ${pkg.compromisedVersions.join(', ')}`);
      if (pkg.type) console.log(`      Dependency Type: ${pkg.type}`);
      if (pkg.path) console.log(`      Path: ${pkg.path}`);
      console.log();
    });

    console.log(`${warningIcon} SECURITY ADVISORY: These packages contain malicious code.`);
    console.log(`   Recommended action: Update to a safe version or remove the package.`);
  }
}

/**
 * Write log entry to file if logging is enabled
 * @param {string} message - Message to log
 */
function writeToLog(message) {
  if (LOG_FILE) {
    fs.appendFileSync(LOG_FILE, message + '\n');
  }
}

/**
 * Initialize log file with header
 * @param {string} filePath - Path to the log file
 * @param {string} scanFile - File being scanned
 */
function initializeLogFile(filePath, scanFile) {
  const timestamp = new Date().toISOString();
  const header = [
    `Compromised NPM Packages Scan Report`,
    `Generated: ${timestamp}`,
    `Scanned file: ${scanFile}`,
    `Tool: compromised-npm-packages-checker`,
    `Database: ${Object.keys(COMPROMISED_PACKAGES).length} known compromised packages`,
    `${'='.repeat(80)}`,
    ''
  ].join('\n');
  
  fs.writeFileSync(filePath, header);
}

/**
 * Log scan results in structured text format
 * @param {Object} result - Scan result object
 */
function logScanResults(result) {
  if (!LOG_FILE) return;

  const lines = [];
  
  if (result.found.length === 0) {
    lines.push('SCAN STATUS: CLEAN');
    lines.push('No compromised packages detected.');
  } else {
    lines.push(`SCAN STATUS: ${result.found.length} COMPROMISED PACKAGE(S) FOUND`);
    lines.push('');
    lines.push('DETAILS:');
    
    result.found.forEach((pkg, index) => {
      lines.push(`${index + 1}. Package: ${pkg.name}`);
      lines.push(`   Version: ${pkg.version}`);
      lines.push(`   Compromised versions: ${pkg.compromisedVersions.join(', ')}`);
      lines.push(`   Risk level: HIGH`);
      lines.push('');
    });
  }
  
  lines.push(`Total packages scanned: ${result.total}`);
  lines.push(`Compromised packages found: ${result.found.length}`);
  lines.push('');
  lines.push('RECOMMENDATIONS:');
  
  if (result.found.length === 0) {
    lines.push('- Your dependencies appear clean from known compromised packages.');
    lines.push('- Continue monitoring for new security advisories.');
  } else {
    lines.push('- IMMEDIATE ACTION REQUIRED: Remove or update compromised packages.');
    lines.push('- Review your package-lock.json for any suspicious packages.');
    lines.push('- Consider running additional security scans.');
    result.found.forEach(pkg => {
      lines.push(`- UPDATE: ${pkg.name} (currently ${pkg.version})`);
    });
  }
  
  lines.push('');
  lines.push(`${'='.repeat(80)}`);
  lines.push('');
  
  writeToLog(lines.join('\n'));
}

/**
 * Display usage information
 */
function showUsage() {
  console.log("Usage: compromised-npm-packages-checker [options] <path-to-package-file>");
  console.log("");
  console.log("Options:");
  console.log("  --no-emoji       Disable emoji output (for CI/CD environments)");
  console.log("  --log <file>     Save scan results to log file (txt format)");
  console.log("  --output <file>  Same as --log (alias)");
  console.log("  --help, -h       Show this help message");
  console.log("");
  console.log("Examples:");
  console.log("  node check-compromised-packages.js package.json");
  console.log("  node check-compromised-packages.js package-lock.json");
  console.log("  node check-compromised-packages.js --no-emoji frontend/package-lock.json");
  console.log("  node check-compromised-packages.js --log scan-results.txt package.json");
  console.log("  node check-compromised-packages.js --output report.txt package-lock.json");
  console.log("");
  console.log("Note: If you get NPX errors, the package may not be published yet.");
  console.log("      See INSTALL.md for alternative installation methods.");
  console.log("");
  console.log("Requirements:");
  console.log("  - compromised.json file must be in the same directory as this script");
}

/**
 * Main function - handles command line arguments and orchestrates the analysis
 */
function main() {
  // Parse command line arguments
  const args = process.argv.slice(2);
  let filePath = null;

  // Process arguments
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--help' || arg === '-h') {
      showUsage();
      process.exit(0);
    } else if (arg === '--no-emoji') {
      USE_EMOJIS = false;
    } else if (arg === '--log' || arg === '--output') {
      // Get the log file path from next argument
      if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        LOG_FILE = args[i + 1];
        i++; // Skip the log file argument in next iteration
      } else {
        console.error(`Error: ${arg} requires a file path`);
        process.exit(1);
      }
    } else if (!arg.startsWith('--') && !filePath) {
      filePath = arg;
    }
  }

  // Show usage if no file path provided
  if (!filePath) {
    showUsage();
    process.exit(1);
  }

  // Check if file exists
  if (!fs.existsSync(filePath)) {
    console.log(`File not found: ${filePath}`);
    process.exit(1);
  }

  // Load compromised packages data
  const compromisedJsonPath = path.join(__dirname, 'compromised.json');
  if (!fs.existsSync(compromisedJsonPath)) {
    console.error(`Error: compromised.json not found at ${compromisedJsonPath}`);
    console.error('Please ensure compromised.json is in the same directory as this script.');
    process.exit(1);
  }

  COMPROMISED_PACKAGES = loadCompromisedPackages(compromisedJsonPath);

  // Initialize log file if specified
  if (LOG_FILE) {
    try {
      initializeLogFile(LOG_FILE, filePath);
      console.log(`📝 Log file initialized: ${LOG_FILE}`);
    } catch (error) {
      console.error(`Error initializing log file: ${error.message}`);
      process.exit(1);
    }
  }

  // Run the analysis and display results
  const result = checkForCompromisedPackages(filePath);
  displayResults(result);

  // Log results if logging is enabled
  if (LOG_FILE) {
    logScanResults(result);
    console.log(`📄 Scan results saved to: ${LOG_FILE}`);
  }

  // Set appropriate exit code (1 if compromised packages found or error occurred)
  if (!result.safe) {
    process.exit(1);
  }
}

// Execute the script if run directly (not imported as module)
if (require.main === module) {
  main();
}

// Export functions for use as a module
module.exports = {
  checkForCompromisedPackages,
  isVersionCompromised,
  parseVersion,
  compareVersions,
  loadCompromisedPackages
};
