#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

// Global configuration
let COMPROMISED_PACKAGES = {};
let USE_EMOJIS = true;

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
 * Display usage information
 */
function showUsage() {
  console.log("Usage: shaihulud-dependency-check [options] <path-to-package-file>");
  console.log("");
  console.log("Options:");
  console.log("  --no-emoji    Disable emoji output (for CI/CD environments)");
  console.log("  --help, -h    Show this help message");
  console.log("");
  console.log("Examples:");
  console.log("  node check-compromised-packages.js package.json");
  console.log("  node check-compromised-packages.js package-lock.json");
  console.log("  node check-compromised-packages.js --no-emoji frontend/package-lock.json");
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

  // Run the analysis and display results
  const result = checkForCompromisedPackages(filePath);
  displayResults(result);

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
