#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

let COMPROMISED_PACKAGES = {};
let USE_EMOJIS = true;
let LOG_FILE = null;
let AUTO_LOG = true;

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

function compareVersions(v1, v2) {
  if (v1.major !== v2.major) return v1.major - v2.major;
  if (v1.minor !== v2.minor) return v1.minor - v2.minor;
  return v1.patch - v2.patch;
}

function isVersionCompromised(versionRange, compromisedVersions) {
  if (!versionRange || !compromisedVersions || compromisedVersions.length === 0) {
    return false;
  }

  const range = versionRange.trim();

  if (/^\d+\.\d+\.\d+/.test(range)) {
    const exactVersion = range.match(/^(\d+\.\d+\.\d+)/)[1];
    return compromisedVersions.includes(exactVersion);
  }

  if (range.startsWith('^')) {
    const versionMatch = range.substring(1).match(/^(\d+\.\d+\.\d+)/);
    if (!versionMatch) return false;
    const baseVersionStr = versionMatch[1];

    const baseVersion = parseVersion(baseVersionStr);
    if (!baseVersion) return false;

    return compromisedVersions.some(compromisedVer => {
      const compVer = parseVersion(compromisedVer);
      if (!compVer) return false;

      return compVer.major === baseVersion.major &&
        compareVersions(compVer, baseVersion) >= 0;
    });
  }

  if (range.startsWith('~')) {
    const versionMatch = range.substring(1).match(/^(\d+\.\d+\.\d+)/);
    if (!versionMatch) return false;
    const baseVersionStr = versionMatch[1];

    const baseVersion = parseVersion(baseVersionStr);
    if (!baseVersion) return false;

    return compromisedVersions.some(compromisedVer => {
      const compVer = parseVersion(compromisedVer);
      if (!compVer) return false;

      return compVer.major === baseVersion.major &&
        compVer.minor === baseVersion.minor &&
        compVer.patch >= baseVersion.patch;
    });
  }

  const versionMatch = range.match(/(\d+\.\d+\.\d+)/);
  if (versionMatch) {
    return compromisedVersions.includes(versionMatch[1]);
  }

  return false;
}

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

    if (packageInfo.dependencies) {
      const nestedDeps = parseV6Dependencies(packageInfo.dependencies, packagePath);
      Object.assign(result, nestedDeps);
    }
  });

  return result;
}

function checkForCompromisedPackages(filePath) {
  const successIcon = USE_EMOJIS ? '✅' : '[OK]';
  const warningIcon = USE_EMOJIS ? '⚠️' : '[WARNING]';

  console.log(`\nAnalyzing: ${filePath}`);
  console.log("=".repeat(50));

  try {
    const fileContent = fs.readFileSync(filePath, "utf8");
    const packageData = JSON.parse(fileContent);

    const result = {
      file: filePath,
      found: [],
      total: 0,
      safe: true,
    };

    if (path.basename(filePath).includes("package-lock.json")) {
      let packagesToCheck = {};

      if (packageData.packages) {
        packagesToCheck = packageData.packages;
      }
      else if (packageData.dependencies) {
        packagesToCheck = parseV6Dependencies(packageData.dependencies);
      }

      Object.keys(packagesToCheck).forEach((packagePath) => {
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

    result.total = result.found.length;
    result.safe = result.total === 0;

    return result;
  } catch (error) {
    return {
      file: filePath,
      error: error.message,
      safe: false,
    };
  }
}

function displayResults(result) {
  const successIcon = USE_EMOJIS ? '✅' : '[OK]';
  const warningIcon = USE_EMOJIS ? '⚠️' : '[WARNING]';

  if (result.error) {
    console.log(`Error analyzing ${result.file}:`);
    console.log(`   ${result.error}`);
    return;
  }

  if (result.safe) {
    console.log(`${successIcon} No compromised packages found!`);
  } else {
    console.log(`${warningIcon} ${result.total} compromised package(s) found:`);
    console.log();

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

function writeToLog(message) {
  if (LOG_FILE) {
    fs.appendFileSync(LOG_FILE, message + '\n');
  }
}

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

function showUsage() {
  console.log("Usage: compromised-npm-packages-checker [options] <path-to-package-file>");
  console.log("");
  console.log("Options:");
  console.log("  --no-emoji       Disable emoji output (for CI/CD environments)");
  console.log("  --no-log         Disable automatic log file creation");
  console.log("  --log <file>     Save scan results to specific log file (disables auto-log)");
  console.log("  --output <file>  Same as --log (alias)");
  console.log("  --help, -h       Show this help message");
  console.log("");
  console.log("Examples:");
  console.log("  node check-compromised-packages.js package.json");
  console.log("  node check-compromised-packages.js --no-log package.json");
  console.log("  node check-compromised-packages.js --log custom.txt package.json");
  console.log("");
  console.log("Auto-logging: By default, creates timestamped log files automatically.");
  console.log("");
  console.log("Requirements:");
  console.log("  - compromised.json file must be in the same directory as this script");
}

function main() {
  const args = process.argv.slice(2);
  let filePath = null;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--help' || arg === '-h') {
      showUsage();
      process.exit(0);
    } else if (arg === '--no-emoji') {
      USE_EMOJIS = false;
    } else if (arg === '--no-log') {
      AUTO_LOG = false;
    } else if (arg === '--log' || arg === '--output') {
      if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        LOG_FILE = args[i + 1];
        AUTO_LOG = false;
        i++;
      } else {
        console.error(`Error: ${arg} requires a file path`);
        process.exit(1);
      }
    } else if (!arg.startsWith('--') && !filePath) {
      filePath = arg;
    }
  }

  if (!filePath) {
    showUsage();
    process.exit(1);
  }

  if (!fs.existsSync(filePath)) {
    console.log(`File not found: ${filePath}`);
    process.exit(1);
  }

  const compromisedJsonPath = path.join(__dirname, 'compromised.json');
  if (!fs.existsSync(compromisedJsonPath)) {
    console.error(`Error: compromised.json not found at ${compromisedJsonPath}`);
    console.error('Please ensure compromised.json is in the same directory as this script.');
    process.exit(1);
  }

  COMPROMISED_PACKAGES = loadCompromisedPackages(compromisedJsonPath);

  if (AUTO_LOG && !LOG_FILE) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('.')[0];
    const baseFileName = path.basename(filePath, path.extname(filePath));
    LOG_FILE = `scan-${baseFileName}-${timestamp}.txt`;
  }

  if (LOG_FILE) {
    try {
      initializeLogFile(LOG_FILE, filePath);
      console.log(`📝 Log file initialized: ${LOG_FILE}`);
    } catch (error) {
      console.error(`Error initializing log file: ${error.message}`);
      process.exit(1);
    }
  }

  const result = checkForCompromisedPackages(filePath);
  displayResults(result);

  if (LOG_FILE) {
    logScanResults(result);
    console.log(`📄 Scan results saved to: ${LOG_FILE}`);
  }

  if (!result.safe) {
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  checkForCompromisedPackages,
  isVersionCompromised,
  parseVersion,
  compareVersions,
  loadCompromisedPackages
};
