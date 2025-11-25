#!/usr/bin/env node

const fs = require('fs');
const https = require('https');

const SOURCES = {
  // Original source (still useful for legacy data)
  legacy: {
    url: 'https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt',
    enabled: true,
    parser: 'legacy'
  },
  // New Wiz Security CSV source
  wizCsv: {
    url: 'https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv',
    enabled: true,
    parser: 'csv'
  },
  // Google Sheets CSV export URL
  // To use: Make your Google Sheet public and use format: 
  // https://docs.google.com/spreadsheets/d/{SHEET_ID}/export?format=csv&gid={GID}
  // Or use the published CSV URL format:
  // https://docs.google.com/spreadsheets/d/e/{SHEET_ID}/pub?gid={GID}&single=true&output=csv
  googleSheets: {
    url: 'https://docs.google.com/spreadsheets/d/16aw6s7mWoGU7vxBciTEZSaR5HaohlBTfVirvI-PypJc/export?format=csv&gid=1289659284',
    enabled: false, // Disabled - using local CSV instead
    parser: 'csv'
  },
  
  // Local CSV file alternative (if Google Sheets doesn't work)
  localCsv: {
    url: './Public Sha1-Hulud - Koi.csv', // Local file path
    enabled: true, // Enable the local CSV file
    parser: 'csv',
    isLocal: true
  }
};

const COMPROMISED_JSON_FILE = 'compromised.json';

function fetchUrl(url, maxRedirects = 3) {
  return new Promise((resolve, reject) => {
    function makeRequest(requestUrl, redirectCount) {
      if (redirectCount >= maxRedirects) {
        reject(new Error(`Too many redirects (${redirectCount})`));
        return;
      }

      https.get(requestUrl, (response) => {
        // Handle redirects
        if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
          console.log(`   🔄 Following redirect to: ${response.headers.location}`);
          makeRequest(response.headers.location, redirectCount + 1);
          return;
        }

        // Handle non-success status codes
        if (response.statusCode < 200 || response.statusCode >= 300) {
          reject(new Error(`HTTP ${response.statusCode}: ${response.statusMessage}`));
          return;
        }

        let data = '';
        
        response.on('data', (chunk) => {
          data += chunk;
        });
        
        response.on('end', () => {
          resolve(data);
        });
      }).on('error', (error) => {
        reject(error);
      });
    }

    makeRequest(url, 0);
  });
}

async function downloadAndMerge() {
  let existingData = { packages: {} };
  if (fs.existsSync(COMPROMISED_JSON_FILE)) {
    existingData = JSON.parse(fs.readFileSync(COMPROMISED_JSON_FILE, 'utf8'));
    console.log(`📖 Loaded existing database with ${Object.keys(existingData.packages).length} packages`);
  }

  const mergedPackages = { ...existingData.packages };
  let totalAddedCount = 0;
  let totalUpdatedCount = 0;

  console.log('🔄 Fetching from multiple sources...\n');

  // Process each enabled source
  for (const [sourceName, sourceConfig] of Object.entries(SOURCES)) {
    if (!sourceConfig.enabled) {
      console.log(`⏭️  Skipping ${sourceName} (disabled)`);
      continue;
    }

    try {
      console.log(`📥 Downloading from ${sourceName}...`);
      
      let data;
      if (sourceConfig.isLocal) {
        // Read from local file
        if (!fs.existsSync(sourceConfig.url)) {
          throw new Error(`Local file not found: ${sourceConfig.url}`);
        }
        data = fs.readFileSync(sourceConfig.url, 'utf8');
        console.log(`   📁 Read local file: ${sourceConfig.url}`);
      } else {
        // Fetch from URL
        data = await fetchUrl(sourceConfig.url);
      }
      
      let packages;
      if (sourceConfig.parser === 'csv') {
        packages = parseCsvFormat(data);
      } else if (sourceConfig.parser === 'legacy') {
        packages = parseCompromisedList(data);
      } else {
        throw new Error(`Unknown parser type: ${sourceConfig.parser}`);
      }
      
      const { added, updated } = mergePackages(mergedPackages, packages);
      totalAddedCount += added;
      totalUpdatedCount += updated;
      console.log(`   ✅ ${sourceName}: ${added} new, ${updated} updated (${Object.keys(packages).length} packages parsed)`);
    } catch (error) {
      console.error(`   ❌ Failed to fetch ${sourceName}: ${error.message}`);
    }
  }
  console.log('\n📊 Creating final database...');
  
  const enabledSources = Object.fromEntries(
    Object.entries(SOURCES)
      .filter(([, config]) => config.enabled)
      .map(([name, config]) => [name, config.url])
  );

  const jsonOutput = {
    "_metadata": {
      "source": "Multiple sources: Wiz Security Research + Google Sheets + Legacy sources",
      "sources": enabledSources,
      "lastUpdated": new Date().toISOString().split('T')[0],
      "description": "Comprehensive list of compromised NPM packages from multiple supply chain attacks including Shai-Hulud campaigns. Updated from multiple authoritative sources.",
      "totalPackages": Object.keys(mergedPackages).length,
      "updateInfo": {
        "newPackages": totalAddedCount,
        "updatedPackages": totalUpdatedCount,
        "enabledSources": Object.keys(enabledSources).length
      }
    },
    "packages": mergedPackages
  };
  
  fs.writeFileSync(COMPROMISED_JSON_FILE, JSON.stringify(jsonOutput, null, 2));
  console.log(`✅ Database updated successfully:`);
  console.log(`   📦 Total packages: ${Object.keys(mergedPackages).length}`);
  console.log(`   🆕 New packages added: ${totalAddedCount}`);
  console.log(`   📝 Packages updated: ${totalUpdatedCount}`);
  console.log(`   💾 Saved to: ${COMPROMISED_JSON_FILE}`);
  
  if (totalAddedCount > 0 || totalUpdatedCount > 0) {
    console.log(`\n🔄 Changes detected! Consider running security scans on your projects.`);
  } else {
    console.log(`\n✨ No new compromised packages found. Database is up to date.`);
  }
}

function mergePackages(mergedPackages, newPackages) {
  let addedCount = 0;
  let updatedCount = 0;
  
  for (const [packageName, versions] of Object.entries(newPackages)) {
    if (mergedPackages[packageName]) {
      const existingVersions = new Set(mergedPackages[packageName]);
      let newVersionsAdded = false;
      
      for (const version of versions) {
        if (!existingVersions.has(version)) {
          mergedPackages[packageName].push(version);
          newVersionsAdded = true;
        }
      }
      
      if (newVersionsAdded) {
        mergedPackages[packageName].sort();
        updatedCount++;
      }
    } else {
      mergedPackages[packageName] = versions;
      addedCount++;
    }
  }
  
  return { added: addedCount, updated: updatedCount };
}

function parseCsvFormat(data) {
  const lines = data.split('\n');
  const packages = {};
  
  if (lines.length === 0) return packages;
  
  // Parse header to determine column positions
  const header = lines[0].toLowerCase();
  let packageCol = 0;
  let versionCol = 1;
  
  if (header.includes('package name')) {
    packageCol = 0;
    versionCol = 1;
  } else if (header.includes('package')) {
    packageCol = 0;
    versionCol = 1;
  }
  
  for (let i = 1; i < lines.length; i++) { // Skip header row
    const line = lines[i].trim();
    
    if (!line) continue;
    
    // Handle CSV with potential commas in quoted fields
    const parts = line.split(',').map(p => p.trim());
    if (parts.length < 2) continue;
    
    const packageName = parts[packageCol].replace(/['"]/g, '').trim();
    const versionInfo = parts[versionCol].replace(/['"]/g, '').trim();
    
    if (!packageName || !versionInfo) continue;
    
    const versions = parseVersionInfo(versionInfo);
    
    if (versions.length > 0) {
      if (!packages[packageName]) {
        packages[packageName] = [];
      }
      
      for (const version of versions) {
        if (!packages[packageName].includes(version)) {
          packages[packageName].push(version);
        }
      }
    }
  }
  
  // Sort versions for each package
  for (const packageName in packages) {
    packages[packageName].sort();
  }
  
  return packages;
}

function parseVersionInfo(versionInfo) {
  const versions = [];
  
  // Clean up the version info
  let cleaned = versionInfo.replace(/^=\s*/, ''); // Remove leading = and spaces
  
  // Split by || to handle multiple versions
  const versionParts = cleaned.split('||').map(v => v.trim());
  
  for (const part of versionParts) {
    // Handle different version formats:
    // 1. Simple version: "1.2.3"
    // 2. With equals: "= 1.2.3"
    // 3. Complex format from Wiz CSV: "= 1.2.3 || = 1.4.5"
    
    let match = part.match(/=?\s*(\d+\.\d+\.\d+(?:-[a-zA-Z0-9-]+)?(?:\+[a-zA-Z0-9-]+)?)/);
    if (match) {
      const version = match[1];
      if (!versions.includes(version)) {
        versions.push(version);
      }
    } else if (/^\d+\.\d+\.\d+/.test(part)) {
      // Handle simple version format directly
      const simpleMatch = part.match(/^(\d+\.\d+\.\d+(?:-[a-zA-Z0-9-]+)?(?:\+[a-zA-Z0-9-]+)?)/);
      if (simpleMatch && !versions.includes(simpleMatch[1])) {
        versions.push(simpleMatch[1]);
      }
    }
  }
  
  return versions;
}

function parseCompromisedList(data) {
  const lines = data.split('\n');
  const packages = {};
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    // Skip comments and empty lines
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    
    // Parse package:version format
    const match = trimmed.match(/^(.+?):(.+)$/);
    if (match) {
      const packageName = match[1].trim();
      const version = match[2].trim();
      
      if (!packages[packageName]) {
        packages[packageName] = [];
      }
      
      // Add version if not already present
      if (!packages[packageName].includes(version)) {
        packages[packageName].push(version);
      }
    }
  }
  
  // Sort versions for each package
  for (const packageName in packages) {
    packages[packageName].sort();
  }
  
  return packages;
}

function showUsage() {
  console.log('Usage: node update-compromised-list.js [options]');
  console.log('');
  console.log('Options:');
  console.log('  --disable-legacy     Disable legacy source');
  console.log('  --disable-wiz        Disable Wiz Security CSV source');
  console.log('  --disable-sheets     Disable Google Sheets source');
  console.log('  --only-wiz          Only use Wiz Security CSV source');
  console.log('  --only-sheets       Only use Google Sheets source');
  console.log('  --only-legacy       Only use legacy source');
  console.log('  --only-local        Only use local CSV file');
  console.log('  --help, -h          Show this help message');
  console.log('');
  console.log('Examples:');
  console.log('  node update-compromised-list.js');
  console.log('  node update-compromised-list.js --disable-legacy');
  console.log('  node update-compromised-list.js --only-wiz');
}

if (require.main === module) {
  const args = process.argv.slice(2);
  
  // Parse command line arguments
  for (const arg of args) {
    if (arg === '--help' || arg === '-h') {
      showUsage();
      process.exit(0);
    } else if (arg === '--disable-legacy') {
      SOURCES.legacy.enabled = false;
    } else if (arg === '--disable-wiz') {
      SOURCES.wizCsv.enabled = false;
    } else if (arg === '--disable-sheets') {
      SOURCES.googleSheets.enabled = false;
    } else if (arg === '--only-wiz') {
      SOURCES.legacy.enabled = false;
      SOURCES.googleSheets.enabled = false;
    } else if (arg === '--only-sheets') {
      SOURCES.legacy.enabled = false;
      SOURCES.wizCsv.enabled = false;
    } else if (arg === '--only-legacy') {
      SOURCES.wizCsv.enabled = false;
      SOURCES.googleSheets.enabled = false;
      SOURCES.localCsv.enabled = false;
    } else if (arg === '--only-local') {
      SOURCES.legacy.enabled = false;
      SOURCES.wizCsv.enabled = false;
      SOURCES.googleSheets.enabled = false;
    }
  }

  console.log('🔄 Updating compromised packages database from multiple sources...');
  downloadAndMerge().catch(error => {
    console.error('❌ Error updating database:', error);
    process.exit(1);
  });
}