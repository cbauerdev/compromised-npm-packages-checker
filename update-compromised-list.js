#!/usr/bin/env node

// Script to update compromised.json with latest packages from GitHub while preserving existing data
const fs = require('fs');
const https = require('https');

const url = 'https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt';
const COMPROMISED_JSON_FILE = 'compromised.json';

function downloadAndMerge() {
  // Read existing compromised.json
  let existingData = { packages: {} };
  if (fs.existsSync(COMPROMISED_JSON_FILE)) {
    existingData = JSON.parse(fs.readFileSync(COMPROMISED_JSON_FILE, 'utf8'));
    console.log(`📖 Loaded existing database with ${Object.keys(existingData.packages).length} packages`);
  }

  https.get(url, (response) => {
    let data = '';
    
    response.on('data', (chunk) => {
      data += chunk;
    });
    
    response.on('end', () => {
      console.log('📥 Downloaded latest compromised packages list from GitHub...');
      const newPackages = parseCompromisedList(data);
      
      // Merge new packages with existing ones
      const mergedPackages = { ...existingData.packages };
      let addedCount = 0;
      let updatedCount = 0;
      
      for (const [packageName, versions] of Object.entries(newPackages)) {
        if (mergedPackages[packageName]) {
          // Merge versions if package exists
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
          // Add new package
          mergedPackages[packageName] = versions;
          addedCount++;
        }
      }
      
      const jsonOutput = {
        "_metadata": {
          "source": "Multiple sources: Shai-Hulud NPM Supply Chain Attack + Red Hat Security Advisory + Auto-updates",
          "url": "https://access.redhat.com/security/supply-chain-attacks-NPM-packages",
          "lastUpdated": new Date().toISOString().split('T')[0],
          "description": "Comprehensive list of compromised NPM packages from multiple supply chain attacks including s1ngularity, popular packages, and shai-hulud campaigns. Automatically updated from upstream sources.",
          "totalPackages": Object.keys(mergedPackages).length,
          "autoUpdateSource": "https://github.com/Cobenian/shai-hulud-detect/blob/main/compromised-packages.txt"
        },
        "packages": mergedPackages
      };
      
      fs.writeFileSync(COMPROMISED_JSON_FILE, JSON.stringify(jsonOutput, null, 2));
      console.log(`✅ Database updated successfully:`);
      console.log(`   📦 Total packages: ${Object.keys(mergedPackages).length}`);
      console.log(`   🆕 New packages added: ${addedCount}`);
      console.log(`   📝 Packages updated: ${updatedCount}`);
      console.log(`   💾 Saved to: ${COMPROMISED_JSON_FILE}`);
      
      if (addedCount > 0 || updatedCount > 0) {
        console.log(`\n🔄 Changes detected! Consider running security scans on your projects.`);
      } else {
        console.log(`\n✨ No new compromised packages found. Database is up to date.`);
      }
    });
  }).on('error', (error) => {
    console.error('❌ Error downloading file:', error);
    process.exit(1);
  });
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

if (require.main === module) {
  console.log('🔄 Updating compromised packages database...');
  downloadAndMerge();
}