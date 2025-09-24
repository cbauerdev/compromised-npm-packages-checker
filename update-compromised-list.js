#!/usr/bin/env node

// Script to convert the GitHub raw format to our JSON format
const fs = require('fs');
const https = require('https');

const url = 'https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt';

function downloadAndConvert() {
  https.get(url, (response) => {
    let data = '';
    
    response.on('data', (chunk) => {
      data += chunk;
    });
    
    response.on('end', () => {
      console.log('Downloaded compromised packages list...');
      const packages = parseCompromisedList(data);
      
      const jsonOutput = {
        "_metadata": {
          "source": "Shai-Hulud NPM Supply Chain Attack - Cobenian Detection List",
          "url": "https://github.com/Cobenian/shai-hulud-detect/blob/main/compromised-packages.txt",
          "lastUpdated": new Date().toISOString().split('T')[0],
          "description": "Compromised NPM packages and their specific vulnerable versions",
          "totalPackages": Object.keys(packages).length
        },
        "packages": packages
      };
      
      fs.writeFileSync('compromised-updated.json', JSON.stringify(jsonOutput, null, 2));
      console.log(`✅ Converted ${Object.keys(packages).length} compromised packages to JSON format`);
      console.log('Output saved to: compromised-updated.json');
    });
  }).on('error', (error) => {
    console.error('Error downloading file:', error);
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
  console.log('Downloading and converting compromised packages list...');
  downloadAndConvert();
}