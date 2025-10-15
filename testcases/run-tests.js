#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Test configuration
const tests = [
  // Safe tests (should return 0)
  { file: 'safe/clean-package.json', expected: 0, description: 'Clean package.json with safe dependencies' },
  { file: 'safe/clean-lockfile-v3.json', expected: 0, description: 'Clean npm v7+ lockfile' },
  { file: 'safe/clean-lockfile-v6.json', expected: 0, description: 'Clean npm v6 lockfile' },
  
  // Compromised tests (should return 1)
  { file: 'compromised/chalk-attack.json', expected: 1, description: 'September 8, 2025 chalk/debug attack packages' },
  { file: 'compromised/ctrl-packages.json', expected: 1, description: '@ctrl namespace compromised packages' },
  { file: 'compromised/comprehensive-attack.json', expected: 1, description: 'Multiple namespaces compromise' },
  
  // Mixed tests (should return 1 if any compromised)
  { file: 'mixed/partial-compromise.json', expected: 1, description: 'Mix of safe and compromised packages' },
  { file: 'mixed/version-ranges.json', expected: 1, description: 'Version ranges with some compromised' },
  
  // Edge cases
  { file: 'edge-cases/empty-dependencies.json', expected: 0, description: 'Empty dependencies object' },
  { file: 'edge-cases/minimal-package.json', expected: 0, description: 'Minimal package.json' },
  { file: 'edge-cases/complex-versions.json', expected: 1, description: 'Complex version formats' }
];

function runTest(test) {
  const testFile = path.join(__dirname, test.file);
  const command = `node ../check-compromised-packages.js --no-emoji "${testFile}"`;
  
  console.log(`\n🧪 Testing: ${test.description}`);
  console.log(`   File: ${test.file}`);
  
  try {
    const output = execSync(command, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
    const exitCode = 0; // execSync succeeded
    
    if (exitCode === test.expected) {
      console.log(`   ✅ PASS - Exit code ${exitCode} (expected ${test.expected})`);
      return { passed: true, test, exitCode, output };
    } else {
      console.log(`   ❌ FAIL - Exit code ${exitCode} (expected ${test.expected})`);
      return { passed: false, test, exitCode, output };
    }
  } catch (error) {
    const exitCode = error.status;
    const output = error.stdout || error.stderr || error.message;
    
    if (exitCode === test.expected) {
      console.log(`   ✅ PASS - Exit code ${exitCode} (expected ${test.expected})`);
      return { passed: true, test, exitCode, output };
    } else {
      console.log(`   ❌ FAIL - Exit code ${exitCode} (expected ${test.expected})`);
      return { passed: false, test, exitCode, output };
    }
  }
}

function runAllTests() {
  console.log('🚀 Running NPM Package Security Checker Test Suite');
  console.log('================================================');
  
  const results = tests.map(runTest);
  
  const passed = results.filter(r => r.passed).length;
  const failed = results.filter(r => !r.passed).length;
  
  console.log('\n📊 Test Results Summary');
  console.log('=======================');
  console.log(`✅ Passed: ${passed}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`📝 Total:  ${tests.length}`);
  
  if (failed > 0) {
    console.log('\n💥 Failed Tests:');
    results.filter(r => !r.passed).forEach(result => {
      console.log(`   - ${result.test.description} (${result.test.file})`);
      console.log(`     Expected exit code: ${result.test.expected}, Got: ${result.exitCode}`);
    });
    process.exit(1);
  } else {
    console.log('\n🎉 All tests passed!');
    process.exit(0);
  }
}

// Run tests if script is executed directly
if (require.main === module) {
  runAllTests();
}

module.exports = { runAllTests, runTest, tests };