const path = require('path');
const SecurityVerifier = require('./security/SecurityVerifier');

console.log('🔍 Healthcare Management System - Security Verification');
console.log('Project Path:', __dirname);
console.log('='.repeat(60));

const verifier = new SecurityVerifier();
verifier.verify();