const dotenv = require('dotenv');
const fs = require('fs');
const path = require('path');

// Load environment variables based on NODE_ENV
const loadEnvironment = () => {
  const environment = process.env.NODE_ENV || 'development';
  const envPath = path.resolve(process.cwd(), `.env.${environment}`);
  
  // Load environment-specific .env file first, then fallback to .env
  if (fs.existsSync(envPath)) {
    dotenv.config({ path: envPath });
    console.log(`Loaded environment config: ${envPath}`);
  } else if (fs.existsSync('.env')) {
    dotenv.config();
    console.log('Loaded default .env file');
  }
  
  // Validate required environment variables
  const requiredEnvVars = [
    'JWT_SECRET',
    'MONGO_URI',
    'PORT',
    'NODE_ENV'
  ];
  
  // Add environment-specific required variables
  if (environment === 'production') {
    requiredEnvVars.push('GOOGLE_CLIENT_SECRET', 'SSL_KEY_PATH');
  }
  
  const missing = requiredEnvVars.filter(envVar => !process.env[envVar]);

  // Add Some validation for this one
  if (missing.length > 0) {
    console.error(`❌ Missing required environment variables: ${missing.join(', ')}`);
    console.error('Application cannot start without these variables.');
    process.exit(1);
  }
  
  // Validate JWT_SECRET strength
  if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
    console.error('❌ JWT_SECRET must be at least 32 characters long');
    process.exit(1);
  }
  
  console.log(`✅ Environment validation successful for: ${environment}`);
  return environment;
};

module.exports = { loadEnvironment };