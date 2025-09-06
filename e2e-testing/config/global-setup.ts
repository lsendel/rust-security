import { chromium, FullConfig } from '@playwright/test';

async function globalSetup(config: FullConfig) {
  console.log('🚀 Starting E2E test environment setup...');
  
  // Ensure directories exist
  const fs = require('fs-extra');
  await fs.ensureDir('reports');
  await fs.ensureDir('evidence');
  
  console.log('✅ E2E test environment ready!');
}

export default globalSetup;
