import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

function generateSecret(): string {
  return crypto.randomBytes(64).toString('base64');
}

function updateEnvFile(secret: string): void {
  const envPath = path.join(process.cwd(), '.env');
  let envContent = '';
  
  try {
    envContent = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : '';
  } catch (error) {
    console.error('Warning: Could not read .env file');
  }

  const secretRegex = /^XSECURITY_SECRET=.*/m;
  const secretLine = `XSECURITY_SECRET=${secret}`;
  const enabledRegex = /^XSECURITY_ENABLED=.*/m;
  const enabledLine = 'XSECURITY_ENABLED=true';

  if (secretRegex.test(envContent)) {
    envContent = envContent.replace(secretRegex, secretLine);
  } else {
    envContent += envContent.length && !envContent.endsWith('\n') ? '\n' : '';
    envContent += `${secretLine}\n`;
  }

  if (enabledRegex.test(envContent)) {
    envContent = envContent.replace(enabledRegex, enabledLine);
  } else {
    envContent += `${enabledLine}\n`;
  }

  try {
    fs.writeFileSync(envPath, envContent);
    console.log('✓ Updated .env file successfully');
  } catch (error) {
    console.error('Error: Could not write to .env file');
    console.error('Please add the following lines to your .env file manually:');
    console.log('\n' + secretLine);
    console.log(enabledLine);
  }
}

function showHelp(): void {
  console.log(`
nestjs-xsecurity <command>

Commands:
  install     Generate secret and configure environment
  init        Alias for install
  help        Show this help message

Example:
  $ npx nestjs-xsecurity install
  `);
}

export function cli(args: string[]): void {
  const command = args[0];

  switch (command) {
    case 'install':
    case 'init':
      console.log('\n🔒 Configuring NestJS XSecurity...\n');
      try {
        const secret = generateSecret();
        console.log('Generated secret: ' + secret);
        console.log('');
        updateEnvFile(secret);
        console.log('\n✨ XSecurity configured successfully!');
        console.log('Make sure to add these environment variables to your production environment.\n');
      } catch (error) {
        console.error('\n❌ Error during configuration:', error.message);
        process.exit(1);
      }
      break;

    case 'help':
    case '--help':
    case '-h':
    default:
      showHelp();
      if (command && command !== 'help' && command !== '--help' && command !== '-h') {
        console.error(`\nUnknown command: ${command}`);
        process.exit(1);
      }
      break;
  }
}