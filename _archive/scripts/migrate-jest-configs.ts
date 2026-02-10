#!/usr/bin/env tsx
import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Migration script to convert jest.config.js files to TypeScript
 */

function findJestConfigs(dir: string, results: string[] = []): string[] {
  const entries = readdirSync(dir);

  for (const entry of entries) {
    const fullPath = join(dir, entry);

    // Skip node_modules and dist
    if (entry === 'node_modules' || entry === 'dist') {
      continue;
    }

    const stat = statSync(fullPath);

    if (stat.isDirectory()) {
      findJestConfigs(fullPath, results);
    } else if (entry === 'jest.config.js' || entry === 'jest.properties.config.js') {
      results.push(fullPath);
    }
  }

  return results;
}

function migrateJestConfig(filePath: string): void {
  console.log(`Migrating: ${filePath}`);

  const content = readFileSync(filePath, 'utf8');

  // Convert to TypeScript format
  let tsContent = `import type { Config } from 'jest';\n\n`;

  // Remove JSDoc comments like /** @type {import('jest').Config} */
  const cleanContent = content.replace(/\/\*\*\s*@type.*?\*\/\s*/g, '');

  // Remove module.exports = and replace with const config: Config =
  const configContent = cleanContent
    .replace(/module\.exports\s*=\s*/, 'const config: Config = ')
    .trim();

  tsContent += configContent;

  // Add export default
  if (!tsContent.includes('export default')) {
    tsContent += '\n\nexport default config;\n';
  }

  // Write to .ts file
  const tsFilePath = filePath.replace(/\.js$/, '.ts');
  writeFileSync(tsFilePath, tsContent);
  console.log(`Created: ${tsFilePath}`);
}

function main(): void {
  const repoRoot = resolve(__dirname, '..');
  const jestConfigs = findJestConfigs(repoRoot);

  console.log(`Found ${jestConfigs.length} jest.config.js files to migrate\n`);

  for (const configPath of jestConfigs) {
    try {
      migrateJestConfig(configPath);
    } catch (error) {
      console.error(`Error migrating ${configPath}:`, error);
    }
  }

  console.log(`\n✓ Migration complete! Migrated ${jestConfigs.length} files.`);
  console.log('\nNext steps:');
  console.log('1. Review the generated .ts files');
  console.log('2. Test the configurations: npm test');
  console.log('3. Delete the old .js files once verified');
}

main();
