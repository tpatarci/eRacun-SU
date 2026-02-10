#!/usr/bin/env tsx

/**
 * TypeScript Compliance Validator
 *
 * This script validates that all configuration and tooling files
 * are using TypeScript instead of JavaScript, as mandated by the
 * TypeScript Harmonization Guide.
 *
 * Usage:
 *   tsx scripts/validate-typescript-compliance.ts [--fix]
 *
 * Options:
 *   --fix    Generate migration commands for non-compliant files
 */

import { readdirSync, statSync, existsSync, readFileSync } from 'node:fs';
import { join, basename, dirname } from 'node:path';
import { execSync } from 'node:child_process';

interface ComplianceReport {
  totalFiles: number;
  compliantFiles: string[];
  nonCompliantFiles: string[];
  complianceScore: number;
  byCategory: {
    [key: string]: {
      compliant: number;
      nonCompliant: number;
      files: string[];
    };
  };
}

// Configuration file patterns to check
const CONFIG_PATTERNS = [
  'jest.config.js',
  '.eslintrc.js',
  '.prettierrc.js',
  'webpack.config.js',
  'rollup.config.js',
  'babel.config.js',
  'tsconfig.js', // Should be .json, but checking for mistakes
];

// Script file patterns
const SCRIPT_PATTERNS = [
  'scripts/**/*.js',
  'tools/**/*.js',
  'bin/**/*.js',
];

// Directories to ignore
const IGNORE_DIRS = [
  'node_modules',
  'dist',
  'build',
  'coverage',
  '.git',
  'tmp',
];

function findFiles(dir: string, pattern: RegExp): string[] {
  const files: string[] = [];

  function walk(currentPath: string) {
    if (IGNORE_DIRS.some(ignore => currentPath.includes(ignore))) {
      return;
    }

    try {
      const entries = readdirSync(currentPath);

      for (const entry of entries) {
        const fullPath = join(currentPath, entry);
        const stat = statSync(fullPath);

        if (stat.isDirectory()) {
          walk(fullPath);
        } else if (pattern.test(entry)) {
          files.push(fullPath);
        }
      }
    } catch (error) {
      // Ignore permission errors
    }
  }

  walk(dir);
  return files;
}

function categorizeFile(filePath: string): string {
  const filename = basename(filePath);

  if (filename.includes('jest.config')) return 'Jest Configuration';
  if (filename.includes('eslintrc')) return 'ESLint Configuration';
  if (filename.includes('prettierrc')) return 'Prettier Configuration';
  if (filePath.includes('/scripts/')) return 'Build Scripts';
  if (filePath.includes('/tools/')) return 'Tooling Scripts';
  if (filename.includes('webpack')) return 'Webpack Configuration';
  if (filename.includes('rollup')) return 'Rollup Configuration';
  if (filename.includes('babel')) return 'Babel Configuration';

  return 'Other Configuration';
}

function validateCompliance(rootDir: string = '.'): ComplianceReport {
  const report: ComplianceReport = {
    totalFiles: 0,
    compliantFiles: [],
    nonCompliantFiles: [],
    complianceScore: 0,
    byCategory: {},
  };

  // Find JavaScript config files
  const jsConfigPattern = new RegExp(`(${CONFIG_PATTERNS.join('|')})$`);
  const jsConfigs = findFiles(rootDir, jsConfigPattern);

  // Find JavaScript scripts
  const jsScripts = findFiles(join(rootDir, 'scripts'), /\.js$/);

  // Find TypeScript equivalents
  const tsConfigPattern = /\.(config|rc)\.ts$/;
  const tsConfigs = findFiles(rootDir, tsConfigPattern);

  const tsScripts = findFiles(join(rootDir, 'scripts'), /\.ts$/);

  // Combine all files
  const allJsFiles = [...jsConfigs, ...jsScripts];
  const allTsFiles = [...tsConfigs, ...tsScripts];

  // Categorize files
  allJsFiles.forEach(file => {
    const category = categorizeFile(file);
    if (!report.byCategory[category]) {
      report.byCategory[category] = { compliant: 0, nonCompliant: 0, files: [] };
    }
    report.byCategory[category].nonCompliant++;
    report.byCategory[category].files.push(file);
    report.nonCompliantFiles.push(file);
  });

  allTsFiles.forEach(file => {
    const category = categorizeFile(file);
    if (!report.byCategory[category]) {
      report.byCategory[category] = { compliant: 0, nonCompliant: 0, files: [] };
    }
    report.byCategory[category].compliant++;
    report.compliantFiles.push(file);
  });

  // Calculate totals
  report.totalFiles = allJsFiles.length + allTsFiles.length;
  report.complianceScore = report.totalFiles > 0
    ? Math.round((allTsFiles.length / report.totalFiles) * 100)
    : 100;

  return report;
}

function generateMigrationCommands(files: string[]): string[] {
  const commands: string[] = [];

  files.forEach(file => {
    const tsFile = file.replace(/\.js$/, '.ts');
    const serviceName = file.split('/').find(part => part.includes('service'));

    commands.push(`# ${file}`);
    commands.push(`mv ${file} ${tsFile}`);

    if (file.includes('jest.config')) {
      commands.push(`# Update package.json to use jest.config.ts`);
      if (serviceName) {
        commands.push(`# Update ${serviceName}/package.json test scripts`);
      }
    }

    commands.push('');
  });

  return commands;
}

function printReport(report: ComplianceReport, showFix: boolean = false): void {
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('                TYPESCRIPT COMPLIANCE REPORT                   ');
  console.log('═══════════════════════════════════════════════════════════════\n');

  // Overall score with color coding
  const scoreColor = report.complianceScore === 100 ? '\x1b[32m' :
                     report.complianceScore >= 75 ? '\x1b[33m' :
                     '\x1b[31m';
  const resetColor = '\x1b[0m';

  console.log(`Overall Compliance: ${scoreColor}${report.complianceScore}%${resetColor}`);
  console.log(`Total Files: ${report.totalFiles}`);
  console.log(`✅ TypeScript: ${report.compliantFiles.length}`);
  console.log(`❌ JavaScript: ${report.nonCompliantFiles.length}\n`);

  // Category breakdown
  console.log('Category Breakdown:');
  console.log('─────────────────────────────────────────────────────────────');

  Object.entries(report.byCategory).forEach(([category, data]) => {
    const categoryScore = data.compliant + data.nonCompliant > 0
      ? Math.round((data.compliant / (data.compliant + data.nonCompliant)) * 100)
      : 100;

    console.log(`\n${category}: ${categoryScore}%`);
    if (data.nonCompliant > 0) {
      console.log(`  ❌ ${data.nonCompliant} JavaScript files need migration:`);
      data.files.slice(0, 5).forEach(file => {
        const relativePath = file.replace(process.cwd() + '/', '');
        console.log(`     - ${relativePath}`);
      });
      if (data.files.length > 5) {
        console.log(`     ... and ${data.files.length - 5} more`);
      }
    }
    if (data.compliant > 0) {
      console.log(`  ✅ ${data.compliant} TypeScript files compliant`);
    }
  });

  // Services needing migration
  if (report.nonCompliantFiles.length > 0) {
    console.log('\n─────────────────────────────────────────────────────────────');
    console.log('Services Requiring Migration:');

    const serviceMap = new Map<string, string[]>();
    report.nonCompliantFiles.forEach(file => {
      const match = file.match(/services\/([^/]+)/);
      if (match) {
        const service = match[1];
        if (!serviceMap.has(service)) {
          serviceMap.set(service, []);
        }
        serviceMap.get(service)!.push(basename(file));
      }
    });

    serviceMap.forEach((files, service) => {
      console.log(`\n  ${service}:`);
      files.forEach(file => console.log(`    - ${file}`));
    });
  }

  // Migration commands
  if (showFix && report.nonCompliantFiles.length > 0) {
    console.log('\n═══════════════════════════════════════════════════════════════');
    console.log('                    MIGRATION COMMANDS                         ');
    console.log('═══════════════════════════════════════════════════════════════\n');

    const commands = generateMigrationCommands(report.nonCompliantFiles);
    commands.forEach(cmd => console.log(cmd));

    console.log('\n# After moving files, remember to:');
    console.log('# 1. Add TypeScript types to the new .ts files');
    console.log('# 2. Update import statements in other files');
    console.log('# 3. Update package.json scripts to reference .ts files');
    console.log('# 4. Run tests to ensure everything works');
  }

  // Summary and next steps
  console.log('\n═══════════════════════════════════════════════════════════════');
  if (report.complianceScore === 100) {
    console.log('🎉 FULLY COMPLIANT! All configuration files use TypeScript.');
  } else {
    console.log(`📊 ${report.nonCompliantFiles.length} files need migration to reach 100% compliance.`);
    console.log('\nNext Steps:');
    console.log('1. Review the TypeScript Harmonization Guide');
    console.log('2. Migrate high-priority services first');
    console.log('3. Run with --fix flag to see migration commands');
    console.log('4. Test thoroughly after each migration');
  }
  console.log('═══════════════════════════════════════════════════════════════\n');
}

// Main execution
function main() {
  const args = process.argv.slice(2);
  const showFix = args.includes('--fix');
  const help = args.includes('--help') || args.includes('-h');

  if (help) {
    console.log('TypeScript Compliance Validator\n');
    console.log('Usage: tsx scripts/validate-typescript-compliance.ts [options]\n');
    console.log('Options:');
    console.log('  --fix     Generate migration commands for non-compliant files');
    console.log('  --help    Show this help message');
    process.exit(0);
  }

  const report = validateCompliance('.');
  printReport(report, showFix);

  // Exit with error if not fully compliant
  process.exit(report.complianceScore === 100 ? 0 : 1);
}

main();