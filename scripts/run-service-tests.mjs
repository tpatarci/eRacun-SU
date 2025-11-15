#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, rmSync, mkdirSync, cpSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');
const servicesRoot = path.join(repoRoot, 'services');
const coverageArtifactsDir = path.join(repoRoot, 'coverage-reports');

if (!existsSync(servicesRoot)) {
  console.error('Services directory not found.');
  process.exit(1);
}

rmSync(coverageArtifactsDir, { recursive: true, force: true });
mkdirSync(coverageArtifactsDir, { recursive: true });

const serviceEntries = readdirSync(servicesRoot, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort();

const filterRaw = process.env.SERVICE_FILTER?.trim() ?? '';
const filterTokens = filterRaw
  ? filterRaw.split(',').map((token) => token.trim()).filter(Boolean)
  : [];

const normalizedFilters = filterTokens.map((token) => token.toLowerCase());

const servicesToTest = normalizedFilters.length
  ? serviceEntries.filter((name) => normalizedFilters.includes(name.toLowerCase()))
  : serviceEntries;

if (servicesToTest.length === 0) {
  console.error('SERVICE_FILTER did not match any services. No tests were executed.');
  process.exit(1);
}

const mode = (process.env.SERVICE_TEST_MODE || 'all').toLowerCase();
const runDeterministicSuites = mode === 'all' || mode === 'deterministic';
const runPropertySuites = mode === 'all' || mode === 'properties';

const coverageSummaries = [];
let hasFailures = false;

for (const serviceName of servicesToTest) {
  const servicePath = path.join(servicesRoot, serviceName);
  const packagePath = path.join(servicePath, 'package.json');

  if (!existsSync(packagePath)) {
    continue;
  }

  let packageJson;
  try {
    packageJson = JSON.parse(readFileSync(packagePath, 'utf8'));
  } catch (error) {
    console.error(`⚠️  Unable to parse package.json for ${serviceName}: ${error.message}`);
    hasFailures = true;
    continue;
  }

  const scripts = packageJson.scripts || {};
  let ranDeterministic = false;

  if (runDeterministicSuites) {
    if (!scripts.test && !scripts['test:coverage']) {
      console.log(`\n⚪ ${serviceName}: no deterministic npm test script defined, skipping`);
    } else {
      const useCoverageScript = Boolean(scripts['test:coverage']);
      const commandArgs = useCoverageScript ? ['run', 'test:coverage'] : ['test'];
      const commandLabel = useCoverageScript ? 'npm run test:coverage' : 'npm test';

      console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log(`Service: ${serviceName}`);
      console.log(`Command: ${commandLabel}`);
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

      const result = spawnSync('npm', commandArgs, {
        cwd: servicePath,
        stdio: 'inherit',
        env: { ...process.env, CI: process.env.CI || 'true', FORCE_COLOR: '1' }
      });

      ranDeterministic = true;

      if (result.status !== 0) {
        console.error(`❌ ${serviceName} tests failed`);
        hasFailures = true;
      } else {
        console.log(`✅ ${serviceName} tests passed`);
      }

      const serviceCoverageDir = path.join(servicePath, 'coverage');
      const coveragePath = path.join(serviceCoverageDir, 'coverage-summary.json');
      if (existsSync(coveragePath)) {
        try {
          const coverageJson = JSON.parse(readFileSync(coveragePath, 'utf8'));
          const total = coverageJson.total || {};
          coverageSummaries.push({
            service: serviceName,
            lines: formatPercent(total.lines?.pct),
            statements: formatPercent(total.statements?.pct),
            branches: formatPercent(total.branches?.pct),
            functions: formatPercent(total.functions?.pct)
          });
          const targetDir = path.join(coverageArtifactsDir, serviceName);
          rmSync(targetDir, { recursive: true, force: true });
          if (existsSync(serviceCoverageDir)) {
            cpSync(serviceCoverageDir, targetDir, { recursive: true });
            console.log(`📦 Coverage artifacts saved to ${path.relative(repoRoot, targetDir)}`);
          }
        } catch (error) {
          console.warn(`⚠️  Unable to parse coverage summary for ${serviceName}: ${error.message}`);
        }
      } else {
        console.warn(`⚠️  Coverage summary missing for ${serviceName}`);
      }
    }
  }

  if (runPropertySuites) {
    if (!scripts['test:properties']) {
      console.log(`⚪ ${serviceName}: no property test script defined, skipping property suite`);
    } else {
      console.log(`↪ ${serviceName}: running npm run test:properties`);
      const propertyResult = spawnSync('npm', ['run', 'test:properties'], {
        cwd: servicePath,
        stdio: 'inherit',
        env: { ...process.env, CI: process.env.CI || 'true', FORCE_COLOR: '1' }
      });

      if (propertyResult.status !== 0) {
        console.error(`❌ ${serviceName} property tests failed`);
        hasFailures = true;
      } else {
        console.log(`✅ ${serviceName} property tests passed`);
      }
    }
  }

  if (!runDeterministicSuites && !runPropertySuites) {
    console.log(`⚪ ${serviceName}: no test mode selected, skipping`);
  }
}

if (runDeterministicSuites) {
  if (coverageSummaries.length) {
    console.log('\nAggregated coverage summary (percentages):');
    console.table(coverageSummaries);
  } else {
    console.warn('\n⚠️  No coverage summaries were produced. Coverage gate cannot be evaluated.');
  }
}

if (hasFailures) {
  process.exit(1);
}

function formatPercent(value) {
  return typeof value === 'number' ? `${value.toFixed(2)}%` : 'N/A';
}