#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const REPO_ROOT = path.resolve(__dirname, '..');
const SERVICES_DIR = path.join(REPO_ROOT, 'services');
const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx']);
const WHITELISTED_GATEWAYS = new Set([
  'api-gateway',
  'invoice-gateway-api',
  'web-gateway',
  'public-api-gateway',
  'upload-gateway'
]);
const PROHIBITED_CLIENT_PATTERNS = [
  { name: 'axios', regex: /\baxios\b/ },
  { name: 'fetch', regex: /\bfetch\s*\(/ },
  { name: 'superagent', regex: /superagent\.(get|post|put|delete|patch)/i },
  { name: 'node:http', regex: /\bhttp\.request\s*\(/i },
  { name: 'node:https', regex: /\bhttps\.request\s*\(/i }
];
const MESSAGE_BUS_INDICATORS = [
  /@eracun\/messaging/,
  /shared\/messaging/,
  /\bmessageBus\b/,
  /\.publish(Command|Event)?\s*\(/i,
  /\.subscribe\s*\(/i,
  /registerHandler\s*\(/i
];
const CONTRACT_IMPORT_REGEX = /from\s+['"](@eracun\/contracts|\.\.?(?:\/[\w.-]+)*\/shared\/contracts[^'"]*)['"]/;
const HTTP_LITERAL_REGEX = /https?:\/\/([a-z0-9.-]+)(?::\d+)?/gi;
const QUERY_KEYWORDS = /(\bquery\b|queries|read model|read-only)/i;

function listDirectories(dir) {
  if (!fs.existsSync(dir)) {
    return [];
  }
  return fs
    .readdirSync(dir)
    .filter((entry) => fs.statSync(path.join(dir, entry)).isDirectory());
}

function gatherSourceFiles(dir) {
  const results = [];
  if (!fs.existsSync(dir)) {
    return results;
  }
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const entryPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...gatherSourceFiles(entryPath));
      continue;
    }
    const ext = path.extname(entry.name).toLowerCase();
    if (SOURCE_EXTENSIONS.has(ext)) {
      results.push(entryPath);
    }
  }
  return results;
}

function normalizeHost(rawHost) {
  if (!rawHost) {
    return null;
  }
  const withoutPort = rawHost.split(':')[0];
  if (!withoutPort) {
    return null;
  }
  const normalized = withoutPort.split('.')[0].toLowerCase();
  return normalized || null;
}

function extractInternalHosts(content, currentService, knownServices) {
  const hosts = new Set();
  let match;
  while ((match = HTTP_LITERAL_REGEX.exec(content)) !== null) {
    const candidate = normalizeHost(match[1]);
    if (!candidate) {
      continue;
    }
    if (candidate === 'localhost' || candidate === '127') {
      continue;
    }
    if (!knownServices.has(candidate)) {
      continue;
    }
    if (candidate === currentService) {
      continue;
    }
    if (WHITELISTED_GATEWAYS.has(candidate)) {
      continue;
    }
    hosts.add(candidate);
  }
  return [...hosts];
}

function hasMessageBusUsage(files) {
  return files.some(({ content }) =>
    MESSAGE_BUS_INDICATORS.some((regex) => regex.test(content))
  );
}

function detectDirectHttpViolations(files, currentService, knownServices) {
  const violations = [];
  for (const file of files) {
    const clientMatches = PROHIBITED_CLIENT_PATTERNS.filter((pattern) =>
      pattern.regex.test(file.content)
    ).map((pattern) => pattern.name);

    if (clientMatches.length === 0) {
      continue;
    }

    const internalHosts = extractInternalHosts(
      file.content,
      currentService,
      knownServices
    );
    if (internalHosts.length === 0) {
      continue;
    }

    const hasContractImport = CONTRACT_IMPORT_REGEX.test(file.content);
    const isAdapterFile = file.relativePath.includes(`${path.sep}adapters${path.sep}`);

    internalHosts.forEach((host) => {
      violations.push({
        type: 'DIRECT_HTTP',
        filePath: file.relativePath,
        message: `Direct HTTP client (${clientMatches.join(
          ', '
        )}) calling internal service "${host}" detected.`,
        hint: hasContractImport
          ? 'Contracts are already imported; route this call through the message bus RPC handler defined in shared/contracts.'
          : 'No shared contract import detected. Import the relevant contract from shared/contracts and expose a message bus handler instead of calling services over HTTP.',
        details: {
          service: currentService,
          host,
          client: clientMatches,
          adapterScoped: isAdapterFile,
        },
      });
    });
  }
  return violations;
}

function detectMessageBusCoverage(serviceName, files, readmePath) {
  const violations = [];
  const readmeContent = fs.existsSync(readmePath)
    ? fs.readFileSync(readmePath, 'utf8')
    : '';
  const declaresQuery = QUERY_KEYWORDS.test(readmeContent);
  if (declaresQuery && !hasMessageBusUsage(files)) {
    violations.push({
      type: 'MESSAGE_BUS',
      filePath: path.relative(REPO_ROOT, readmePath),
      message: `Service "${serviceName}" declares query responsibilities but no message bus handlers were detected in src/.`,
      hint: 'Register handlers via shared/messaging and publish query responses over the bus instead of using HTTP clients.',
    });
  }
  return violations;
}

function collectServiceFiles(serviceDir) {
  const srcDir = path.join(serviceDir, 'src');
  const files = gatherSourceFiles(srcDir);
  return files.map((filePath) => ({
    absolutePath: filePath,
    relativePath: path.relative(REPO_ROOT, filePath),
    content: fs.readFileSync(filePath, 'utf8'),
  }));
}

function run() {
  const serviceDirs = listDirectories(SERVICES_DIR);
  const knownServices = new Set(serviceDirs.map((service) => service.toLowerCase()));
  const allViolations = [];

  for (const serviceName of serviceDirs) {
    const serviceDir = path.join(SERVICES_DIR, serviceName);
    const files = collectServiceFiles(serviceDir);
    if (files.length === 0) {
      continue;
    }
    const serviceKey = serviceName.toLowerCase();
    const httpViolations = detectDirectHttpViolations(
      files,
      serviceKey,
      knownServices
    );
    allViolations.push(...httpViolations);

    const readmePath = path.join(serviceDir, 'README.md');
    const busViolations = detectMessageBusCoverage(
      serviceName,
      files,
      readmePath
    );
    allViolations.push(...busViolations);
  }

  if (allViolations.length === 0) {
    console.log('✓ Architecture compliance checks passed: no violations detected.');
    return;
  }

  console.error('✗ Architecture compliance violations detected:');
  allViolations.forEach((violation, index) => {
    console.error(`${index + 1}. [${violation.type}] ${violation.filePath}`);
    console.error(`   → ${violation.message}`);
    if (violation.hint) {
      console.error(`     Hint: ${violation.hint}`);
    }
    if (violation.details) {
      console.error(`     Details: ${JSON.stringify(violation.details)}`);
    }
  });
  process.exitCode = 1;
}

run();
