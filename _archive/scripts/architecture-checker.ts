#!/usr/bin/env tsx
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { resolve, join, relative, extname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const REPO_ROOT = resolve(__dirname, '..');
const SERVICES_DIR = join(REPO_ROOT, 'services');
const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx']);
const WHITELISTED_GATEWAYS = new Set([
  'api-gateway',
  'invoice-gateway-api',
  'web-gateway',
  'public-api-gateway',
  'upload-gateway'
]);

interface ClientPattern {
  name: string;
  regex: RegExp;
}

const PROHIBITED_CLIENT_PATTERNS: ClientPattern[] = [
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

interface SourceFile {
  absolutePath: string;
  relativePath: string;
  content: string;
}

interface Violation {
  type: string;
  filePath: string;
  message: string;
  hint?: string;
  details?: {
    service: string;
    host: string;
    client: string[];
    adapterScoped: boolean;
  };
}

function listDirectories(dir: string): string[] {
  if (!existsSync(dir)) {
    return [];
  }
  return readdirSync(dir)
    .filter((entry) => statSync(join(dir, entry)).isDirectory());
}

function gatherSourceFiles(dir: string): string[] {
  const results: string[] = [];
  if (!existsSync(dir)) {
    return results;
  }
  const entries = readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const entryPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...gatherSourceFiles(entryPath));
      continue;
    }
    const ext = extname(entry.name).toLowerCase();
    if (SOURCE_EXTENSIONS.has(ext)) {
      results.push(entryPath);
    }
  }
  return results;
}

function normalizeHost(rawHost: string | undefined): string | null {
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

function extractInternalHosts(
  content: string,
  currentService: string,
  knownServices: Set<string>
): string[] {
  const hosts = new Set<string>();
  let match: RegExpExecArray | null;
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

function hasMessageBusUsage(files: SourceFile[]): boolean {
  return files.some(({ content }) =>
    MESSAGE_BUS_INDICATORS.some((regex) => regex.test(content))
  );
}

function detectDirectHttpViolations(
  files: SourceFile[],
  currentService: string,
  knownServices: Set<string>
): Violation[] {
  const violations: Violation[] = [];
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
    const isAdapterFile = file.relativePath.includes(`${sep}adapters${sep}`);

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

function detectMessageBusCoverage(
  serviceName: string,
  files: SourceFile[],
  readmePath: string
): Violation[] {
  const violations: Violation[] = [];
  const readmeContent = existsSync(readmePath)
    ? readFileSync(readmePath, 'utf8')
    : '';
  const declaresQuery = QUERY_KEYWORDS.test(readmeContent);
  if (declaresQuery && !hasMessageBusUsage(files)) {
    violations.push({
      type: 'MESSAGE_BUS',
      filePath: relative(REPO_ROOT, readmePath),
      message: `Service "${serviceName}" declares query responsibilities but no message bus handlers were detected in src/.`,
      hint: 'Register handlers via shared/messaging and publish query responses over the bus instead of using HTTP clients.',
    });
  }
  return violations;
}

function collectServiceFiles(serviceDir: string): SourceFile[] {
  const srcDir = join(serviceDir, 'src');
  const files = gatherSourceFiles(srcDir);
  return files.map((filePath) => ({
    absolutePath: filePath,
    relativePath: relative(REPO_ROOT, filePath),
    content: readFileSync(filePath, 'utf8'),
  }));
}

function run(): void {
  const serviceDirs = listDirectories(SERVICES_DIR);
  const knownServices = new Set(serviceDirs.map((service) => service.toLowerCase()));
  const allViolations: Violation[] = [];

  for (const serviceName of serviceDirs) {
    const serviceDir = join(SERVICES_DIR, serviceName);
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

    const readmePath = join(serviceDir, 'README.md');
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
