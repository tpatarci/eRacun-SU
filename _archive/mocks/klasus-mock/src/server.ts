/**
 * KLASUS Registry Mock Service
 * Production-grade mock for Croatian product classification system (KLASUS 2025)
 *
 * Features:
 * - Complete KLASUS 2025 code database
 * - Search and filter endpoints
 * - Bulk validation
 * - Version management
 * - Fast in-memory lookups
 */

import express from 'express';
import bodyParser from 'body-parser';
import winston from 'winston';
import fs from 'fs/promises';
import path from 'path';

interface KLASUSCode {
  code: string;
  name: string;
  nameEn?: string;
  parent?: string;
  level: number;
  active: boolean;
  validFrom: string;
  validTo?: string;
}

interface MockConfig {
  port: number;
  dataVersion: string;
  dataFile: string;
}

class KLASUSMockService {
  private app: express.Application;
  private config: MockConfig;
  private logger: winston.Logger;
  private codes: Map<string, KLASUSCode> = new Map();
  private codesByLevel: Map<number, Set<string>> = new Map();
  private metrics: {
    requests: number;
    lookups: number;
    searches: number;
    startTime: Date;
  };

  constructor(config: Partial<MockConfig> = {}) {
    this.app = express();
    this.config = {
      port: config.port || 8451,
      dataVersion: config.dataVersion || '2025',
      dataFile: config.dataFile || '/app/data/klasus-2025.json'
    };

    this.metrics = {
      requests: 0,
      lookups: 0,
      searches: 0,
      startTime: new Date()
    };

    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        }),
        new winston.transports.File({ filename: 'klasus-mock.log' })
      ]
    });

    this.app.use(bodyParser.json());
    this.setupRoutes();
  }

  private setupRoutes(): void {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'operational',
        version: this.config.dataVersion,
        codeCount: this.codes.size,
        uptime: Date.now() - this.metrics.startTime.getTime(),
        metrics: {
          requests: this.metrics.requests,
          lookups: this.metrics.lookups,
          searches: this.metrics.searches
        }
      });
    });

    // Get code by ID
    this.app.get('/api/codes/:code', (req, res) => {
      this.metrics.requests++;
      this.metrics.lookups++;

      const code = this.codes.get(req.params.code);
      if (!code) {
        return res.status(404).json({
          error: 'CODE_NOT_FOUND',
          message: `Code ${req.params.code} not found`
        });
      }

      res.json(code);
    });

    // Search codes
    this.app.get('/api/search', (req, res) => {
      this.metrics.requests++;
      this.metrics.searches++;

      const query = (req.query.q as string || '').toLowerCase();
      const level = req.query.level ? parseInt(req.query.level as string) : undefined;
      const limit = Math.min(parseInt(req.query.limit as string) || 100, 1000);
      const offset = parseInt(req.query.offset as string) || 0;

      let results = Array.from(this.codes.values());

      // Filter by level
      if (level !== undefined) {
        results = results.filter(c => c.level === level);
      }

      // Filter by query
      if (query) {
        results = results.filter(c =>
          c.code.includes(query) ||
          c.name.toLowerCase().includes(query) ||
          c.nameEn?.toLowerCase().includes(query)
        );
      }

      // Filter active codes only
      results = results.filter(c => c.active);

      const total = results.length;
      const paged = results.slice(offset, offset + limit);

      res.json({
        query,
        total,
        limit,
        offset,
        results: paged
      });
    });

    // Bulk validate codes
    this.app.post('/api/validate/bulk', (req, res) => {
      this.metrics.requests++;

      const { codes } = req.body;
      if (!Array.isArray(codes)) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'codes must be an array'
        });
      }

      const results = codes.map(code => ({
        code,
        valid: this.codes.has(code),
        active: this.codes.get(code)?.active ?? false,
        name: this.codes.get(code)?.name
      }));

      const validCount = results.filter(r => r.valid).length;

      res.json({
        total: codes.length,
        validCount,
        invalidCount: codes.length - validCount,
        results
      });
    });

    // Get codes by level
    this.app.get('/api/levels/:level', (req, res) => {
      this.metrics.requests++;

      const level = parseInt(req.params.level);
      const codeIds = this.codesByLevel.get(level);

      if (!codeIds) {
        return res.status(404).json({
          error: 'LEVEL_NOT_FOUND',
          message: `Level ${level} not found`
        });
      }

      const codes = Array.from(codeIds)
        .map(id => this.codes.get(id))
        .filter(Boolean);

      res.json({
        level,
        count: codes.length,
        codes
      });
    });

    // Get hierarchy (parent-child relationships)
    this.app.get('/api/codes/:code/children', (req, res) => {
      this.metrics.requests++;

      const parentCode = req.params.code;
      if (!this.codes.has(parentCode)) {
        return res.status(404).json({
          error: 'CODE_NOT_FOUND',
          message: `Code ${parentCode} not found`
        });
      }

      const children = Array.from(this.codes.values())
        .filter(c => c.parent === parentCode);

      res.json({
        parentCode,
        childCount: children.length,
        children
      });
    });

    // Random code (for testing)
    this.app.get('/api/random', (req, res) => {
      const level = req.query.level ? parseInt(req.query.level as string) : undefined;
      let pool = Array.from(this.codes.values()).filter(c => c.active);

      if (level !== undefined) {
        pool = pool.filter(c => c.level === level);
      }

      if (pool.length === 0) {
        return res.status(404).json({
          error: 'NO_CODES',
          message: 'No codes available'
        });
      }

      const random = pool[Math.floor(Math.random() * pool.length)];
      res.json(random);
    });
  }

  public async loadData(): Promise<void> {
    try {
      const data = await fs.readFile(this.config.dataFile, 'utf-8');
      const codes: KLASUSCode[] = JSON.parse(data);

      for (const code of codes) {
        this.codes.set(code.code, code);

        if (!this.codesByLevel.has(code.level)) {
          this.codesByLevel.set(code.level, new Set());
        }
        this.codesByLevel.get(code.level)!.add(code.code);
      }

      this.logger.info(`Loaded ${this.codes.size} KLASUS codes (version ${this.config.dataVersion})`);
    } catch (error) {
      this.logger.warn(`Could not load data file: ${error}`);
      this.logger.info('Generating sample data...');
      this.generateSampleData();
    }
  }

  private generateSampleData(): void {
    // Generate realistic KLASUS codes
    const categories = [
      { prefix: '01', name: 'Proizvodi od poljoprivrede, šumarstva i ribarstva' },
      { prefix: '10', name: 'Prehrambeni proizvodi' },
      { prefix: '13', name: 'Tekstil' },
      { prefix: '26', name: 'Računala i elektronički proizvodi' },
      { prefix: '28', name: 'Strojevi i oprema' },
      { prefix: '46', name: 'Trgovina na veliko' },
      { prefix: '47', name: 'Trgovina na malo' },
      { prefix: '58', name: 'Izdavačke djelatnosti' },
      { prefix: '62', name: 'Računalno programiranje' },
      { prefix: '63', name: 'Informacijske usluge' },
      { prefix: '70', name: 'Upravljanje i poslovno savjetovanje' },
      { prefix: '71', name: 'Arhitektonske i inženjerske djelatnosti' }
    ];

    for (const cat of categories) {
      // Level 1: Division (2 digits)
      const l1Code = `${cat.prefix}.00`;
      this.codes.set(l1Code, {
        code: l1Code,
        name: cat.name,
        level: 1,
        active: true,
        validFrom: '2025-01-01'
      });

      if (!this.codesByLevel.has(1)) {
        this.codesByLevel.set(1, new Set());
      }
      this.codesByLevel.get(1)!.add(l1Code);

      // Level 2: Group (3 digits)
      for (let i = 1; i <= 3; i++) {
        const l2Code = `${cat.prefix}.${i}0`;
        this.codes.set(l2Code, {
          code: l2Code,
          name: `${cat.name} - Grupa ${i}`,
          parent: l1Code,
          level: 2,
          active: true,
          validFrom: '2025-01-01'
        });

        if (!this.codesByLevel.has(2)) {
          this.codesByLevel.set(2, new Set());
        }
        this.codesByLevel.get(2)!.add(l2Code);

        // Level 3: Class (4 digits)
        for (let j = 1; j <= 2; j++) {
          const l3Code = `${cat.prefix}.${i}${j}`;
          this.codes.set(l3Code, {
            code: l3Code,
            name: `${cat.name} - Klasa ${i}.${j}`,
            parent: l2Code,
            level: 3,
            active: true,
            validFrom: '2025-01-01'
          });

          if (!this.codesByLevel.has(3)) {
            this.codesByLevel.set(3, new Set());
          }
          this.codesByLevel.get(3)!.add(l3Code);
        }
      }
    }

    this.logger.info(`Generated ${this.codes.size} sample KLASUS codes`);
  }

  public async start(): Promise<void> {
    await this.loadData();

    this.app.listen(this.config.port, () => {
      this.logger.info(`KLASUS Mock Service started on port ${this.config.port}`);
      this.logger.info(`Version: ${this.config.dataVersion}`);
      this.logger.info(`Codes loaded: ${this.codes.size}`);
    });
  }
}

// Start the service
if (require.main === module) {
  const config: Partial<MockConfig> = {
    port: parseInt(process.env.KLASUS_PORT || '8451'),
    dataVersion: process.env.DATA_VERSION || '2025',
    dataFile: process.env.DATA_FILE || '/app/data/klasus-2025.json'
  };

  const service = new KLASUSMockService(config);
  service.start();
}

export { KLASUSMockService, MockConfig, KLASUSCode };
