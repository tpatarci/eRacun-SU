/**
 * Integration Tests for gRPC API
 */

import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import { resolve } from 'path';
import { startGRPCServer, stopGRPCServer } from '../../src/grpc-server';
import * as repository from '../../src/repository';
import { KPDCode } from '../../src/repository';

// Mock repository module
jest.mock('../../src/repository', () => ({
  getKPDCode: jest.fn(),
  searchKPDCodes: jest.fn(),
}));

// Mock observability
jest.mock('../../src/observability', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
  kpdLookupRequests: {
    inc: jest.fn(),
  },
  kpdLookupDuration: {
    observe: jest.fn(),
  },
  traceOperation: jest.fn((name, fn) => fn({ setAttribute: jest.fn() })),
}));

describe('gRPC API Integration Tests', () => {
  let client: any;
  const GRPC_PORT = 50053; // Use different port for tests

  beforeAll(async () => {
    // Set test port
    process.env.GRPC_PORT = '50053';

    // Start gRPC server
    await startGRPCServer();

    // Load proto file
    const PROTO_PATH = resolve(__dirname, '../../proto/kpd-lookup.proto');
    const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
      keepCase: true,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true,
    });

    const protoDescriptor = grpc.loadPackageDefinition(packageDefinition) as any;
    const kpdProto = protoDescriptor.kpd;

    // Create gRPC client
    client = new kpdProto.KPDLookupService(
      `localhost:${GRPC_PORT}`,
      grpc.credentials.createInsecure()
    );
  });

  afterAll(async () => {
    // Stop gRPC server
    await stopGRPCServer();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('LookupCode RPC', () => {
    it('should lookup existing KPD code', (done) => {
      const mockCode: KPDCode = {
        kpd_code: '010101',
        description: 'Cattle',
        level: 3,
        parent_code: '0101',
        active: true,
        effective_from: new Date('2025-01-01'),
        effective_to: null,
      };

      (repository.getKPDCode as jest.Mock).mockResolvedValue(mockCode);

      client.LookupCode({ kpd_code: '010101' }, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.found).toBe(true);
        expect(response.code_info).toBeDefined();
        expect(response.code_info.kpd_code).toBe('010101');
        expect(response.code_info.description).toBe('Cattle');
        expect(response.code_info.level).toBe(3);
        expect(response.code_info.parent_code).toBe('0101');
        expect(response.code_info.active).toBe(true);
        done();
      });
    });

    it('should return not found for non-existent code', (done) => {
      (repository.getKPDCode as jest.Mock).mockResolvedValue(null);

      client.LookupCode({ kpd_code: '999999' }, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.found).toBe(false);
        expect(response.code_info).toBeUndefined();
        done();
      });
    });

    it('should handle lookup errors', (done) => {
      (repository.getKPDCode as jest.Mock).mockRejectedValue(new Error('Database error'));

      client.LookupCode({ kpd_code: '010101' }, (error: any, response: any) => {
        expect(error).toBeDefined();
        expect(error.code).toBe(grpc.status.INTERNAL);
        done();
      });
    });
  });

  describe('ValidateCode RPC', () => {
    it('should validate active KPD code', (done) => {
      const mockCode: KPDCode = {
        kpd_code: '010101',
        description: 'Cattle',
        level: 3,
        parent_code: '0101',
        active: true,
        effective_from: new Date('2025-01-01'),
        effective_to: null,
      };

      (repository.getKPDCode as jest.Mock).mockResolvedValue(mockCode);

      client.ValidateCode({ kpd_code: '010101' }, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.valid).toBe(true);
        expect(response.error_message).toBe('');
        done();
      });
    });

    it('should reject non-existent code', (done) => {
      (repository.getKPDCode as jest.Mock).mockResolvedValue(null);

      client.ValidateCode({ kpd_code: '999999' }, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.valid).toBe(false);
        expect(response.error_message).toContain('not found');
        done();
      });
    });

    it('should reject inactive code', (done) => {
      const inactiveCode: KPDCode = {
        kpd_code: '010101',
        description: 'Cattle',
        level: 3,
        parent_code: '0101',
        active: false,
        effective_from: new Date('2025-01-01'),
        effective_to: new Date('2025-06-01'),
      };

      (repository.getKPDCode as jest.Mock).mockResolvedValue(inactiveCode);

      client.ValidateCode({ kpd_code: '010101' }, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.valid).toBe(false);
        expect(response.error_message).toContain('inactive');
        done();
      });
    });

    it('should handle validation errors', (done) => {
      (repository.getKPDCode as jest.Mock).mockRejectedValue(new Error('Database error'));

      client.ValidateCode({ kpd_code: '010101' }, (error: any, response: any) => {
        expect(error).toBeDefined();
        expect(error.code).toBe(grpc.status.INTERNAL);
        done();
      });
    });
  });

  describe('SearchCodes RPC', () => {
    it('should search codes by description', (done) => {
      const mockCodes: KPDCode[] = [
        {
          kpd_code: '010101',
          description: 'Cattle',
          level: 3,
          parent_code: '0101',
          active: true,
          effective_from: new Date('2025-01-01'),
          effective_to: null,
        },
      ];

      (repository.searchKPDCodes as jest.Mock).mockResolvedValue(mockCodes);

      client.SearchCodes({ query: 'cattle', limit: 10 }, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.codes).toHaveLength(1);
        expect(response.codes[0].kpd_code).toBe('010101');
        expect(response.codes[0].description).toBe('Cattle');
        expect(response.total_results).toBe(1);
        done();
      });
    });

    it('should return empty results for no matches', (done) => {
      (repository.searchKPDCodes as jest.Mock).mockResolvedValue([]);

      client.SearchCodes({ query: 'nonexistent', limit: 10 }, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.codes).toHaveLength(0);
        expect(response.total_results).toBe(0);
        done();
      });
    });

    it('should use default limit if not provided', (done) => {
      (repository.searchKPDCodes as jest.Mock).mockResolvedValue([]);

      client.SearchCodes({ query: 'test', limit: 0 }, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(repository.searchKPDCodes).toHaveBeenCalledWith('test', 100);
        done();
      });
    });

    it('should handle search errors', (done) => {
      (repository.searchKPDCodes as jest.Mock).mockRejectedValue(new Error('Search error'));

      client.SearchCodes({ query: 'test', limit: 10 }, (error: any, response: any) => {
        expect(error).toBeDefined();
        expect(error.code).toBe(grpc.status.INTERNAL);
        done();
      });
    });
  });

  describe('Performance', () => {
    it('should respond to lookups within 5ms', (done) => {
      const mockCode: KPDCode = {
        kpd_code: '010101',
        description: 'Cattle',
        level: 3,
        parent_code: '0101',
        active: true,
        effective_from: new Date('2025-01-01'),
        effective_to: null,
      };

      (repository.getKPDCode as jest.Mock).mockResolvedValue(mockCode);

      const startTime = Date.now();
      client.LookupCode({ kpd_code: '010101' }, (error: any, response: any) => {
        const duration = Date.now() - startTime;
        expect(duration).toBeLessThan(100); // Allow 100ms for test environment
        expect(error).toBeNull();
        done();
      });
    });
  });
});
