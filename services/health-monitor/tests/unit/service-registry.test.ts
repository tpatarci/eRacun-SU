/**
 * Unit Tests for Service Registry Module
 */

import fs from 'fs';
import {
  loadServiceRegistry,
  getAllServices,
  getCriticalServices,
  getExternalDependencies,
  getServiceByName,
  getServicesByLayer,
  validateServiceRegistry,
  resetServiceRegistry,
} from '../../src/service-registry';

// Mock fs
jest.mock('fs');
const mockedFs = fs as jest.Mocked<typeof fs>;

// Mock observability
jest.mock('../../src/observability', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
  },
}));

describe('Service Registry Module', () => {
  const validRegistry = {
    services: [
      {
        name: 'xsd-validator',
        health_url: 'http://xsd-validator:8088/health',
        ready_url: 'http://xsd-validator:8088/ready',
        critical: true,
        poll_interval_ms: 15000,
        layer: 3,
        description: 'XSD schema validator',
      },
      {
        name: 'audit-logger',
        health_url: 'http://audit-logger:8083/health',
        ready_url: 'http://audit-logger:8083/ready',
        critical: false,
        poll_interval_ms: 30000,
        layer: 9,
      },
      {
        name: 'notification-service',
        health_url: 'http://notification-service:8085/health',
        ready_url: 'http://notification-service:8085/ready',
        critical: true,
        poll_interval_ms: 15000,
        layer: 8,
      },
    ],
    external_dependencies: [
      {
        name: 'postgresql',
        health_url: 'postgresql://localhost:5432',
        ready_url: 'postgresql://localhost:5432',
        critical: true,
        poll_interval_ms: 30000,
      },
      {
        name: 'rabbitmq',
        health_url: 'http://rabbitmq:15672/api/healthchecks/node',
        ready_url: 'http://rabbitmq:15672/api/healthchecks/node',
        critical: true,
        poll_interval_ms: 30000,
      },
    ],
  };

  beforeEach(() => {
    jest.clearAllMocks();
    resetServiceRegistry();
  });

  describe('loadServiceRegistry()', () => {
    it('should load service registry from file', () => {
      mockedFs.readFileSync.mockReturnValue(JSON.stringify(validRegistry));

      const registry = loadServiceRegistry('/path/to/services.json');

      expect(registry).toBeDefined();
      expect(registry.services).toHaveLength(3);
      expect(registry.external_dependencies).toHaveLength(2);
    });

    it('should throw error if file not found', () => {
      mockedFs.readFileSync.mockImplementation(() => {
        throw new Error('ENOENT: no such file');
      });

      expect(() => loadServiceRegistry('/nonexistent.json')).toThrow(
        /Failed to load service registry/
      );
    });

    it('should throw error if JSON is invalid', () => {
      mockedFs.readFileSync.mockReturnValue('invalid json');

      expect(() => loadServiceRegistry()).toThrow();
    });

    it('should use default path if none provided', () => {
      mockedFs.readFileSync.mockReturnValue(JSON.stringify(validRegistry));

      loadServiceRegistry();

      expect(mockedFs.readFileSync).toHaveBeenCalledWith(
        expect.stringContaining('config/services.json'),
        'utf-8'
      );
    });
  });

  describe('getAllServices()', () => {
    it('should return all services', () => {
      mockedFs.readFileSync.mockReturnValue(JSON.stringify(validRegistry));
      loadServiceRegistry();

      const services = getAllServices();

      expect(services).toHaveLength(3);
      expect(services[0].name).toBe('xsd-validator');
    });

    it('should throw error if registry not loaded', () => {
      expect(() => getAllServices()).toThrow(
        'Service registry not loaded. Call loadServiceRegistry() first.'
      );
    });
  });

  describe('getCriticalServices()', () => {
    it('should return only critical services', () => {
      mockedFs.readFileSync.mockReturnValue(JSON.stringify(validRegistry));
      loadServiceRegistry();

      const criticalServices = getCriticalServices();

      expect(criticalServices).toHaveLength(2);
      expect(criticalServices.every((s) => s.critical)).toBe(true);
      expect(criticalServices.map((s) => s.name)).toEqual([
        'xsd-validator',
        'notification-service',
      ]);
    });

    it('should throw error if registry not loaded', () => {
      expect(() => getCriticalServices()).toThrow();
    });
  });

  describe('getExternalDependencies()', () => {
    it('should return external dependencies', () => {
      mockedFs.readFileSync.mockReturnValue(JSON.stringify(validRegistry));
      loadServiceRegistry();

      const deps = getExternalDependencies();

      expect(deps).toHaveLength(2);
      expect(deps.map((d) => d.name)).toEqual(['postgresql', 'rabbitmq']);
    });

    it('should throw error if registry not loaded', () => {
      expect(() => getExternalDependencies()).toThrow();
    });
  });

  describe('getServiceByName()', () => {
    beforeEach(() => {
      mockedFs.readFileSync.mockReturnValue(JSON.stringify(validRegistry));
      loadServiceRegistry();
    });

    it('should find service by name', () => {
      const service = getServiceByName('xsd-validator');

      expect(service).toBeDefined();
      expect(service?.name).toBe('xsd-validator');
      expect(service?.health_url).toBe('http://xsd-validator:8088/health');
    });

    it('should return undefined for non-existent service', () => {
      const service = getServiceByName('non-existent');

      expect(service).toBeUndefined();
    });

    it('should be case-sensitive', () => {
      const service = getServiceByName('XSD-VALIDATOR');

      expect(service).toBeUndefined();
    });
  });

  describe('getServicesByLayer()', () => {
    beforeEach(() => {
      mockedFs.readFileSync.mockReturnValue(JSON.stringify(validRegistry));
      loadServiceRegistry();
    });

    it('should return services in specified layer', () => {
      const layer3Services = getServicesByLayer(3);

      expect(layer3Services).toHaveLength(1);
      expect(layer3Services[0].name).toBe('xsd-validator');
    });

    it('should return empty array for layer with no services', () => {
      const services = getServicesByLayer(99);

      expect(services).toHaveLength(0);
    });

    it('should handle services without layer attribute', () => {
      const layer8Services = getServicesByLayer(8);

      expect(layer8Services).toHaveLength(1);
      expect(layer8Services[0].name).toBe('notification-service');
    });
  });

  describe('validateServiceRegistry()', () => {
    it('should return empty array for valid registry', () => {
      const errors = validateServiceRegistry(validRegistry);

      expect(errors).toEqual([]);
    });

    it('should detect missing services array', () => {
      const invalid = {
        ...validRegistry,
        services: null as any,
      };

      const errors = validateServiceRegistry(invalid);

      expect(errors).toContain('services must be an array');
    });

    it('should detect missing external_dependencies array', () => {
      const invalid = {
        ...validRegistry,
        external_dependencies: null as any,
      };

      const errors = validateServiceRegistry(invalid);

      expect(errors).toContain('external_dependencies must be an array');
    });

    it('should detect missing service name', () => {
      const invalid = {
        ...validRegistry,
        services: [
          {
            health_url: 'http://test',
            ready_url: 'http://test',
            critical: true,
            poll_interval_ms: 15000,
          } as any,
        ],
      };

      const errors = validateServiceRegistry(invalid);

      expect(errors.some((e) => e.includes("missing 'name'"))).toBe(true);
    });

    it('should detect missing health_url', () => {
      const invalid = {
        ...validRegistry,
        services: [
          {
            name: 'test',
            ready_url: 'http://test',
            critical: true,
            poll_interval_ms: 15000,
          } as any,
        ],
      };

      const errors = validateServiceRegistry(invalid);

      expect(errors.some((e) => e.includes("missing 'health_url'"))).toBe(true);
    });

    it('should detect missing ready_url', () => {
      const invalid = {
        ...validRegistry,
        services: [
          {
            name: 'test',
            health_url: 'http://test',
            critical: true,
            poll_interval_ms: 15000,
          } as any,
        ],
      };

      const errors = validateServiceRegistry(invalid);

      expect(errors.some((e) => e.includes("missing 'ready_url'"))).toBe(true);
    });

    it('should detect invalid critical field', () => {
      const invalid = {
        ...validRegistry,
        services: [
          {
            name: 'test',
            health_url: 'http://test',
            ready_url: 'http://test',
            critical: 'yes' as any,
            poll_interval_ms: 15000,
          },
        ],
      };

      const errors = validateServiceRegistry(invalid);

      expect(errors.some((e) => e.includes("'critical' must be a boolean"))).toBe(true);
    });

    it('should detect invalid poll_interval_ms', () => {
      const invalid = {
        ...validRegistry,
        services: [
          {
            name: 'test',
            health_url: 'http://test',
            ready_url: 'http://test',
            critical: true,
            poll_interval_ms: 500, // < 1000
          },
        ],
      };

      const errors = validateServiceRegistry(invalid);

      expect(errors.some((e) => e.includes("'poll_interval_ms' must be a number >= 1000"))).toBe(
        true
      );
    });

    it('should return multiple errors for multiple invalid services', () => {
      const invalid = {
        services: [
          { name: 'test1' } as any,
          { name: 'test2' } as any,
        ],
        external_dependencies: [],
      };

      const errors = validateServiceRegistry(invalid);

      expect(errors.length).toBeGreaterThan(2);
    });
  });

  describe('resetServiceRegistry()', () => {
    it('should reset service registry', () => {
      mockedFs.readFileSync.mockReturnValue(JSON.stringify(validRegistry));
      loadServiceRegistry();

      resetServiceRegistry();

      expect(() => getAllServices()).toThrow();
    });
  });
});
