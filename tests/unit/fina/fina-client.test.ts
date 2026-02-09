import {
  FINASOAPClient,
  FINASOAPError,
  createFINAClient,
} from '../../../src/fina/fina-client';
import type { SOAPClientConfig, FINAFiscalizationResponse } from '../../../src/fina/types';

describe('FINA Client', () => {
  const mockConfig: SOAPClientConfig = {
    wsdlUrl: 'https://test.example.com/wsdl',
    timeout: 10000,
  };

  describe('constructor', () => {
    it('should create client instance', () => {
      const client = createFINAClient(mockConfig);
      expect(client).toBeInstanceOf(FINASOAPClient);
    });

    it('should use default timeout', () => {
      const client = createFINAClient({ wsdlUrl: mockConfig.wsdlUrl });
      expect(client).toBeInstanceOf(FINASOAPClient);
    });
  });

  describe('initialize', () => {
    it('should throw error when not initialized (Test 4.6)', async () => {
      const client = createFINAClient(mockConfig);

      // Try to call fiscalize without initialization
      await expect(client.fiscalizeInvoice({
        oib: '12345678903',
        datVrijeme: '2026-01-15T10:30:00',
        brojRacuna: '1/PP1/1',
        oznPoslProstora: 'PP1',
        oznNapUr: '1',
        ukupanIznos: '1250.00',
        zki: 'abc123',
        nacinPlac: 'T',
      }, 'signed')).rejects.toThrow('Client not initialized');
    });
  });

  describe('parseRacuniResponse', () => {
    let client: FINASOAPClient;

    beforeAll(() => {
      client = createFINAClient(mockConfig);
    });

    it('should parse success response with JIR (Test 4.7)', () => {
      const response = [{ Jir: 'ABC-123-DEF' }];

      // Access private method via type assertion for testing
      const parseFn = (client as any).parseRacuniResponse.bind(client);
      const result: FINAFiscalizationResponse = parseFn(response);

      expect(result.success).toBe(true);
      expect(result.jir).toBe('ABC-123-DEF');
    });

    it('should parse error response (Test 4.8)', () => {
      const response = [{
        Greska: {
          SifraGreske: 's:001',
          PorukaGreske: 'Invalid OIB format',
        },
      }];

      const parseFn = (client as any).parseRacuniResponse.bind(client);
      const result: FINAFiscalizationResponse = parseFn(response);

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('s:001');
    });

    it('should handle empty response (Test 4.9)', () => {
      const response = [];

      const parseFn = (client as any).parseRacuniResponse.bind(client);
      const result: FINAFiscalizationResponse = parseFn(response);

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('EMPTY_RESPONSE');
    });
  });

  describe('parseSoapFault', () => {
    let client: FINASOAPClient;

    beforeAll(() => {
      client = createFINAClient(mockConfig);
    });

    it('should parse SOAP fault error', () => {
      const error = {
        root: {
          Envelope: {
            Body: {
              Fault: {
                faultcode: 's:002',
                faultstring: 'Validation failed',
              },
            },
          },
        },
      };

      const parseFn = (client as any).parseSoapFault.bind(client);
      const result = parseFn(error);

      expect(result.code).toBe('s:002');
      expect(result.message).toBe('Validation failed');
    });

    it('should parse network error', () => {
      const error = {
        code: 'ETIMEDOUT',
        message: 'Connection timeout',
        stack: 'error stack',
      };

      const parseFn = (client as any).parseSoapFault.bind(client);
      const result = parseFn(error);

      expect(result.code).toBe('NETWORK_ERROR');
      expect(result.message).toContain('Connection timeout');
    });
  });

  describe('FINASOAPError', () => {
    it('should create error with code and message', () => {
      const error = new FINASOAPError('Test error', 'E001');

      expect(error.message).toBe('Test error');
      expect(error.code).toBe('E001');
      expect(error.name).toBe('FINASOAPError');
    });

    it('should support cause error', () => {
      const cause = new Error('Underlying error');
      const error = new FINASOAPError('Test error', 'E001', cause);

      expect(error.cause).toBe(cause);
    });
  });

  describe('buildInvoiceXML', () => {
    let client: FINASOAPClient;

    beforeAll(() => {
      client = createFINAClient(mockConfig);
    });

    it('should build invoice XML structure', () => {
      const invoice = {
        oib: '12345678903',
        datVrijeme: '2026-01-15T10:30:00',
        brojRacuna: '1/PP1/1',
        oznPoslProstora: 'PP1',
        oznNapUr: '1',
        ukupanIznos: '1250.00',
        zki: 'abc123',
        nacinPlac: 'T' as const,
        pdv: [
          { porez: '1000.00', stopa: '25.00', iznos: '250.00' },
        ],
      };

      const buildFn = (client as any).buildInvoiceXML.bind(client);
      const result = buildFn(invoice);

      expect(result.Oib).toBe('12345678903');
      expect(result.BrojRacuna.BrRac.BrOznRac).toBe('1/PP1/1');
      expect(result.Pdv).toHaveLength(1);
      expect(result.Pdv[0].Porez).toBe('1000.00');
    });
  });

  describe('No banned deps (Test 4.10)', () => {
    it('should have no opossum, opentelemetry, prom-client, or amqplib', async () => {
      const fs = require('fs');
      const content = fs.readFileSync('src/fina/fina-client.ts', 'utf8');

      expect(content).not.toContain('opossum');
      expect(content).not.toContain('opentelemetry');
      expect(content).not.toContain('prom-client');
      expect(content).not.toContain('amqplib');
    });
  });
});
