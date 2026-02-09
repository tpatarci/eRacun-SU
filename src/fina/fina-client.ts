import * as soap from 'soap';
import { logger } from '../shared/logger.js';
import type {
  FINAInvoice,
  FINAFiscalizationResponse,
  FINAEchoRequest,
  FINAEchoResponse,
  FINAValidationRequest,
  FINAValidationResponse,
  FINAError,
} from './types.js';

/**
 * SOAP Client Configuration
 */
export interface SOAPClientConfig {
  /** WSDL URL */
  wsdlUrl: string;
  /** Endpoint URL (override WSDL endpoint if needed) */
  endpointUrl?: string;
  /** Request timeout (milliseconds) */
  timeout?: number;
}

/**
 * FINA SOAP Client Error
 */
export class FINASOAPError extends Error {
  constructor(
    message: string,
    public code: string,
    public cause?: Error
  ) {
    super(message);
    this.name = 'FINASOAPError';
  }
}

/**
 * FINA SOAP Client
 *
 * Handles all SOAP communication with FINA Fiscalization Service
 */
export class FINASOAPClient {
  private client: soap.Client | null = null;
  private config: SOAPClientConfig;
  private initialized = false;

  constructor(config: SOAPClientConfig) {
    this.config = {
      timeout: config.timeout || 30000,
      ...config,
    };
  }

  /**
   * Initialize SOAP client
   */
  async initialize(): Promise<void> {
    try {
      logger.info({ wsdlUrl: this.config.wsdlUrl }, 'Initializing FINA SOAP client');

      this.client = await soap.createClientAsync(this.config.wsdlUrl);

      if (this.config.endpointUrl) {
        this.client.setEndpoint(this.config.endpointUrl);
      }

      this.initialized = true;
      logger.info('FINA SOAP client initialized successfully');
    } catch (error) {
      logger.error({ error }, 'Failed to initialize FINA SOAP client');
      throw new FINASOAPError(
        'Failed to initialize SOAP client',
        'INIT_ERROR',
        error as Error
      );
    }
  }

  /**
   * Ensure client is initialized
   */
  private ensureInitialized(): void {
    if (!this.initialized || !this.client) {
      throw new FINASOAPError(
        'Client not initialized. Call initialize() first.',
        'NOT_INITIALIZED'
      );
    }
  }

  /**
   * Fiscalize an invoice with retry logic
   */
  async fiscalizeInvoice(
    invoice: FINAInvoice,
    signedXml: string
  ): Promise<FINAFiscalizationResponse> {
    return this.withRetry(
      async () => this.fiscalizeInvoiceInternal(invoice, signedXml),
      'fiscalizeInvoice'
    );
  }

  /**
   * Internal fiscalize implementation
   */
  private async fiscalizeInvoiceInternal(
    invoice: FINAInvoice,
    signedXml: string
  ): Promise<FINAFiscalizationResponse> {
    this.ensureInitialized();
    const client = this.client!;

    try {
      logger.info({
        oib: invoice.oib,
        brojRacuna: invoice.brojRacuna,
      }, 'Fiscalizing invoice');

      // Build request object
      const requestArgs = this.buildInvoiceXML(invoice);

      // Call SOAP service
      const response = await client.RacunZahtjevAsync({
        RacunZahtjev: {
          Racun: requestArgs,
        },
      });

      return this.parseRacuniResponse(response);
    } catch (error) {
      const finaError = this.parseSoapFault(error);
      logger.error({
        error: finaError,
        oib: invoice.oib,
      }, 'Invoice fiscalization failed');

      throw new FINASOAPError(
        finaError.message,
        finaError.code,
        error as Error
      );
    }
  }

  /**
   * Echo request (health check)
   */
  async echo(request: FINAEchoRequest): Promise<FINAEchoResponse> {
    return this.withRetry(
      async () => this.echoInternal(request),
      'echo'
    );
  }

  /**
   * Internal echo implementation
   */
  private async echoInternal(request: FINAEchoRequest): Promise<FINAEchoResponse> {
    this.ensureInitialized();
    const client = this.client!;

    try {
      logger.info('Sending echo request to FINA');

      const response = await client.EchoAsync({
        Poruka: request.message,
      });

      const result = response?.[0];
      return {
        message: result?.Poruka || result?.poruka || 'No response',
      };
    } catch (error) {
      logger.error({ error }, 'Echo request failed');
      throw new FINASOAPError(
        'Echo request failed',
        'ECHO_ERROR',
        error as Error
      );
    }
  }

  /**
   * Validate invoice (test environment only)
   */
  async validateInvoice(
    request: FINAValidationRequest
  ): Promise<FINAValidationResponse> {
    return this.withRetry(
      async () => this.validateInvoiceInternal(request),
      'validateInvoice'
    );
  }

  /**
   * Internal validate implementation
   */
  private async validateInvoiceInternal(
    request: FINAValidationRequest
  ): Promise<FINAValidationResponse> {
    this.ensureInitialized();
    const client = this.client!;

    try {
      logger.info('Validating invoice with FINA');

      const response = await client.ProvjeraAsync({
        Racun: this.buildInvoiceXML(request.racun),
      });

      const errors = this.parseValidationResponse(response);

      return {
        success: errors.length === 0,
        errors: errors.length > 0 ? errors : undefined,
      };
    } catch (error) {
      logger.error({ error }, 'Invoice validation failed');
      throw new FINASOAPError(
        'Validation operation failed',
        'VALIDATION_ERROR',
        error as Error
      );
    }
  }

  /**
   * Build invoice XML for SOAP request
   */
  private buildInvoiceXML(invoice: FINAInvoice): any {
    return {
      Oib: invoice.oib,
      DatVrijeme: invoice.datVrijeme,
      BrojRacuna: {
        BrRac: {
          BrOznRac: invoice.brojRacuna,
          OznPosPr: invoice.oznPoslProstora,
          OznNapUr: invoice.oznNapUr,
        },
      },
      Pdv: invoice.pdv?.map((pdv) => ({
        Porez: pdv.porez,
        Stopa: pdv.stopa,
        Iznos: pdv.iznos,
      })) || [],
      Pnp: invoice.pnp?.map((pnp) => ({
        Porez: pnp.porez,
        Stopa: pnp.stopa,
        Iznos: pnp.iznos,
      })) || [],
      OstaliPor: invoice.ostaliPor?.map((por) => ({
        Naziv: por.naziv,
        Stopa: por.stopa,
        Iznos: por.iznos,
      })) || [],
      IznosUkupno: invoice.ukupanIznos,
      NacinPlac: invoice.nacinPlac,
      ZastKod: invoice.zki,
      NakDost: invoice.nakDost,
      ParagonBrRac: invoice.paragonBroj,
      SpecNamj: invoice.specNamj,
    };
  }

  /**
   * Parse racuni response and extract JIR
   */
  private parseRacuniResponse(response: any): FINAFiscalizationResponse {
    try {
      const responseData = response?.[0];
      if (!responseData) {
        return {
          success: false,
          error: {
            code: 'EMPTY_RESPONSE',
            message: 'Empty response from FINA',
          },
          rawResponse: response,
        };
      }

      // Check for JIR (success case)
      const jir = responseData.Jir || responseData.jir;
      if (jir) {
        return {
          success: true,
          jir,
          rawResponse: response,
        };
      }

      // Check for Greska (error case)
      const greska = responseData.Greska || responseData.greska;

      if (greska && typeof greska === 'object') {
        return {
          success: false,
          error: {
            code: greska.SifraGreske || greska.sifraGreske || 'UNKNOWN_ERROR',
            message: greska.PorukaGreske || greska.porukaGreske || 'Unknown error',
          },
          rawResponse: response,
        };
      }

      // Unknown response format
      return {
        success: false,
        error: {
          code: 'UNKNOWN_RESPONSE',
          message: 'Unknown response format from FINA',
        },
        rawResponse: response,
      };
    } catch (error) {
      logger.error({ error, response }, 'Failed to parse racuni response');

      return {
        success: false,
        error: {
          code: 'PARSE_ERROR',
          message: 'Failed to parse FINA response',
        },
      };
    }
  }

  /**
   * Parse validation response and extract errors
   */
  private parseValidationResponse(response: any): string[] {
    try {
      const errors: string[] = [];

      const responseData = response?.[0];
      if (!responseData) {
        return [];
      }

      // FINA returns validation errors in Greske array
      const greske = responseData.Greske || responseData.greske || [];

      for (const greska of greske) {
        if (greska && typeof greska === 'object') {
          const errorMsg = greska.Poruka || greska.poruka || 'Unknown error';
          errors.push(errorMsg);
        }
      }

      return errors;
    } catch (error) {
      logger.error({ error, response }, 'Failed to parse validation response');
      return ['Failed to parse validation response'];
    }
  }

  /**
   * Parse SOAP fault and convert to FINAError
   */
  private parseSoapFault(error: any): FINAError {
    try {
      const root = error?.root;
      const envelope = root?.Envelope;
      const body = envelope?.Body;
      const fault = body?.Fault;

      if (fault) {
        const faultcode = fault.faultcode || 's:999';
        const faultstring = fault.faultstring || error.message || 'SOAP fault';

        return {
          code: faultcode,
          message: faultstring,
          stack: error.stack,
        };
      }

      // Network or other errors
      if (error.code === 'ETIMEDOUT' || error.code === 'ECONNREFUSED') {
        return {
          code: 'NETWORK_ERROR',
          message: `Network error: ${error.message}`,
          stack: error.stack,
        };
      }

      // Generic error
      return {
        code: 's:999',
        message: error.message || 'Unknown SOAP error',
        stack: error.stack,
      };
    } catch (parseError) {
      logger.error({ parseError, originalError: error }, 'Failed to parse SOAP fault');

      return {
        code: 's:999',
        message: 'Failed to parse SOAP fault',
      };
    }
  }

  /**
   * Simple retry pattern with exponential backoff
   */
  private async withRetry<T>(
    fn: () => Promise<T>,
    operation: string,
    maxAttempts = 3
  ): Promise<T> {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        return await fn();
      } catch (error) {
        if (attempt === maxAttempts) {
          logger.error({
            operation,
            attempt,
            maxAttempts,
          }, 'All retry attempts exhausted');
          throw error;
        }

        const delay = Math.pow(2, attempt - 1) * 1000; // 1s, 2s, 4s
        logger.warn({
          operation,
          attempt,
          maxAttempts,
          delayMs: delay,
          error: (error as Error).message,
        }, 'Retrying after failure');

        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }

    throw new Error('Unreachable');
  }

  /**
   * Close the client and cleanup resources
   */
  async close(): Promise<void> {
    this.client = null;
    this.initialized = false;
    logger.info('FINA SOAP client closed');
  }
}

/**
 * Create a new FINA SOAP client instance
 */
export function createFINAClient(config: SOAPClientConfig): FINASOAPClient {
  return new FINASOAPClient(config);
}
