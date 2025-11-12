import * as soap from 'soap';
import axios from 'axios';
import {
  logger,
  fiscalizationTotal,
  fiscalizationDuration,
  finaErrors,
  createSpan,
  setSpanError,
  endSpanSuccess,
} from './observability.js';
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
  timeout: number;
  /** Enable WSDL caching */
  disableCache?: boolean;
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

  constructor(config: SOAPClientConfig) {
    this.config = config;
  }

  /**
   * Initialize SOAP client (load WSDL)
   */
  async initialize(): Promise<void> {
    const span = createSpan('initialize_soap_client', {
      wsdl_url: this.config.wsdlUrl,
    });

    try {
      logger.info({ wsdlUrl: this.config.wsdlUrl }, 'Initializing FINA SOAP client');

      // Create SOAP client from WSDL
      this.client = await soap.createClientAsync(this.config.wsdlUrl, {
        disableCache: this.config.disableCache || false,
        endpoint: this.config.endpointUrl,
      });

      // Set timeout
      if (this.client) {
        (this.client as any).httpClient = axios.create({
          timeout: this.config.timeout,
          httpsAgent: new (await import('https')).Agent({
            rejectUnauthorized: true, // Validate FINA SSL certificate
          }),
        });
      }

      endSpanSuccess(span);
      logger.info('FINA SOAP client initialized successfully');
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ error, wsdlUrl: this.config.wsdlUrl }, 'Failed to initialize FINA SOAP client');
      throw new FINASOAPError(
        'Failed to initialize SOAP client',
        'SOAP_INIT_ERROR',
        error as Error
      );
    }
  }

  /**
   * Check if client is initialized
   */
  private ensureInitialized(): void {
    if (!this.client) {
      throw new FINASOAPError(
        'SOAP client not initialized. Call initialize() first.',
        'SOAP_NOT_INITIALIZED'
      );
    }
  }

  /**
   * Submit invoice for fiscalization (racuni operation)
   *
   * @param invoice - Invoice data
   * @param signedXml - XMLDSig signed SOAP envelope
   * @returns Fiscalization response with JIR
   */
  async fiscalizeInvoice(
    invoice: FINAInvoice,
    signedXml: string
  ): Promise<FINAFiscalizationResponse> {
    this.ensureInitialized();

    const span = createSpan('fiscalize_invoice', {
      invoice_number: invoice.brojRacuna,
      premises: invoice.oznPoslProstora,
      device: invoice.oznNapUr,
    });

    const startTime = Date.now();

    try {
      logger.info({
        invoiceNumber: invoice.brojRacuna,
        premises: invoice.oznPoslProstora,
        device: invoice.oznNapUr,
        totalAmount: invoice.ukupanIznos,
      }, 'Submitting invoice for fiscalization');

      // Call FINA racuni operation with signed XML
      // Note: The signed XML already contains the full SOAP envelope with signature
      const response = await this.client!.RacuniAsync({
        racun: this.buildInvoiceXML(invoice),
      });

      // Parse response
      const result = this.parseRacuniResponse(response);

      const duration = (Date.now() - startTime) / 1000;
      fiscalizationDuration.observe({ operation: 'racuni' }, duration);

      if (result.success) {
        fiscalizationTotal.inc({ operation: 'racuni', status: 'success' });
        endSpanSuccess(span);

        logger.info({
          invoiceNumber: invoice.brojRacuna,
          jir: result.jir,
          duration_ms: duration * 1000,
        }, 'Invoice fiscalized successfully');
      } else {
        fiscalizationTotal.inc({ operation: 'racuni', status: 'failure' });
        if (result.error) {
          finaErrors.inc({ error_code: result.error.code });
        }

        logger.error({
          invoiceNumber: invoice.brojRacuna,
          error: result.error,
          duration_ms: duration * 1000,
        }, 'Invoice fiscalization failed');
      }

      return result;
    } catch (error) {
      const duration = (Date.now() - startTime) / 1000;
      fiscalizationDuration.observe({ operation: 'racuni' }, duration);
      fiscalizationTotal.inc({ operation: 'racuni', status: 'failure' });

      setSpanError(span, error as Error);
      span.end();

      logger.error({
        invoiceNumber: invoice.brojRacuna,
        error,
        duration_ms: duration * 1000,
      }, 'Failed to fiscalize invoice');

      // Parse SOAP fault if available
      const finaError = this.parseSoapFault(error);
      finaErrors.inc({ error_code: finaError.code });

      return {
        success: false,
        error: finaError,
      };
    }
  }

  /**
   * Echo operation (health check)
   *
   * @param request - Echo request
   * @returns Echo response
   */
  async echo(request: FINAEchoRequest): Promise<FINAEchoResponse> {
    this.ensureInitialized();

    const span = createSpan('fina_echo');
    const startTime = Date.now();

    try {
      logger.debug({ message: request.message }, 'Sending echo request to FINA');

      const response = await this.client!.EchoAsync({
        poruka: request.message,
      });

      const duration = (Date.now() - startTime) / 1000;
      fiscalizationDuration.observe({ operation: 'echo' }, duration);
      fiscalizationTotal.inc({ operation: 'echo', status: 'success' });

      endSpanSuccess(span);

      logger.debug({
        responseMessage: response[0]?.poruka,
        duration_ms: duration * 1000,
      }, 'Echo response received');

      return {
        message: response[0]?.poruka || request.message,
      };
    } catch (error) {
      const duration = (Date.now() - startTime) / 1000;
      fiscalizationDuration.observe({ operation: 'echo' }, duration);
      fiscalizationTotal.inc({ operation: 'echo', status: 'failure' });

      setSpanError(span, error as Error);
      span.end();

      logger.error({ error, duration_ms: duration * 1000 }, 'Echo request failed');

      throw new FINASOAPError(
        'Echo operation failed',
        'ECHO_ERROR',
        error as Error
      );
    }
  }

  /**
   * Provjera operation (validation - TEST ONLY)
   *
   * @param request - Validation request
   * @returns Validation response
   */
  async validateInvoice(
    request: FINAValidationRequest
  ): Promise<FINAValidationResponse> {
    this.ensureInitialized();

    const span = createSpan('validate_invoice');
    const startTime = Date.now();

    try {
      logger.info({
        invoiceNumber: request.racun.brojRacuna,
      }, 'Validating invoice with FINA (TEST ONLY)');

      const response = await this.client!.ProvjeraAsync({
        racun: this.buildInvoiceXML(request.racun),
      });

      const duration = (Date.now() - startTime) / 1000;
      fiscalizationDuration.observe({ operation: 'provjera' }, duration);
      fiscalizationTotal.inc({ operation: 'provjera', status: 'success' });

      endSpanSuccess(span);

      logger.info({
        invoiceNumber: request.racun.brojRacuna,
        duration_ms: duration * 1000,
      }, 'Invoice validation completed');

      // Parse validation errors if any
      const errors = this.parseValidationResponse(response);

      return {
        success: errors.length === 0,
        errors: errors.length > 0 ? errors : undefined,
      };
    } catch (error) {
      const duration = (Date.now() - startTime) / 1000;
      fiscalizationDuration.observe({ operation: 'provjera' }, duration);
      fiscalizationTotal.inc({ operation: 'provjera', status: 'failure' });

      setSpanError(span, error as Error);
      span.end();

      logger.error({ error, duration_ms: duration * 1000 }, 'Invoice validation failed');

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
      })),
      Pnp: invoice.pnp?.map((pnp) => ({
        Porez: pnp.porez,
        Stopa: pnp.stopa,
        Iznos: pnp.iznos,
      })),
      OstaliPor: invoice.ostaliPor?.map((por) => ({
        Naziv: por.naziv,
        Stopa: por.stopa,
        Iznos: por.iznos,
      })),
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
      // FINA returns JIR in response
      const jir = response[0]?.Jir || response[0]?.jir;

      if (jir) {
        return {
          success: true,
          jir,
          rawResponse: response,
        };
      }

      // Check for error in response
      const error = this.parseResponseError(response);
      if (error) {
        return {
          success: false,
          error,
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

      // FINA returns validation errors in Greske array
      const greske = response[0]?.Greske || response[0]?.greske || [];

      for (const greska of greske) {
        const errorMsg = greska.Poruka || greska.poruka || 'Unknown error';
        errors.push(errorMsg);
      }

      return errors;
    } catch (error) {
      logger.error({ error, response }, 'Failed to parse validation response');
      return ['Failed to parse validation response'];
    }
  }

  /**
   * Parse response error (non-SOAP fault errors)
   */
  private parseResponseError(response: any): FINAError | null {
    try {
      // Check for error in response structure
      const error = response[0]?.Greska || response[0]?.greska;

      if (error) {
        return {
          code: error.SifraGreske || error.sifraGreske || 'UNKNOWN_ERROR',
          message: error.PorukaGreske || error.porukaGreske || 'Unknown error',
        };
      }

      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Parse SOAP fault and convert to FINAError
   */
  private parseSoapFault(error: any): FINAError {
    try {
      // SOAP fault structure
      const fault = error.root?.Envelope?.Body?.Fault;

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
   * Close SOAP client connection
   */
  async close(): Promise<void> {
    if (this.client) {
      logger.info('Closing FINA SOAP client');
      this.client = null;
    }
  }
}

/**
 * Create FINA SOAP client instance
 */
export function createFINAClient(config: SOAPClientConfig): FINASOAPClient {
  return new FINASOAPClient(config);
}
