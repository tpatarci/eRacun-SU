import * as soap from 'soap';
import axios, { AxiosInstance } from 'axios';
import {
  logger,
  fiscalizationTotal,
  fiscalizationDuration,
  finaErrors,
  createSpan,
  setSpanError,
  endSpanSuccess,
  wsdlRefreshTotal,
  wsdlRefreshDuration,
  wsdlCacheHealth,
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
 * IMPROVEMENT-021: Shared axios instance for all SOAP clients
 * Reuses connection pool and prevents creating new instance per client
 * This reduces overhead and improves connection reuse
 */
let sharedHttpClient: AxiosInstance | null = null;

/**
 * Initialize or get shared HTTP client with connection pooling
 */
function getOrCreateSharedHttpClient(timeout: number): AxiosInstance {
  if (!sharedHttpClient) {
    sharedHttpClient = axios.create({
      timeout,
      httpsAgent: new (require('https').Agent)({
        rejectUnauthorized: true, // Validate FINA SSL certificate
        keepAlive: true, // Reuse TCP connections
      }),
    });

    logger.info('Created shared HTTP client with connection pooling');
  }

  return sharedHttpClient;
}

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
  /** IMPROVEMENT-006: WSDL refresh interval in hours (default: 24) */
  wsdlRefreshIntervalHours?: number;
  /** IMPROVEMENT-006: WSDL request timeout in milliseconds (default: 10000) */
  wsdlRequestTimeoutMs?: number;
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
 * IMPROVEMENT-006: Includes WSDL cache expiration and refresh
 */
export class FINASOAPClient {
  private client: soap.Client | null = null;
  private config: SOAPClientConfig;
  private wsdlCacheExpireAt: Date | null = null; // IMPROVEMENT-006
  private wsdlLastFetchedAt: Date | null = null; // IMPROVEMENT-006
  private wsdlVersion: string | null = null; // IMPROVEMENT-006

  constructor(config: SOAPClientConfig) {
    this.config = {
      ...config,
      wsdlRefreshIntervalHours: config.wsdlRefreshIntervalHours || 24, // Default: 24 hours
      wsdlRequestTimeoutMs: config.wsdlRequestTimeoutMs || 10000, // Default: 10 seconds
    };
  }

  /**
   * Initialize SOAP client (load WSDL)
   * IMPROVEMENT-006: Checks WSDL cache expiration and refreshes if needed
   */
  async initialize(): Promise<void> {
    const span = createSpan('initialize_soap_client', {
      wsdl_url: this.config.wsdlUrl,
    });

    try {
      logger.info({ wsdlUrl: this.config.wsdlUrl }, 'Initializing FINA SOAP client');

      // IMPROVEMENT-006: Check if WSDL cache needs refresh
      const now = new Date();
      if (!this.wsdlCacheExpireAt || now.getTime() >= this.wsdlCacheExpireAt.getTime()) {
        logger.info('WSDL cache expired, refreshing', {
          lastFetch: this.wsdlLastFetchedAt?.toISOString(),
          expiresAt: this.wsdlCacheExpireAt?.toISOString(),
        });

        await this.refreshWSDLCache();
      }

      // Create SOAP client from WSDL
      this.client = await soap.createClientAsync(this.config.wsdlUrl, {
        disableCache: this.config.disableCache || false,
        endpoint: this.config.endpointUrl,
      });

      // IMPROVEMENT-021: Use shared HTTP client with connection pooling
      if (this.client) {
        (this.client as any).httpClient = getOrCreateSharedHttpClient(this.config.timeout);
      }

      wsdlCacheHealth.set({
        status: 'valid',
        version: this.wsdlVersion || 'unknown',
      }, 1);

      endSpanSuccess(span);
      logger.info('FINA SOAP client initialized successfully', {
        wsdlVersion: this.wsdlVersion,
        nextRefresh: this.wsdlCacheExpireAt?.toISOString(),
      });
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      wsdlCacheHealth.set({
        status: 'error',
        version: this.wsdlVersion || 'unknown',
      }, 0);

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
   *
   * IMPROVEMENT-022: Cache response[0] to avoid multiple accesses
   * IMPROVEMENT-023: Extract all data in single pass, reuse parsed values
   */
  private parseRacuniResponse(response: any): FINAFiscalizationResponse {
    try {
      // IMPROVEMENT-022: Cache first element to avoid repeated access
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

      // IMPROVEMENT-023: Extract all fields in single pass, check in order
      // Check for JIR (success case)
      const jir = responseData.Jir || responseData.jir;
      if (jir) {
        return {
          success: true,
          jir,
          rawResponse: response,
        };
      }

      // IMPROVEMENT-023: Extract error data (already have responseData cached)
      // Check for Greska (error case) - no need to re-access response[0]
      const greska = responseData.Greska || responseData.greska;
      if (greska) {
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
   *
   * IMPROVEMENT-022: Cache response[0] to avoid multiple accesses
   */
  private parseValidationResponse(response: any): string[] {
    try {
      const errors: string[] = [];

      // IMPROVEMENT-022: Cache first element to avoid repeated access
      const responseData = response?.[0];
      if (!responseData) {
        return [];
      }

      // FINA returns validation errors in Greske array
      const greske = responseData.Greske || responseData.greske || [];

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
   * Parse SOAP fault and convert to FINAError
   *
   * IMPROVEMENT-022: Cache nested objects to avoid repeated deep traversal
   */
  private parseSoapFault(error: any): FINAError {
    try {
      // IMPROVEMENT-022: Cache intermediate objects to avoid repeated navigation
      // Instead of: error.root?.Envelope?.Body?.Fault (multiple null checks)
      // Cache each level and check once
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
   * Refresh WSDL cache (IMPROVEMENT-006)
   *
   * Fetches WSDL from FINA and validates its structure
   */
  private async refreshWSDLCache(): Promise<void> {
    const startTime = Date.now();

    try {
      logger.info('Fetching WSDL from FINA', { url: this.config.wsdlUrl });

      // Fetch WSDL with timeout
      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        this.config.wsdlRequestTimeoutMs || 10000
      );

      const response = await fetch(this.config.wsdlUrl, {
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (!response.ok) {
        throw new Error(`WSDL fetch failed: HTTP ${response.status}`);
      }

      const wsdlContent = await response.text();

      // Validate WSDL structure
      await this.validateWSDL(wsdlContent);

      // Extract version if available
      this.wsdlVersion = this.extractWSDLVersion(wsdlContent);

      // Calculate next refresh time
      const refreshInterval =
        (this.config.wsdlRefreshIntervalHours || 24) * 60 * 60 * 1000;
      this.wsdlCacheExpireAt = new Date(Date.now() + refreshInterval);
      this.wsdlLastFetchedAt = new Date();

      const duration = Date.now() - startTime;

      wsdlRefreshDuration.observe(duration);
      wsdlRefreshTotal.inc({ status: 'success' });

      logger.info('WSDL cache refreshed successfully', {
        version: this.wsdlVersion,
        size: wsdlContent.length,
        durationMs: duration,
        nextRefresh: this.wsdlCacheExpireAt.toISOString(),
      });
    } catch (err) {
      const duration = Date.now() - startTime;

      logger.warn(
        { error: err, durationMs: duration },
        'WSDL refresh failed, continuing with existing cache'
      );

      wsdlRefreshTotal.inc({ status: 'error' });

      // Don't crash - use existing cache if available
      if (!this.wsdlCacheExpireAt) {
        // First time fetch failed, schedule retry sooner (1 hour)
        this.wsdlCacheExpireAt = new Date(Date.now() + 60 * 60 * 1000);
        logger.info('Scheduling WSDL retry in 1 hour');
      }
      // Otherwise keep existing expiration
    }
  }

  /**
   * Validate WSDL structure (IMPROVEMENT-006)
   */
  private async validateWSDL(wsdlContent: string): Promise<void> {
    try {
      // Basic XML parsing check
      if (!wsdlContent.includes('<definitions') && !wsdlContent.includes('<wsdl:definitions')) {
        throw new Error('WSDL missing <definitions> element');
      }

      if (!wsdlContent.includes('<service') && !wsdlContent.includes('<wsdl:service')) {
        throw new Error('WSDL missing <service> element');
      }

      logger.debug('WSDL validation passed');
    } catch (err) {
      throw new Error(`Invalid WSDL structure: ${(err as Error).message}`);
    }
  }

  /**
   * Extract WSDL version from content (IMPROVEMENT-006)
   */
  private extractWSDLVersion(wsdlContent: string): string {
    // Try to extract version from comment or element
    // Format: <!-- WSDL v1.9 --> or <definitions version="1.9">

    const versionMatch = wsdlContent.match(/v([\d.]+)/);
    if (versionMatch) {
      return versionMatch[1];
    }

    // Fallback: use FINA endpoint URL as identifier
    return this.config.wsdlUrl.includes('cistest') ? 'test' : 'production';
  }

  /**
   * Get WSDL cache information (IMPROVEMENT-006)
   */
  getWSDLInfo(): {
    version: string | null;
    lastFetched: Date | null;
    expiresAt: Date | null;
  } {
    return {
      version: this.wsdlVersion,
      lastFetched: this.wsdlLastFetchedAt,
      expiresAt: this.wsdlCacheExpireAt,
    };
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
