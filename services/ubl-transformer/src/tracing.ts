/**
 * OpenTelemetry Tracing Configuration
 *
 * Implements distributed tracing for the ubl-transformer service.
 * Exports traces to Jaeger for visualization and analysis.
 */

import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { Resource } from '@opentelemetry/resources';
import { ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';
import { BatchSpanProcessor } from '@opentelemetry/sdk-trace-node';

const serviceName = process.env.SERVICE_NAME || 'ubl-transformer';
const serviceVersion = process.env.SERVICE_VERSION || '1.0.0';
const otlpEndpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4318/v1/traces';

// Configure resource with service information
const resource = new Resource({
  [ATTR_SERVICE_NAME]: serviceName,
  [ATTR_SERVICE_VERSION]: serviceVersion,
});

// Configure OTLP exporter (for Jaeger)
const traceExporter = new OTLPTraceExporter({
  url: otlpEndpoint,
  headers: {},
});

// Initialize OpenTelemetry SDK
const sdk = new NodeSDK({
  resource,
  spanProcessor: new BatchSpanProcessor(traceExporter),
  instrumentations: [
    getNodeAutoInstrumentations({
      // Automatically instrument common libraries
      '@opentelemetry/instrumentation-http': {
        enabled: true,
      },
      '@opentelemetry/instrumentation-express': {
        enabled: true,
      },
    }),
  ],
});

/**
 * Start OpenTelemetry SDK
 *
 * MUST be called before importing any other modules
 * to ensure automatic instrumentation works.
 */
export async function startTracing(): Promise<void> {
  try {
    await sdk.start();
    console.log(`[Tracing] OpenTelemetry initialized for ${serviceName}`);
    console.log(`[Tracing] Exporting to: ${otlpEndpoint}`);
  } catch (error) {
    console.error('[Tracing] Failed to initialize OpenTelemetry:', error);
    // Don't fail startup if tracing fails
  }
}

/**
 * Gracefully shutdown OpenTelemetry SDK
 *
 * Ensures all pending spans are exported before shutdown.
 */
export async function stopTracing(): Promise<void> {
  try {
    await sdk.shutdown();
    console.log('[Tracing] OpenTelemetry shutdown complete');
  } catch (error) {
    console.error('[Tracing] Error during shutdown:', error);
  }
}

// Graceful shutdown on process signals
process.on('SIGTERM', async () => {
  await stopTracing();
  process.exit(0);
});

process.on('SIGINT', async () => {
  await stopTracing();
  process.exit(0);
});
