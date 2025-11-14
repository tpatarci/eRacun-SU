/**
 * Feature Flags Configuration
 * Enables gradual rollout and independent development with mocks
 */

export interface FeatureFlags {
  // Mock services (all teams)
  useMockFINA: boolean;
  useMockPorezna: boolean;
  useMockOCR: boolean;
  useMockAI: boolean;
  useMockEmail: boolean;

  // Processing features
  enableAIValidation: boolean;
  enableAutoRetry: boolean;
  enableBatchProcessing: boolean;

  // Performance
  parallelValidation: boolean;
  cacheValidationResults: boolean;

  // Security
  enforceDigitalSignature: boolean;
  requireCertificateValidation: boolean;

  // Monitoring
  detailedLogging: boolean;
  performanceMetrics: boolean;
}

// Default configuration for development
export const defaultFeatureFlags: FeatureFlags = {
  useMockFINA: true,
  useMockPorezna: true,
  useMockOCR: true,
  useMockAI: true,
  useMockEmail: true,
  enableAIValidation: true,
  enableAutoRetry: true,
  enableBatchProcessing: false,
  parallelValidation: true,
  cacheValidationResults: true,
  enforceDigitalSignature: false,
  requireCertificateValidation: false,
  detailedLogging: true,
  performanceMetrics: true,
};

// Production configuration
export const productionFeatureFlags: FeatureFlags = {
  useMockFINA: false,
  useMockPorezna: false,
  useMockOCR: false,
  useMockAI: false,
  useMockEmail: false,
  enableAIValidation: true,
  enableAutoRetry: true,
  enableBatchProcessing: true,
  parallelValidation: true,
  cacheValidationResults: true,
  enforceDigitalSignature: true,
  requireCertificateValidation: true,
  detailedLogging: false,
  performanceMetrics: true,
};
