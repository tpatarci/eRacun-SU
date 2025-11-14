/**
 * Dependency Injection Container
 * Configures Inversify container with feature flag support
 */

import 'reflect-metadata';
import { Container } from 'inversify';
import { TYPES } from './types';
import { Config, loadConfig } from './config';

// Import interfaces
import {
  IValidationService,
  IKPDValidatorService,
  IOIBValidatorService,
  IFINAService,
  IPoreznaService,
  IOCRService,
  IAIValidationService,
} from '@eracun/adapters';

// Import mock implementations
import {
  MockValidationService,
  MockKPDValidatorService,
  MockOIBValidatorService,
  MockFINAService,
  MockPoreznaService,
  MockOCRService,
  MockAIValidationService,
} from '@eracun/mocks';

/**
 * Create and configure the DI container
 */
export function createContainer(): Container {
  const container = new Container();

  // Load configuration
  const config = loadConfig();

  // Bind configuration
  container.bind<Config>(TYPES.Config).toConstantValue(config);
  container.bind(TYPES.FeatureFlags).toConstantValue(config.featureFlags);

  // Configure services based on feature flags
  configureValidationServices(container, config);
  configureExternalServices(container, config);

  return container;
}

/**
 * Configure validation services
 */
function configureValidationServices(container: Container, config: Config): void {
  // For now, always use mocks (real implementations will be added later)
  container.bind<IValidationService>(TYPES.ValidationService).to(MockValidationService);
  container.bind<IKPDValidatorService>(TYPES.KPDValidatorService).to(MockKPDValidatorService);
  container.bind<IOIBValidatorService>(TYPES.OIBValidatorService).to(MockOIBValidatorService);
}

/**
 * Configure external services
 */
function configureExternalServices(container: Container, config: Config): void {
  // FINA Service
  if (config.featureFlags.useMockFINA) {
    container.bind<IFINAService>(TYPES.FINAService).to(MockFINAService);
  } else {
    // Real implementation will be added by Team 3
    // container.bind<IFINAService>(TYPES.FINAService).to(RealFINAService);
    console.warn('Real FINA service not implemented yet, using mock');
    container.bind<IFINAService>(TYPES.FINAService).to(MockFINAService);
  }

  // Porezna Service
  if (config.featureFlags.useMockPorezna) {
    container.bind<IPoreznaService>(TYPES.PoreznaService).to(MockPoreznaService);
  } else {
    // Real implementation will be added by Team 3
    console.warn('Real Porezna service not implemented yet, using mock');
    container.bind<IPoreznaService>(TYPES.PoreznaService).to(MockPoreznaService);
  }

  // OCR Service
  if (config.featureFlags.useMockOCR) {
    container.bind<IOCRService>(TYPES.OCRService).to(MockOCRService);
  } else {
    // Real implementation will be added by Team 2
    console.warn('Real OCR service not implemented yet, using mock');
    container.bind<IOCRService>(TYPES.OCRService).to(MockOCRService);
  }

  // AI Validation Service
  if (config.featureFlags.useMockAI) {
    container.bind<IAIValidationService>(TYPES.AIValidationService).to(MockAIValidationService);
  } else {
    // Real implementation will be added by Team 2
    console.warn('Real AI validation service not implemented yet, using mock');
    container.bind<IAIValidationService>(TYPES.AIValidationService).to(MockAIValidationService);
  }
}

/**
 * Get service from container (helper function)
 */
export function getService<T>(container: Container, serviceIdentifier: symbol): T {
  return container.get<T>(serviceIdentifier);
}

/**
 * Check if service is bound
 */
export function hasService(container: Container, serviceIdentifier: symbol): boolean {
  return container.isBound(serviceIdentifier);
}
