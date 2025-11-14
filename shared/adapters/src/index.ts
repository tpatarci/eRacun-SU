/**
 * @eracun/adapters - Service Adapter Interfaces
 *
 * This module contains all adapter interfaces for external services,
 * enabling dependency injection and mock implementations.
 *
 * @version 1.0.0
 */

// Validation adapters
export * from './validation.interface';

// External service adapters
export * from './fina.interface';
export * from './ocr.interface';
export * from './ai-validation.interface';
export * from './signature.interface';
export * from './storage.interface';
