/**
 * Jest Test Setup
 *
 * Global setup and teardown for all tests
 */

import { resetMetrics } from '../src/observability.js';

// Global setup before all tests
beforeAll(() => {
  // Set test environment
  process.env.NODE_ENV = 'test';
  process.env.LOG_LEVEL = 'silent';
});

// Setup before each test
beforeEach(() => {
  // Reset Prometheus metrics before each test
  resetMetrics();
});

// Teardown after each test
afterEach(() => {
  // Clean up any test artifacts
});

// Global teardown after all tests
afterAll(() => {
  // Clean up
});
