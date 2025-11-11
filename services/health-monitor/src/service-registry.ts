/**
 * Service Registry Module
 *
 * Loads and manages the list of all services to monitor.
 * Service definitions come from config/services.json (static config)
 * or Consul (dynamic service discovery) if available.
 */

import fs from 'fs';
import path from 'path';
import { logger } from './observability';

// =============================================
// Types
// =============================================

export interface Service {
  name: string;
  health_url: string;      // e.g., "http://xsd-validator:8088/health"
  ready_url: string;       // e.g., "http://xsd-validator:8088/ready"
  critical: boolean;       // If true, P0 alert on failure
  poll_interval_ms: number; // 15000 (critical), 30000 (standard), 60000 (external)
  layer?: number;          // Optional: 1-9 (ingestion to infrastructure)
  description?: string;    // Optional: Service description
}

export interface ServiceRegistry {
  services: Service[];
  external_dependencies: Service[];
}

// =============================================
// Service Registry
// =============================================

let serviceRegistry: ServiceRegistry | null = null;

/**
 * Load service registry from config file
 * @param configPath - Path to services.json config file
 * @returns ServiceRegistry
 */
export function loadServiceRegistry(configPath?: string): ServiceRegistry {
  const resolvedPath = configPath || path.join(__dirname, '../config/services.json');

  try {
    const fileContent = fs.readFileSync(resolvedPath, 'utf-8');
    serviceRegistry = JSON.parse(fileContent) as ServiceRegistry;

    logger.info(
      {
        services_count: serviceRegistry.services.length,
        external_deps_count: serviceRegistry.external_dependencies.length,
        config_path: resolvedPath,
      },
      'Service registry loaded successfully'
    );

    return serviceRegistry;
  } catch (error) {
    logger.error(
      {
        err: error,
        config_path: resolvedPath,
      },
      'Failed to load service registry'
    );
    throw new Error(`Failed to load service registry from ${resolvedPath}: ${(error as Error).message}`);
  }
}

/**
 * Get all registered services
 * @returns Array of all services
 */
export function getAllServices(): Service[] {
  if (!serviceRegistry) {
    throw new Error('Service registry not loaded. Call loadServiceRegistry() first.');
  }

  return serviceRegistry.services;
}

/**
 * Get critical services only
 * Critical services trigger P0 alerts on failure
 * @returns Array of critical services
 */
export function getCriticalServices(): Service[] {
  if (!serviceRegistry) {
    throw new Error('Service registry not loaded. Call loadServiceRegistry() first.');
  }

  return serviceRegistry.services.filter((service) => service.critical);
}

/**
 * Get external dependencies
 * @returns Array of external dependencies (RabbitMQ, PostgreSQL, Kafka, FINA)
 */
export function getExternalDependencies(): Service[] {
  if (!serviceRegistry) {
    throw new Error('Service registry not loaded. Call loadServiceRegistry() first.');
  }

  return serviceRegistry.external_dependencies;
}

/**
 * Get service by name
 * @param name - Service name
 * @returns Service or undefined if not found
 */
export function getServiceByName(name: string): Service | undefined {
  if (!serviceRegistry) {
    throw new Error('Service registry not loaded. Call loadServiceRegistry() first.');
  }

  return serviceRegistry.services.find((service) => service.name === name);
}

/**
 * Get services by layer
 * @param layer - Layer number (1-9)
 * @returns Array of services in the specified layer
 */
export function getServicesByLayer(layer: number): Service[] {
  if (!serviceRegistry) {
    throw new Error('Service registry not loaded. Call loadServiceRegistry() first.');
  }

  return serviceRegistry.services.filter((service) => service.layer === layer);
}

/**
 * Validate service registry configuration
 * @param registry - Service registry to validate
 * @returns Array of validation errors (empty if valid)
 */
export function validateServiceRegistry(registry: ServiceRegistry): string[] {
  const errors: string[] = [];

  // Check services array exists
  if (!Array.isArray(registry.services)) {
    errors.push('services must be an array');
    return errors;
  }

  // Check external_dependencies array exists
  if (!Array.isArray(registry.external_dependencies)) {
    errors.push('external_dependencies must be an array');
    return errors;
  }

  // Validate each service
  registry.services.forEach((service, index) => {
    if (!service.name) {
      errors.push(`Service at index ${index} is missing 'name'`);
    }
    if (!service.health_url) {
      errors.push(`Service '${service.name || index}' is missing 'health_url'`);
    }
    if (!service.ready_url) {
      errors.push(`Service '${service.name || index}' is missing 'ready_url'`);
    }
    if (typeof service.critical !== 'boolean') {
      errors.push(`Service '${service.name || index}' 'critical' must be a boolean`);
    }
    if (typeof service.poll_interval_ms !== 'number' || service.poll_interval_ms < 1000) {
      errors.push(`Service '${service.name || index}' 'poll_interval_ms' must be a number >= 1000`);
    }
  });

  // Validate external dependencies
  registry.external_dependencies.forEach((dep, index) => {
    if (!dep.name) {
      errors.push(`External dependency at index ${index} is missing 'name'`);
    }
    if (!dep.health_url) {
      errors.push(`External dependency '${dep.name || index}' is missing 'health_url'`);
    }
  });

  return errors;
}

/**
 * Reload service registry (for dynamic updates)
 * @param configPath - Path to services.json config file
 */
export function reloadServiceRegistry(configPath?: string): void {
  logger.info('Reloading service registry...');
  loadServiceRegistry(configPath);
}

// =============================================
// Export for Testing
// =============================================

export function resetServiceRegistry(): void {
  serviceRegistry = null;
}
