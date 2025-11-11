/**
 * Template Engine
 *
 * Handles Handlebars template rendering for email and SMS notifications.
 * Features:
 * - Template caching for performance
 * - Support for both HTML (email) and plain text (SMS)
 * - Safe template loading from filesystem
 * - Variable substitution with error handling
 */

import * as fs from 'fs';
import * as path from 'path';
import Handlebars from 'handlebars';
import { logger } from './observability';

// =============================================================================
// TYPES
// =============================================================================

export interface TemplateVariables {
  [key: string]: string | number | boolean | Date | null | undefined;
}

export enum TemplateType {
  EMAIL = 'email',
  SMS = 'sms',
}

// =============================================================================
// CONFIGURATION
// =============================================================================

const TEMPLATES_DIR = path.join(__dirname, '../templates');

// Template cache: Map<templateName, compiledTemplate>
const templateCache = new Map<string, HandlebarsTemplateDelegate>();

// =============================================================================
// TEMPLATE LOADING
// =============================================================================

/**
 * Load template from filesystem
 *
 * @param templateName - Template filename without extension (e.g., 'invoice_submitted')
 * @param templateType - 'email' or 'sms'
 * @returns Template source string
 */
function loadTemplateSource(templateName: string, templateType: TemplateType): string {
  const extension = templateType === TemplateType.EMAIL ? 'html' : 'txt';
  const templatePath = path.join(TEMPLATES_DIR, templateType, `${templateName}.${extension}`);

  try {
    const source = fs.readFileSync(templatePath, 'utf-8');
    logger.debug({ template_name: templateName, template_type: templateType }, 'Template loaded from filesystem');
    return source;
  } catch (error) {
    logger.error(
      { error, template_name: templateName, template_type: templateType, template_path: templatePath },
      'Failed to load template'
    );
    throw new Error(`Template not found: ${templateName} (${templateType})`);
  }
}

/**
 * Get compiled template from cache or load and compile
 *
 * @param templateName - Template filename without extension
 * @param templateType - 'email' or 'sms'
 * @returns Compiled Handlebars template
 */
function getCompiledTemplate(templateName: string, templateType: TemplateType): HandlebarsTemplateDelegate {
  const cacheKey = `${templateType}:${templateName}`;

  // Check cache first
  if (templateCache.has(cacheKey)) {
    logger.debug({ template_name: templateName, cache_hit: true }, 'Template cache hit');
    return templateCache.get(cacheKey)!;
  }

  // Load and compile template
  const source = loadTemplateSource(templateName, templateType);
  const compiled = Handlebars.compile(source);

  // Store in cache
  templateCache.set(cacheKey, compiled);
  logger.info({ template_name: templateName, template_type: templateType }, 'Template compiled and cached');

  return compiled;
}

// =============================================================================
// TEMPLATE RENDERING
// =============================================================================

/**
 * Render email template with variables
 *
 * @param templateName - Template filename without extension (e.g., 'invoice_submitted')
 * @param variables - Template variables for substitution
 * @returns Rendered HTML string
 *
 * @example
 * const html = renderEmailTemplate('invoice_submitted', {
 *   user_name: 'John Doe',
 *   invoice_number: 'INV-2025-001',
 *   submission_date: new Date(),
 * });
 */
export function renderEmailTemplate(templateName: string, variables: TemplateVariables): string {
  try {
    const template = getCompiledTemplate(templateName, TemplateType.EMAIL);
    const rendered = template(variables);

    logger.debug(
      { template_name: templateName, variable_count: Object.keys(variables).length },
      'Email template rendered successfully'
    );

    return rendered;
  } catch (error) {
    logger.error(
      { error, template_name: templateName, variables },
      'Failed to render email template'
    );
    throw new Error(`Failed to render email template: ${templateName}`);
  }
}

/**
 * Render SMS template with variables
 *
 * @param templateName - Template filename without extension (e.g., 'critical_error')
 * @param variables - Template variables for substitution
 * @returns Rendered plain text string
 *
 * @example
 * const message = renderSMSTemplate('critical_error', {
 *   service_name: 'email-ingestion-worker',
 *   error_message: 'Connection timeout',
 * });
 */
export function renderSMSTemplate(templateName: string, variables: TemplateVariables): string {
  try {
    const template = getCompiledTemplate(templateName, TemplateType.SMS);
    const rendered = template(variables);

    logger.debug(
      { template_name: templateName, variable_count: Object.keys(variables).length },
      'SMS template rendered successfully'
    );

    return rendered;
  } catch (error) {
    logger.error(
      { error, template_name: templateName, variables },
      'Failed to render SMS template'
    );
    throw new Error(`Failed to render SMS template: ${templateName}`);
  }
}

/**
 * Render template (auto-detect type based on template name)
 *
 * @param templateName - Template filename without extension
 * @param templateType - 'email' or 'sms'
 * @param variables - Template variables for substitution
 * @returns Rendered template string
 */
export function renderTemplate(
  templateName: string,
  templateType: TemplateType,
  variables: TemplateVariables
): string {
  if (templateType === TemplateType.EMAIL) {
    return renderEmailTemplate(templateName, variables);
  } else {
    return renderSMSTemplate(templateName, variables);
  }
}

// =============================================================================
// TEMPLATE CACHE MANAGEMENT
// =============================================================================

/**
 * Clear template cache (for hot-reloading in development)
 */
export function clearTemplateCache(): void {
  const cacheSize = templateCache.size;
  templateCache.clear();
  logger.info({ cleared_templates: cacheSize }, 'Template cache cleared');
}

/**
 * Get cache statistics
 */
export function getTemplateCacheStats(): { size: number; keys: string[] } {
  return {
    size: templateCache.size,
    keys: Array.from(templateCache.keys()),
  };
}

// =============================================================================
// HANDLEBARS HELPERS (Custom template helpers)
// =============================================================================

/**
 * Register custom Handlebars helpers
 */
function registerHelpers(): void {
  // Date formatting helper
  Handlebars.registerHelper('formatDate', (date: Date | string) => {
    if (!date) return '';
    const d = typeof date === 'string' ? new Date(date) : date;
    return d.toLocaleDateString('hr-HR', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  });

  // Currency formatting helper (Croatian Kuna / Euro)
  Handlebars.registerHelper('formatCurrency', (amount: number, currency = 'EUR') => {
    if (amount === null || amount === undefined) return '';
    return new Intl.NumberFormat('hr-HR', {
      style: 'currency',
      currency: currency,
    }).format(amount);
  });

  // Uppercase helper
  Handlebars.registerHelper('uppercase', (text: string) => {
    return text ? text.toUpperCase() : '';
  });

  // Truncate helper
  Handlebars.registerHelper('truncate', (text: string, maxLength: number) => {
    if (!text) return '';
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
  });

  logger.info('Handlebars custom helpers registered');
}

// Initialize helpers on module load
registerHelpers();

// =============================================================================
// EXPORTS
// =============================================================================

export default {
  renderEmailTemplate,
  renderSMSTemplate,
  renderTemplate,
  clearTemplateCache,
  getTemplateCacheStats,
};
