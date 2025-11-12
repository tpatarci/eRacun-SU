/**
 * XML Parser and Validator
 *
 * Secure XML parsing for Croatian e-invoices (UBL 2.1, EN 16931).
 *
 * Security Features:
 * - XXE (XML External Entity) attack prevention
 * - Billion laughs attack prevention
 * - Size limit enforcement
 * - Depth limit enforcement
 * - Entity expansion limit
 */

import { XMLParser, XMLBuilder, XMLValidator } from 'fast-xml-parser';

/**
 * XML parsing configuration
 */
export interface XMLParserConfig {
  /** Maximum XML document size in bytes (default: 10MB) */
  maxSize?: number;
  /** Maximum nesting depth (default: 20) */
  maxDepth?: number;
  /** Allow attributes (default: true) */
  allowAttributes?: boolean;
  /** Ignore XML declaration (default: false) */
  ignoreDeclaration?: boolean;
  /** Parse attribute values (default: true) */
  parseAttributeValue?: boolean;
  /** Trim text values (default: true) */
  trimValues?: boolean;
}

/**
 * XML parsing result
 */
export interface XMLParseResult {
  /** Whether parsing was successful */
  success: boolean;
  /** Parsed data (if successful) */
  data?: any;
  /** Array of errors (if failed) */
  errors: string[];
  /** Metadata about the XML document */
  metadata: {
    /** Original size in bytes */
    sizeBytes: number;
    /** Estimated depth */
    depth: number;
    /** Whether document has XML declaration */
    hasDeclaration: boolean;
    /** Root element name */
    rootElement?: string;
  };
}

/**
 * XML validation result
 */
export interface XMLValidationResult {
  /** Whether validation passed */
  valid: boolean;
  /** Array of validation errors */
  errors: string[];
}

/**
 * Default parser configuration
 */
const DEFAULT_CONFIG: Required<XMLParserConfig> = {
  maxSize: 10 * 1024 * 1024, // 10MB
  maxDepth: 20,
  allowAttributes: true,
  ignoreDeclaration: false,
  parseAttributeValue: true,
  trimValues: true,
};

/**
 * Validate XML string for security vulnerabilities
 *
 * @param xml - XML string to validate
 * @param config - Parser configuration
 * @returns Validation result
 */
export function validateXMLSecurity(
  xml: string,
  config: XMLParserConfig = {}
): XMLValidationResult {
  const errors: string[] = [];
  const cfg = { ...DEFAULT_CONFIG, ...config };

  // Check if XML is provided
  if (!xml || typeof xml !== 'string') {
    errors.push('XML content is required');
    return { valid: false, errors };
  }

  const trimmed = xml.trim();

  if (trimmed === '') {
    errors.push('XML content is required');
    return { valid: false, errors };
  }

  // Check size limit
  const sizeBytes = Buffer.byteLength(trimmed, 'utf8');
  if (sizeBytes > cfg.maxSize) {
    errors.push(
      `XML document exceeds maximum size of ${cfg.maxSize} bytes (got ${sizeBytes} bytes)`
    );
  }

  // Check for XXE attack patterns
  if (trimmed.includes('<!ENTITY') || trimmed.includes('<!DOCTYPE')) {
    errors.push('XML document contains potentially dangerous entities (XXE attack prevention)');
  }

  // Check for excessive entity expansion (billion laughs pattern)
  const entityCount = (trimmed.match(/&[a-zA-Z0-9]+;/g) || []).length;
  if (entityCount > 100) {
    errors.push(
      `XML document contains excessive entity references (${entityCount} > 100, billion laughs prevention)`
    );
  }

  // Estimate depth (approximate check)
  const depthEstimate = estimateXMLDepth(trimmed);
  if (depthEstimate > cfg.maxDepth) {
    errors.push(
      `XML document exceeds maximum nesting depth of ${cfg.maxDepth} (estimated ${depthEstimate})`
    );
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Estimate XML nesting depth (approximation)
 *
 * @param xml - XML string
 * @returns Estimated depth
 */
function estimateXMLDepth(xml: string): number {
  // Track depth by counting opening/closing tags
  let depth = 0;
  let maxDepth = 0;

  // Simple state machine to track depth
  for (let i = 0; i < xml.length; i++) {
    if (xml[i] === '<') {
      // Check if it's a closing tag
      if (xml[i + 1] === '/') {
        depth--;
      }
      // Check if it's not a self-closing or special tag
      else if (xml[i + 1] !== '!' && xml[i + 1] !== '?') {
        depth++;
        maxDepth = Math.max(maxDepth, depth);
      }
    }
    // Check for self-closing tags
    else if (xml[i] === '/' && xml[i + 1] === '>') {
      depth--;
    }
  }

  return maxDepth;
}

/**
 * Parse XML string to JavaScript object
 *
 * @param xml - XML string to parse
 * @param config - Parser configuration
 * @returns Parse result
 */
export function parseXML(xml: string, config: XMLParserConfig = {}): XMLParseResult {
  const cfg = { ...DEFAULT_CONFIG, ...config };

  // Validate security first
  const securityCheck = validateXMLSecurity(xml, cfg);
  if (!securityCheck.valid) {
    return {
      success: false,
      errors: securityCheck.errors,
      metadata: {
        sizeBytes: Buffer.byteLength(xml, 'utf8'),
        depth: 0,
        hasDeclaration: xml.trim().startsWith('<?xml'),
      },
    };
  }

  // Validate XML syntax
  const validationResult = XMLValidator.validate(xml, {
    allowBooleanAttributes: true,
  });

  if (validationResult !== true) {
    return {
      success: false,
      errors: [
        `Invalid XML syntax: ${validationResult.err?.msg || 'Unknown error'} at line ${validationResult.err?.line}`,
      ],
      metadata: {
        sizeBytes: Buffer.byteLength(xml, 'utf8'),
        depth: 0,
        hasDeclaration: xml.trim().startsWith('<?xml'),
      },
    };
  }

  // Parse XML
  try {
    const parser = new XMLParser({
      ignoreAttributes: !cfg.allowAttributes,
      ignoreDeclaration: cfg.ignoreDeclaration,
      parseAttributeValue: cfg.parseAttributeValue,
      trimValues: cfg.trimValues,
      attributeNamePrefix: '@_',
      textNodeName: '#text',
      cdataPropName: '__cdata',
    });

    const data = parser.parse(xml);

    // Extract root element (skip ?xml declaration if present)
    const keys = Object.keys(data).filter((key) => key !== '?xml');
    const rootElement = keys.length > 0 ? keys[0] : undefined;

    return {
      success: true,
      data,
      errors: [],
      metadata: {
        sizeBytes: Buffer.byteLength(xml, 'utf8'),
        depth: estimateXMLDepth(xml),
        hasDeclaration: xml.trim().startsWith('<?xml'),
        rootElement,
      },
    };
  } catch (error) {
    return {
      success: false,
      errors: [
        `XML parsing error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      ],
      metadata: {
        sizeBytes: Buffer.byteLength(xml, 'utf8'),
        depth: 0,
        hasDeclaration: xml.trim().startsWith('<?xml'),
      },
    };
  }
}

/**
 * Convert JavaScript object to XML string
 *
 * @param obj - JavaScript object to convert
 * @param config - Parser configuration
 * @returns XML string
 */
export function toXML(obj: any, config: XMLParserConfig = {}): string {
  const cfg = { ...DEFAULT_CONFIG, ...config };

  const builder = new XMLBuilder({
    ignoreAttributes: !cfg.allowAttributes,
    attributeNamePrefix: '@_',
    textNodeName: '#text',
    cdataPropName: '__cdata',
    format: true,
    indentBy: '  ',
    suppressBooleanAttributes: false,
  });

  return builder.build(obj);
}

/**
 * Extract specific element from parsed XML
 *
 * @param data - Parsed XML data
 * @param path - Dot-notation path (e.g., "Invoice.InvoiceLine.0.Item")
 * @returns Value at path or undefined
 */
export function extractElement(data: any, path: string): any {
  if (!data || !path) return undefined;

  const parts = path.split('.');
  let current = data;

  for (const part of parts) {
    if (current === undefined || current === null) {
      return undefined;
    }

    // Handle array indices
    if (/^\d+$/.test(part)) {
      const index = parseInt(part, 10);
      if (Array.isArray(current)) {
        current = current[index];
      } else {
        return undefined;
      }
    } else {
      current = current[part];
    }
  }

  return current;
}

/**
 * Validate XML against expected structure
 *
 * @param data - Parsed XML data
 * @param requiredFields - Array of required field paths
 * @returns Validation result
 */
export function validateXMLStructure(
  data: any,
  requiredFields: string[]
): XMLValidationResult {
  const errors: string[] = [];

  if (!data || typeof data !== 'object') {
    errors.push('Invalid XML data structure');
    return { valid: false, errors };
  }

  for (const field of requiredFields) {
    const value = extractElement(data, field);
    if (value === undefined || value === null || value === '') {
      errors.push(`Required field missing or empty: ${field}`);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Batch parse multiple XML documents
 *
 * @param xmlDocuments - Array of XML strings
 * @param config - Parser configuration
 * @returns Array of parse results
 */
export function parseXMLBatch(
  xmlDocuments: string[],
  config: XMLParserConfig = {}
): XMLParseResult[] {
  return xmlDocuments.map((xml) => parseXML(xml, config));
}
