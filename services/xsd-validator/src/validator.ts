import { parseXml } from 'libxmljs2';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export enum SchemaType {
  UBL_INVOICE_2_1 = 'UBL-Invoice-2.1',
  UBL_CREDIT_NOTE_2_1 = 'UBL-CreditNote-2.1',
}

export enum ValidationStatus {
  VALID = 'VALID',
  INVALID = 'INVALID',
  ERROR = 'ERROR',
}

export interface ValidationError {
  code: string;
  message: string;
  line?: number;
  column?: number;
  field?: string;
}

export interface ValidationResult {
  status: ValidationStatus;
  errors: ValidationError[];
  validationTimeMs: number;
}

/**
 * XSD Validator for UBL 2.1 documents
 *
 * Validates XML documents against official UBL 2.1 XSD schemas.
 *
 * Security:
 * - XXE protection: External entity resolution disabled
 * - Billion laughs protection: Entity expansion limited
 * - Size limits: Enforced by caller (max 10MB)
 */
export class XSDValidator {
  private schemaCache: Map<SchemaType, any> = new Map();
  private schemaPath: string;

  constructor(schemaPath?: string) {
    this.schemaPath = schemaPath || path.join(__dirname, '../schemas/ubl-2.1');
  }

  /**
   * Load UBL 2.1 schemas into memory at startup
   * Schemas are cached for the lifetime of the service
   */
  async loadSchemas(): Promise<void> {
    const schemaFiles: Record<SchemaType, string> = {
      [SchemaType.UBL_INVOICE_2_1]: 'maindoc/UBL-Invoice-2.1.xsd',
      [SchemaType.UBL_CREDIT_NOTE_2_1]: 'maindoc/UBL-CreditNote-2.1.xsd',
    };

    for (const [schemaType, schemaFile] of Object.entries(schemaFiles)) {
      const schemaFullPath = path.join(this.schemaPath, schemaFile);

      try {
        const schemaContent = await fs.readFile(schemaFullPath, 'utf-8');
        const schemaDoc = parseXml(schemaContent, {
          nonet: true, // Disable network access (XXE protection)
          noent: false, // Disable entity substitution (billion laughs protection)
        });

        this.schemaCache.set(schemaType as SchemaType, schemaDoc);
      } catch (error) {
        throw new Error(
          `Failed to load schema ${schemaType}: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
      }
    }
  }

  /**
   * Validate XML document against UBL 2.1 XSD schema
   *
   * @param xmlContent - XML document as bytes/string
   * @param schemaType - UBL document type (Invoice, CreditNote, etc.)
   * @returns ValidationResult with status and errors
   */
  async validate(
    xmlContent: Buffer | string,
    schemaType: SchemaType
  ): Promise<ValidationResult> {
    const startTime = Date.now();
    const errors: ValidationError[] = [];

    try {
      // Parse XML with security protections
      const xmlDoc = parseXml(xmlContent.toString('utf-8'), {
        nonet: true, // Disable network access (XXE protection)
        noent: false, // Disable entity substitution (billion laughs protection)
        nocdata: false, // Allow CDATA sections
        recover: false, // Strict parsing (don't try to recover from errors)
      });

      // Get cached schema
      const schema = this.schemaCache.get(schemaType);
      if (!schema) {
        return {
          status: ValidationStatus.ERROR,
          errors: [
            {
              code: 'SCHEMA_NOT_LOADED',
              message: `Schema ${schemaType} not loaded. Call loadSchemas() first.`,
            },
          ],
          validationTimeMs: Date.now() - startTime,
        };
      }

      // Validate against XSD schema
      const isValid = xmlDoc.validate(schema);

      if (!isValid) {
        // Extract validation errors from libxmljs2
        const validationErrors = xmlDoc.validationErrors || [];

        for (const error of validationErrors) {
          errors.push({
            code: 'XSD_VALIDATION_ERROR',
            message: error.message || 'Validation error',
            line: error.line,
            column: error.column,
          });
        }
      }

      return {
        status: errors.length > 0 ? ValidationStatus.INVALID : ValidationStatus.VALID,
        errors,
        validationTimeMs: Date.now() - startTime,
      };
    } catch (error) {
      // Parse errors or other exceptions
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      // Try to extract line/column from libxml2 error message
      const lineMatch = errorMessage.match(/line (\d+)/i);
      const columnMatch = errorMessage.match(/column (\d+)/i);

      return {
        status: ValidationStatus.ERROR,
        errors: [
          {
            code: 'XML_PARSE_ERROR',
            message: errorMessage,
            line: lineMatch ? parseInt(lineMatch[1], 10) : undefined,
            column: columnMatch ? parseInt(columnMatch[1], 10) : undefined,
          },
        ],
        validationTimeMs: Date.now() - startTime,
      };
    }
  }

  /**
   * Check if schemas are loaded and ready
   */
  isReady(): boolean {
    return this.schemaCache.size > 0;
  }

  /**
   * Get loaded schema types (for diagnostics)
   */
  getLoadedSchemas(): SchemaType[] {
    return Array.from(this.schemaCache.keys());
  }
}
