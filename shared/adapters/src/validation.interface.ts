/**
 * Validation Service Adapter Interface
 * Abstracts XSD, Schematron, KPD, and semantic validation
 */

import { ValidationResult, LayerResult } from '@eracun/contracts';

export interface IValidationService {
  /**
   * Validate XML against XSD schema
   */
  validateXSD(xml: string): Promise<LayerResult>;

  /**
   * Validate XML against Schematron rules (Croatian CIUS)
   */
  validateSchematron(xml: string): Promise<LayerResult>;

  /**
   * Validate KPD codes against KLASUS registry
   */
  validateKPD(kpdCodes: string[]): Promise<LayerResult>;

  /**
   * Validate business rules (VAT calculations, OIB format, etc.)
   */
  validateSemantic(xml: string): Promise<LayerResult>;

  /**
   * Full validation pipeline (all layers)
   */
  validateFull(xml: string): Promise<ValidationResult>;
}

export interface IXSDValidatorService {
  /**
   * Validate XML against UBL 2.1 XSD schema
   */
  validate(xml: string): Promise<LayerResult>;
}

export interface ISchematronValidatorService {
  /**
   * Validate XML against Croatian CIUS Schematron rules
   */
  validate(xml: string): Promise<LayerResult>;
}

export interface IKPDValidatorService {
  /**
   * Validate KPD code against KLASUS 2025 registry
   */
  validateCode(kpdCode: string): Promise<boolean>;

  /**
   * Validate multiple KPD codes
   */
  validateCodes(kpdCodes: string[]): Promise<LayerResult>;

  /**
   * Get KPD code details
   */
  getCodeDetails(kpdCode: string): Promise<KPDCodeDetails | null>;
}

export interface KPDCodeDetails {
  code: string;
  description: string;
  valid: boolean;
  category: string;
}

export interface IOIBValidatorService {
  /**
   * Validate OIB format and check digit
   */
  validate(oib: string): Promise<boolean>;

  /**
   * Calculate OIB check digit
   */
  calculateCheckDigit(digits: string): string;
}
