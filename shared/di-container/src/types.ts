/**
 * Dependency Injection Types
 * Symbols for dependency resolution
 */

export const TYPES = {
  // Validation services
  ValidationService: Symbol.for('IValidationService'),
  XSDValidatorService: Symbol.for('IXSDValidatorService'),
  SchematronValidatorService: Symbol.for('ISchematronValidatorService'),
  KPDValidatorService: Symbol.for('IKPDValidatorService'),
  OIBValidatorService: Symbol.for('IOIBValidatorService'),

  // External services
  FINAService: Symbol.for('IFINAService'),
  PoreznaService: Symbol.for('IPoreznaService'),
  OCRService: Symbol.for('IOCRService'),
  AIValidationService: Symbol.for('IAIValidationService'),
  DigitalSignatureService: Symbol.for('IDigitalSignatureService'),
  CertificateService: Symbol.for('ICertificateService'),
  StorageService: Symbol.for('IStorageService'),
  ArchiveService: Symbol.for('IArchiveService'),

  // Configuration
  Config: Symbol.for('Config'),
  FeatureFlags: Symbol.for('FeatureFlags'),
};
