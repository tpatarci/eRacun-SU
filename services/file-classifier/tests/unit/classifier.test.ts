/**
 * Classifier Module Tests
 */

import { Classifier } from '../../src/classifier';
import { DetectedFile } from '../../src/file-detector';

describe('Classifier', () => {
  let classifier: Classifier;

  beforeEach(() => {
    classifier = new Classifier({
      pdfTypes: ['application/pdf'],
      xmlTypes: ['application/xml', 'text/xml'],
      imageTypes: ['image/jpeg', 'image/png', 'image/tiff'],
    });
  });

  describe('classify', () => {
    it('should use default rules when constructed without arguments', () => {
      const defaultClassifier = new Classifier();
      const rules = defaultClassifier.getRules();

      expect(rules.pdfTypes).toContain('application/pdf');
      expect(rules.xmlTypes).toContain('application/xml');
      expect(rules.imageTypes).toContain('image/jpeg');
    });

    it('should classify PDF documents', () => {
      const detectedFile: DetectedFile = {
        mimeType: 'application/pdf',
        extension: 'pdf',
        detectionMethod: 'magic-number',
        isSupported: true,
        size: 102400,
      };

      const result = classifier.classify(detectedFile);

      expect(result.processor).toBe('pdf-parser');
      expect(result.priority).toBe('high');
      expect(result.category).toBe('pdf-document');
      expect(result.confidence).toBe('high');
      expect(result.mimeType).toBe('application/pdf');
      expect(result.extension).toBe('pdf');
      expect(result.size).toBe(102400);
    });

    it('should classify XML documents', () => {
      const detectedFile: DetectedFile = {
        mimeType: 'application/xml',
        extension: 'xml',
        detectionMethod: 'magic-number',
        isSupported: true,
        size: 50000,
      };

      const result = classifier.classify(detectedFile);

      expect(result.processor).toBe('xml-parser');
      expect(result.priority).toBe('high');
      expect(result.category).toBe('xml-document');
      expect(result.confidence).toBe('high');
    });

    it('should classify text/xml documents', () => {
      const detectedFile: DetectedFile = {
        mimeType: 'text/xml',
        extension: 'xml',
        detectionMethod: 'extension',
        isSupported: true,
        size: 30000,
      };

      const result = classifier.classify(detectedFile);

      expect(result.processor).toBe('xml-parser');
      expect(result.priority).toBe('high');
      expect(result.category).toBe('xml-document');
    });

    it('should classify JPEG images', () => {
      const detectedFile: DetectedFile = {
        mimeType: 'image/jpeg',
        extension: 'jpg',
        detectionMethod: 'magic-number',
        isSupported: true,
        size: 204800,
      };

      const result = classifier.classify(detectedFile);

      expect(result.processor).toBe('ocr-processing-service');
      expect(result.priority).toBe('medium');
      expect(result.category).toBe('image');
      expect(result.confidence).toBe('high');
    });

    it('should classify PNG images', () => {
      const detectedFile: DetectedFile = {
        mimeType: 'image/png',
        extension: 'png',
        detectionMethod: 'magic-number',
        isSupported: true,
        size: 150000,
      };

      const result = classifier.classify(detectedFile);

      expect(result.processor).toBe('ocr-processing-service');
      expect(result.priority).toBe('medium');
      expect(result.category).toBe('image');
    });

    it('should classify TIFF images', () => {
      const detectedFile: DetectedFile = {
        mimeType: 'image/tiff',
        extension: 'tiff',
        detectionMethod: 'magic-number',
        isSupported: true,
        size: 500000,
      };

      const result = classifier.classify(detectedFile);

      expect(result.processor).toBe('ocr-processing-service');
      expect(result.category).toBe('image');
    });

    it('should route unknown file types to manual review', () => {
      const detectedFile: DetectedFile = {
        mimeType: 'application/zip',
        extension: 'zip',
        detectionMethod: 'magic-number',
        isSupported: false,
        size: 1024000,
      };

      const result = classifier.classify(detectedFile);

      expect(result.processor).toBe('manual-review-queue');
      expect(result.priority).toBe('low');
      expect(result.category).toBe('unknown');
      expect(result.confidence).toBe('low');
    });

    it('should route unsupported types to manual review', () => {
      const detectedFile: DetectedFile = {
        mimeType: 'application/octet-stream',
        extension: 'bin',
        detectionMethod: 'unknown',
        isSupported: false,
        size: 5000,
      };

      const result = classifier.classify(detectedFile);

      expect(result.processor).toBe('manual-review-queue');
      expect(result.category).toBe('unknown');
      expect(result.confidence).toBe('low');
    });

    it('should handle edge case file types', () => {
      const detectedFile: DetectedFile = {
        mimeType: 'text/plain',
        extension: 'txt',
        detectionMethod: 'extension',
        isSupported: false,
        size: 1024,
      };

      const result = classifier.classify(detectedFile);

      expect(result.processor).toBe('manual-review-queue');
      expect(result.category).toBe('unknown');
    });
  });

  describe('getRules', () => {
    it('should return classification rules', () => {
      const rules = classifier.getRules();

      expect(rules.pdfTypes).toContain('application/pdf');
      expect(rules.xmlTypes).toContain('application/xml');
      expect(rules.imageTypes).toContain('image/jpeg');
    });

    it('should return a copy of rules', () => {
      const rules = classifier.getRules();
      rules.pdfTypes.push('test');

      const rulesAgain = classifier.getRules();
      expect(rulesAgain.pdfTypes).not.toContain('test');
    });
  });

  describe('setRules', () => {
    it('should update PDF types', () => {
      classifier.setRules({
        pdfTypes: ['application/pdf', 'application/x-pdf'],
      });

      const rules = classifier.getRules();
      expect(rules.pdfTypes).toHaveLength(2);
      expect(rules.pdfTypes).toContain('application/x-pdf');
    });

    it('should update XML types', () => {
      classifier.setRules({
        xmlTypes: ['application/xml'],
      });

      const rules = classifier.getRules();
      expect(rules.xmlTypes).toHaveLength(1);
    });

    it('should update image types', () => {
      classifier.setRules({
        imageTypes: ['image/jpeg'],
      });

      const rules = classifier.getRules();
      expect(rules.imageTypes).toHaveLength(1);
    });

    it('should merge with existing rules', () => {
      const originalRules = classifier.getRules();

      classifier.setRules({
        pdfTypes: ['application/x-pdf'],
      });

      const updatedRules = classifier.getRules();
      expect(updatedRules.pdfTypes).toEqual(['application/x-pdf']);
      expect(updatedRules.xmlTypes).toEqual(originalRules.xmlTypes);
      expect(updatedRules.imageTypes).toEqual(originalRules.imageTypes);
    });
  });

  describe('Custom Rules', () => {
    it('should use custom classification rules', () => {
      const customClassifier = new Classifier({
        pdfTypes: ['application/x-custom-pdf'],
        xmlTypes: ['application/custom-xml'],
        imageTypes: ['image/custom'],
      });

      const detectedFile: DetectedFile = {
        mimeType: 'application/x-custom-pdf',
        extension: 'cpdf',
        detectionMethod: 'magic-number',
        isSupported: true,
        size: 10000,
      };

      const result = customClassifier.classify(detectedFile);

      expect(result.processor).toBe('pdf-parser');
      expect(result.category).toBe('pdf-document');
    });
  });

  describe('createClassifierFromEnv', () => {
    const originalEnv = process.env;

    beforeEach(() => {
      jest.resetModules();
      process.env = { ...originalEnv };
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it('should create classifier with default rules when no env vars set', () => {
      const { createClassifierFromEnv } = require('../../src/classifier');
      const classifier = createClassifierFromEnv();
      const rules = classifier.getRules();

      expect(rules.pdfTypes).toEqual(['application/pdf']);
      expect(rules.xmlTypes).toEqual(['application/xml', 'text/xml']);
      expect(rules.imageTypes).toContain('image/jpeg');
    });

    it('should create classifier with custom PDF types from env', () => {
      process.env.PDF_MIME_TYPES = 'application/pdf,application/x-pdf';

      const { createClassifierFromEnv } = require('../../src/classifier');
      const classifier = createClassifierFromEnv();
      const rules = classifier.getRules();

      expect(rules.pdfTypes).toEqual(['application/pdf', 'application/x-pdf']);
    });

    it('should create classifier with custom XML types from env', () => {
      process.env.XML_MIME_TYPES = 'application/xml,text/xml,application/ubl+xml';

      const { createClassifierFromEnv } = require('../../src/classifier');
      const classifier = createClassifierFromEnv();
      const rules = classifier.getRules();

      expect(rules.xmlTypes).toEqual([
        'application/xml',
        'text/xml',
        'application/ubl+xml',
      ]);
    });

    it('should create classifier with custom image types from env', () => {
      process.env.IMAGE_MIME_TYPES = 'image/jpeg,image/png,image/webp';

      const { createClassifierFromEnv } = require('../../src/classifier');
      const classifier = createClassifierFromEnv();
      const rules = classifier.getRules();

      expect(rules.imageTypes).toEqual(['image/jpeg', 'image/png', 'image/webp']);
    });

    it('should trim whitespace from env var values', () => {
      process.env.PDF_MIME_TYPES = ' application/pdf , application/x-pdf ';

      const { createClassifierFromEnv } = require('../../src/classifier');
      const classifier = createClassifierFromEnv();
      const rules = classifier.getRules();

      expect(rules.pdfTypes).toEqual(['application/pdf', 'application/x-pdf']);
    });

    it('should create classifier with all custom rules', () => {
      process.env.PDF_MIME_TYPES = 'application/pdf';
      process.env.XML_MIME_TYPES = 'application/xml';
      process.env.IMAGE_MIME_TYPES = 'image/jpeg';

      const { createClassifierFromEnv } = require('../../src/classifier');
      const classifier = createClassifierFromEnv();
      const rules = classifier.getRules();

      expect(rules.pdfTypes).toEqual(['application/pdf']);
      expect(rules.xmlTypes).toEqual(['application/xml']);
      expect(rules.imageTypes).toEqual(['image/jpeg']);
    });

    it('should use default PDF types when PDF_MIME_TYPES not set', () => {
      process.env.XML_MIME_TYPES = 'application/xml';
      process.env.IMAGE_MIME_TYPES = 'image/jpeg';
      delete process.env.PDF_MIME_TYPES;

      const { createClassifierFromEnv } = require('../../src/classifier');
      const classifier = createClassifierFromEnv();
      const rules = classifier.getRules();

      expect(rules.pdfTypes).toContain('application/pdf');
    });

    it('should use default XML types when XML_MIME_TYPES not set', () => {
      process.env.PDF_MIME_TYPES = 'application/pdf';
      process.env.IMAGE_MIME_TYPES = 'image/jpeg';
      delete process.env.XML_MIME_TYPES;

      const { createClassifierFromEnv } = require('../../src/classifier');
      const classifier = createClassifierFromEnv();
      const rules = classifier.getRules();

      expect(rules.xmlTypes).toContain('application/xml');
    });

    it('should use default image types when IMAGE_MIME_TYPES not set', () => {
      process.env.PDF_MIME_TYPES = 'application/pdf';
      process.env.XML_MIME_TYPES = 'application/xml';
      delete process.env.IMAGE_MIME_TYPES;

      const { createClassifierFromEnv } = require('../../src/classifier');
      const classifier = createClassifierFromEnv();
      const rules = classifier.getRules();

      expect(rules.imageTypes).toContain('image/jpeg');
    });
  });
});
