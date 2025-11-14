/**
 * Unit Tests for Image Preprocessor
 */

import { ImagePreprocessor } from '../../src/image-preprocessor';

describe('ImagePreprocessor', () => {
  let preprocessor: ImagePreprocessor;

  beforeEach(() => {
    preprocessor = new ImagePreprocessor({
      maxWidth: 2000,
      maxHeight: 2000
    });
  });

  describe('validate', () => {
    it('should reject 1x1 image as too small', async () => {
      // 1x1 pixel is below minimum size of 100x100
      const tinyPng = Buffer.from(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
        'base64'
      );

      const result = await preprocessor.validate(tinyPng);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('too small'))).toBe(true);
    });

    it('should reject invalid image data', async () => {
      const invalidData = Buffer.from('not an image');

      const result = await preprocessor.validate(invalidData);

      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject empty buffer', async () => {
      const emptyBuffer = Buffer.from([]);

      const result = await preprocessor.validate(emptyBuffer);

      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject images that are too small', async () => {
      // 1x1 pixel image is too small (minimum is 100x100)
      const tinyPng = Buffer.from(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
        'base64'
      );

      const result = await preprocessor.validate(tinyPng);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('too small'))).toBe(true);
    });
  });

  describe('preprocess', () => {
    it('should preprocess a valid image', async () => {
      const validPng = Buffer.from(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
        'base64'
      );

      const result = await preprocessor.preprocess(validPng);

      expect(result.buffer).toBeInstanceOf(Buffer);
      expect(result.width).toBeGreaterThan(0);
      expect(result.height).toBeGreaterThan(0);
      expect(result.format).toBe('png');
      expect(result.preprocessingApplied).toContain('grayscale');
      expect(result.preprocessingApplied).toContain('normalize');
      expect(result.preprocessingApplied).toContain('sharpen');
    });

    it('should apply preprocessing steps', async () => {
      const validPng = Buffer.from(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
        'base64'
      );

      const result = await preprocessor.preprocess(validPng);

      expect(result.preprocessingApplied.length).toBeGreaterThan(0);
      expect(result.preprocessingApplied).toEqual(
        expect.arrayContaining(['grayscale', 'normalize', 'sharpen'])
      );
    });

    it('should throw error for invalid image', async () => {
      const invalidData = Buffer.from('not an image');

      await expect(preprocessor.preprocess(invalidData)).rejects.toThrow();
    });
  });
});
