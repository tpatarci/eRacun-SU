/**
 * Image Preprocessor
 * Prepares images for OCR by applying various transformations
 */

import sharp from 'sharp';
import pino from 'pino';
import { ImagePreprocessingResult } from './types';

const logger = pino({ name: 'image-preprocessor' });

export class ImagePreprocessor {
  private readonly maxWidth: number;
  private readonly maxHeight: number;

  constructor(options: { maxWidth?: number; maxHeight?: number } = {}) {
    this.maxWidth = options.maxWidth || 4000;
    this.maxHeight = options.maxHeight || 4000;
  }

  /**
   * Preprocess image for OCR
   * - Resize if too large
   * - Convert to grayscale
   * - Enhance contrast
   * - Sharpen text
   */
  async preprocess(buffer: Buffer): Promise<ImagePreprocessingResult> {
    const startTime = Date.now();
    const preprocessingApplied: string[] = [];

    try {
      let image = sharp(buffer);
      const metadata = await image.metadata();

      logger.debug(
        { width: metadata.width, height: metadata.height, format: metadata.format },
        'Original image metadata'
      );

      // Resize if too large
      if (metadata.width && metadata.width > this.maxWidth) {
        image = image.resize(this.maxWidth, undefined, {
          fit: 'inside',
          withoutEnlargement: true
        });
        preprocessingApplied.push('resize');
      }

      if (metadata.height && metadata.height > this.maxHeight) {
        image = image.resize(undefined, this.maxHeight, {
          fit: 'inside',
          withoutEnlargement: true
        });
        preprocessingApplied.push('resize');
      }

      // Convert to grayscale for better OCR
      image = image.grayscale();
      preprocessingApplied.push('grayscale');

      // Normalize (enhance contrast)
      image = image.normalize();
      preprocessingApplied.push('normalize');

      // Sharpen to make text clearer
      image = image.sharpen();
      preprocessingApplied.push('sharpen');

      // Convert to PNG for consistent processing
      const processedBuffer = await image.png().toBuffer();
      const processedMetadata = await sharp(processedBuffer).metadata();

      const processingTime = Date.now() - startTime;

      logger.info(
        {
          originalSize: buffer.length,
          processedSize: processedBuffer.length,
          preprocessingApplied,
          processingTime
        },
        'Image preprocessing complete'
      );

      return {
        buffer: processedBuffer,
        width: processedMetadata.width || 0,
        height: processedMetadata.height || 0,
        format: 'png',
        preprocessingApplied
      };
    } catch (error) {
      logger.error({ error }, 'Image preprocessing failed');
      throw new Error(`Image preprocessing failed: ${error}`);
    }
  }

  /**
   * Validate image format and size
   */
  async validate(buffer: Buffer): Promise<{ valid: boolean; errors: string[] }> {
    const errors: string[] = [];

    try {
      const metadata = await sharp(buffer).metadata();

      // Check format
      const supportedFormats = ['jpeg', 'jpg', 'png', 'tiff', 'webp', 'bmp'];
      if (!metadata.format || !supportedFormats.includes(metadata.format)) {
        errors.push(`Unsupported image format: ${metadata.format}`);
      }

      // Check dimensions
      if (!metadata.width || !metadata.height) {
        errors.push('Could not determine image dimensions');
      } else {
        if (metadata.width < 100 || metadata.height < 100) {
          errors.push('Image too small (minimum 100x100 pixels)');
        }
        if (metadata.width > 10000 || metadata.height > 10000) {
          errors.push('Image too large (maximum 10000x10000 pixels)');
        }
      }

      // Check file size
      if (buffer.length > 20 * 1024 * 1024) {
        errors.push('Image file size exceeds 20MB limit');
      }

      return {
        valid: errors.length === 0,
        errors
      };
    } catch (error) {
      errors.push(`Invalid image format: ${error}`);
      return { valid: false, errors };
    }
  }
}
