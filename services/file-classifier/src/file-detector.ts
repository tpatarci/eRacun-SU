/**
 * File Detector Module
 *
 * Detects file types using magic numbers and extension fallback.
 * - Magic number detection (file-type library)
 * - Extension-based fallback (mime-types library)
 * - File validation (size limits, supported formats)
 */

import fileType from 'file-type';
import mime from 'mime-types';
import { logger, fileSizeBytes, classificationErrorsTotal } from './observability';

/**
 * Detected file information
 */
export interface DetectedFile {
  /** MIME type (e.g., 'application/pdf') */
  mimeType: string;
  /** File extension (e.g., 'pdf') */
  extension: string;
  /** Detection method used */
  detectionMethod: 'magic-number' | 'extension' | 'unknown';
  /** Whether file type is supported */
  isSupported: boolean;
  /** File size in bytes */
  size: number;
}

/**
 * File validation options
 */
export interface ValidationOptions {
  /** Maximum file size in bytes */
  maxFileSize: number;
  /** Minimum file size in bytes */
  minFileSize: number;
  /** Supported MIME types (empty = allow all) */
  supportedMimeTypes: string[];
}

/**
 * Default validation options
 */
const DEFAULT_VALIDATION: ValidationOptions = {
  maxFileSize: 10 * 1024 * 1024, // 10 MB
  minFileSize: 1, // 1 byte
  supportedMimeTypes: [
    'application/pdf',
    'application/xml',
    'text/xml',
    'image/jpeg',
    'image/jpg',
    'image/png',
    'image/tiff',
  ],
};

/**
 * File Detector
 */
export class FileDetector {
  private validationOptions: ValidationOptions;

  constructor(validationOptions: ValidationOptions = DEFAULT_VALIDATION) {
    this.validationOptions = validationOptions;
  }

  /**
   * Detect file type from buffer
   *
   * @param buffer - File content buffer
   * @param filename - Original filename (for fallback)
   * @returns Detected file information
   */
  async detectFileType(buffer: Buffer, filename?: string): Promise<DetectedFile> {
    const size = buffer.length;

    // Record file size metric
    const detectedMimeType = await this.detectMimeType(buffer, filename);
    fileSizeBytes.observe({ file_type: detectedMimeType || 'unknown' }, size);

    // Validate file size
    if (!this.validateFileSize(size)) {
      classificationErrorsTotal.inc({ error_type: 'size_exceeded' });
      throw new Error(
        `File size ${size} bytes exceeds limit of ${this.validationOptions.maxFileSize} bytes`
      );
    }

    // Try magic number detection first
    const magicDetection = await this.detectByMagicNumber(buffer);
    if (magicDetection) {
      logger.debug({ mimeType: magicDetection.mimeType }, 'File type detected by magic number');

      const isSupported = this.isSupportedType(magicDetection.mimeType);

      return {
        mimeType: magicDetection.mimeType,
        extension: magicDetection.extension,
        detectionMethod: 'magic-number',
        isSupported,
        size,
      };
    }

    // Fallback to extension-based detection
    if (filename) {
      const extensionDetection = this.detectByExtension(filename);
      if (extensionDetection) {
        logger.debug(
          { mimeType: extensionDetection.mimeType, filename },
          'File type detected by extension'
        );

        const isSupported = this.isSupportedType(extensionDetection.mimeType);

        return {
          mimeType: extensionDetection.mimeType,
          extension: extensionDetection.extension,
          detectionMethod: 'extension',
          isSupported,
          size,
        };
      }
    }

    // Detection failed
    logger.warn({ filename, size }, 'Unable to detect file type');
    classificationErrorsTotal.inc({ error_type: 'detection_failed' });

    return {
      mimeType: 'application/octet-stream',
      extension: 'bin',
      detectionMethod: 'unknown',
      isSupported: false,
      size,
    };
  }

  /**
   * Detect file type using magic numbers
   */
  private async detectByMagicNumber(
    buffer: Buffer
  ): Promise<{ mimeType: string; extension: string } | null> {
    try {
      const result = await fileType.fromBuffer(buffer);
      if (result) {
        return {
          mimeType: result.mime,
          extension: result.ext,
        };
      }
      return null;
    } catch (error) {
      logger.error({ error }, 'Magic number detection failed');
      return null;
    }
  }

  /**
   * Detect file type from filename extension
   */
  private detectByExtension(filename: string): { mimeType: string; extension: string } | null {
    const mimeType = mime.lookup(filename);
    if (mimeType) {
      const extension = mime.extension(mimeType);
      if (extension) {
        return {
          mimeType,
          extension,
        };
      }
    }
    return null;
  }

  /**
   * Detect MIME type (either by magic number or extension)
   */
  private async detectMimeType(buffer: Buffer, filename?: string): Promise<string | null> {
    const magic = await this.detectByMagicNumber(buffer);
    if (magic) return magic.mimeType;

    if (filename) {
      const ext = this.detectByExtension(filename);
      if (ext) return ext.mimeType;
    }

    return null;
  }

  /**
   * Check if MIME type is supported
   */
  private isSupportedType(mimeType: string): boolean {
    // Empty list means all types are supported
    if (this.validationOptions.supportedMimeTypes.length === 0) {
      return true;
    }

    return this.validationOptions.supportedMimeTypes.includes(mimeType);
  }

  /**
   * Validate file size
   */
  private validateFileSize(size: number): boolean {
    return (
      size >= this.validationOptions.minFileSize &&
      size <= this.validationOptions.maxFileSize
    );
  }

  /**
   * Get current validation options
   */
  getValidationOptions(): ValidationOptions {
    return { ...this.validationOptions };
  }

  /**
   * Update validation options
   */
  setValidationOptions(options: Partial<ValidationOptions>): void {
    this.validationOptions = {
      ...this.validationOptions,
      ...options,
    };
    logger.info({ validationOptions: this.validationOptions }, 'Validation options updated');
  }
}

/**
 * Create file detector from environment variables
 */
export function createFileDetectorFromEnv(): FileDetector {
  const supportedMimeTypes = process.env.SUPPORTED_MIME_TYPES
    ? process.env.SUPPORTED_MIME_TYPES.split(',').map((type) => type.trim())
    : DEFAULT_VALIDATION.supportedMimeTypes;

  const maxFileSize = process.env.MAX_FILE_SIZE
    ? parseInt(process.env.MAX_FILE_SIZE, 10)
    : DEFAULT_VALIDATION.maxFileSize;

  const minFileSize = process.env.MIN_FILE_SIZE
    ? parseInt(process.env.MIN_FILE_SIZE, 10)
    : DEFAULT_VALIDATION.minFileSize;

  const options: ValidationOptions = {
    supportedMimeTypes,
    maxFileSize,
    minFileSize,
  };

  logger.info({ validationOptions: options }, 'Creating file detector');

  return new FileDetector(options);
}
