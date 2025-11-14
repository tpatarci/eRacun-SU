/**
 * File Type Detector
 * Detects file MIME types using magic bytes and file extensions
 */

import mime from 'mime-types';
import pino from 'pino';

const logger = pino({ name: 'file-detector' });

/**
 * Detect MIME type from buffer and filename
 * Uses magic bytes as primary method, falls back to extension
 */
export async function detectMimeType(buffer: Buffer, filename: string): Promise<string> {
  try {
    // Try magic bytes detection first
    const mimeFromMagic = detectMimeFromMagicBytes(buffer);

    if (mimeFromMagic) {
      logger.debug({ filename, mimeType: mimeFromMagic }, 'MIME type detected from magic bytes');
      return mimeFromMagic;
    }

    // Fallback to file extension
    const mimeFromExt = mime.lookup(filename);
    if (mimeFromExt) {
      logger.debug({ filename, mimeType: mimeFromExt }, 'MIME type detected from extension');
      return mimeFromExt;
    }

    // Default to binary
    logger.warn({ filename }, 'Could not detect MIME type, using default');
    return 'application/octet-stream';

  } catch (error) {
    logger.error({ error, filename }, 'Error detecting MIME type');
    return 'application/octet-stream';
  }
}

/**
 * Detect MIME type from magic bytes
 */
function detectMimeFromMagicBytes(buffer: Buffer): string | null {
  if (buffer.length < 4) {
    return null;
  }

  // PDF: %PDF
  if (buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46) {
    return 'application/pdf';
  }

  // ZIP: PK
  if (buffer[0] === 0x50 && buffer[1] === 0x4B && (buffer[2] === 0x03 || buffer[2] === 0x05)) {
    return 'application/zip';
  }

  // XML: <?xml
  if (buffer[0] === 0x3C && buffer[1] === 0x3F && buffer[2] === 0x78 && buffer[3] === 0x6D) {
    return 'application/xml';
  }

  // JPEG: FF D8 FF
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
    return 'image/jpeg';
  }

  // PNG: 89 50 4E 47
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
    return 'image/png';
  }

  // TIFF: II (little-endian) or MM (big-endian)
  if ((buffer[0] === 0x49 && buffer[1] === 0x49 && buffer[2] === 0x2A && buffer[3] === 0x00) ||
      (buffer[0] === 0x4D && buffer[1] === 0x4D && buffer[2] === 0x00 && buffer[3] === 0x2A)) {
    return 'image/tiff';
  }

  // RAR: 52 61 72 21
  if (buffer[0] === 0x52 && buffer[1] === 0x61 && buffer[2] === 0x72 && buffer[3] === 0x21) {
    return 'application/x-rar-compressed';
  }

  // 7-Zip: 37 7A BC AF
  if (buffer[0] === 0x37 && buffer[1] === 0x7A && buffer[2] === 0xBC && buffer[3] === 0xAF) {
    return 'application/x-7z-compressed';
  }

  // GZIP: 1F 8B
  if (buffer[0] === 0x1F && buffer[1] === 0x8B) {
    return 'application/gzip';
  }

  return null;
}

/**
 * Validate file signature (magic bytes)
 */
export function validateFileSignature(buffer: Buffer, expectedMimeType: string): boolean {
  if (buffer.length < 4) {
    return false;
  }

  const magicBytes: Record<string, number[][]> = {
    'application/pdf': [[0x25, 0x50, 0x44, 0x46]], // %PDF
    'application/zip': [[0x50, 0x4B, 0x03, 0x04], [0x50, 0x4B, 0x05, 0x06]], // PK
    'application/xml': [[0x3C, 0x3F, 0x78, 0x6D]], // <?xml
    'image/jpeg': [[0xFF, 0xD8, 0xFF]], // JPEG
    'image/png': [[0x89, 0x50, 0x4E, 0x47]], // PNG
    'image/tiff': [[0x49, 0x49, 0x2A, 0x00], [0x4D, 0x4D, 0x00, 0x2A]] // TIFF
  };

  const expected = magicBytes[expectedMimeType];
  if (!expected) {
    return true; // No validation rule, assume valid
  }

  // Check if buffer matches any of the expected signatures
  return expected.some(signature =>
    signature.every((byte, index) => buffer[index] === byte)
  );
}

/**
 * Check if file is a known invoice format
 */
export function isInvoiceFormat(mimeType: string): boolean {
  const invoiceFormats = [
    'application/pdf',
    'application/xml',
    'text/xml',
    'application/vnd.oasis.opendocument.text',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  ];

  return invoiceFormats.includes(mimeType);
}

/**
 * Check if file is an image that might need OCR
 */
export function requiresOCR(mimeType: string): boolean {
  const imageFormats = [
    'image/jpeg',
    'image/jpg',
    'image/png',
    'image/tiff',
    'image/bmp',
    'image/gif'
  ];

  return imageFormats.includes(mimeType);
}

/**
 * Get file extension from MIME type
 */
export function getExtensionFromMime(mimeType: string): string {
  const ext = mime.extension(mimeType);
  return ext || 'bin';
}

/**
 * Validate file size is within acceptable range
 */
export function validateFileSize(
  size: number,
  minSize = 0,
  maxSize = 10 * 1024 * 1024
): { valid: boolean; error?: string } {
  if (size < minSize) {
    return {
      valid: false,
      error: `File size ${size} bytes is below minimum ${minSize} bytes`
    };
  }

  if (size > maxSize) {
    return {
      valid: false,
      error: `File size ${size} bytes exceeds maximum ${maxSize} bytes`
    };
  }

  return { valid: true };
}
