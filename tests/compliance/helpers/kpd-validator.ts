/**
 * KPD (KLASUS 2025) Code Validator
 *
 * Validates Croatian product classification codes
 */

// Sample valid KPD codes (in production, load from official registry)
const VALID_KPD_CODES = new Set([
  '26.20.11', // Laptops
  '26.30.22', // Smartphones
  '32.50.11', // Medical instruments
  '10.51.11', // Dairy products
  '46.90.11', // Wholesale trade
  '62.01.11', // Computer programming
  '63.11.11', // Data processing
  '71.11.11', // Architectural services
  '43.21.11', // Electrical installation
  '56.10.11', // Restaurant services
]);

export function validateKPDCode(code: string): boolean {
  // KPD format: XX.XX.XX
  if (!/^\d{2}\.\d{2}\.\d{2}$/.test(code)) {
    return false;
  }

  // In production, validate against official KLASUS 2025 registry
  // For testing, accept all codes in sample set + any valid format
  return VALID_KPD_CODES.has(code) || /^\d{2}\.\d{2}\.\d{2}$/.test(code);
}
