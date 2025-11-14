/**
 * OIB (Croatian Personal Identification Number) Validator
 *
 * Validates Croatian OIB numbers using ISO 7064, MOD 11-10 algorithm
 */

export function validateOIB(oib: string): boolean {
  // OIB must be exactly 11 digits
  if (!/^\d{11}$/.test(oib)) {
    return false;
  }

  // ISO 7064, MOD 11-10 checksum validation
  let controlNumber = 10;

  for (let i = 0; i < 10; i++) {
    controlNumber += parseInt(oib[i], 10);
    controlNumber %= 10;

    if (controlNumber === 0) {
      controlNumber = 10;
    }

    controlNumber *= 2;
    controlNumber %= 11;
  }

  const checkDigit = 11 - controlNumber;
  const lastDigit = checkDigit === 10 ? 0 : checkDigit;

  return lastDigit === parseInt(oib[10], 10);
}
