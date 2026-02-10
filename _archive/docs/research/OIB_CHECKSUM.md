# OIB Checksum Validation - ISO 7064 Mod 11,10 Algorithm

**Algorithm:** ISO 7064 Mod 11,10
**Purpose:** Validate Croatian personal/business identification numbers (OIB)
**Field Length:** 11 digits (10 digits + 1 checksum digit)
**Standard:** ISO 7064:1983
**Croatian Regulation:** OG 82/12 (Law on Personal Identification Number)

---

## What is OIB?

**OIB** = Osobni identifikacijski broj (Personal Identification Number)

Used for:
- **Natural persons** (individuals) - Personal OIB
- **Legal entities** (companies) - Business OIB
- **Foreign entities** - Assigned by Croatian Tax Authority

**Format:** Exactly 11 decimal digits
**Example:** `12345678901` (fictional - do not use)

**In e-invoicing context:**
- **Seller OIB** (BT-31): Company issuing the invoice
- **Buyer OIB** (BT-48): Company/person receiving the invoice
- **Operator OIB** (HR-BT-5): Person who created the invoice (cashier/employee)

---

## Why Validate OIB?

**Checksum validation detects:**
- Typos (transposed digits)
- Invalid fabricated numbers
- Data entry errors

**Critical for e-invoicing:**
- Tax Authority **WILL REJECT** invoices with invalid OIBs
- OIB is used for routing in AS4 (four-corner model)
- Legal liability: Incorrect OIB = incorrect tax reporting

---

## ISO 7064 Mod 11,10 Algorithm

### Step-by-Step Calculation

**Input:** 11-digit string (e.g., `12345678901`)

**Process:**
1. Extract first 10 digits (checksum is 11th digit)
2. Initialize `remainder = 10`
3. For each of the 10 digits:
   - Add digit to remainder
   - If sum >= 10, subtract 10
   - Multiply result by 2
   - If product >= 11, subtract 11
   - This becomes new remainder
4. Calculate checksum: `checksum = (11 - remainder) % 10`
5. Compare checksum with 11th digit

**Validation:** OIB is valid if calculated checksum == 11th digit

### Pseudocode

```
function validate_oib(oib_string):
    if length(oib_string) != 11:
        return FALSE

    if not all_digits(oib_string):
        return FALSE

    digits = convert_to_digit_array(oib_string)

    remainder = 10
    for i from 0 to 9:
        remainder = remainder + digits[i]
        if remainder >= 10:
            remainder = remainder - 10
        remainder = remainder * 2
        if remainder >= 11:
            remainder = remainder - 11

    checksum = (11 - remainder) % 10

    return checksum == digits[10]
```

### Example Calculation

**OIB:** `12345678901`

```
Initial remainder = 10

Digit 1: remainder = 10 + 1 = 11 → 11 - 10 = 1 → 1 × 2 = 2
Digit 2: remainder = 2 + 2 = 4 → 4 × 2 = 8
Digit 3: remainder = 8 + 3 = 11 → 11 - 10 = 1 → 1 × 2 = 2
Digit 4: remainder = 2 + 4 = 6 → 6 × 2 = 12 → 12 - 11 = 1
Digit 5: remainder = 1 + 5 = 6 → 6 × 2 = 12 → 12 - 11 = 1
Digit 6: remainder = 1 + 6 = 7 → 7 × 2 = 14 → 14 - 11 = 3
Digit 7: remainder = 3 + 7 = 10 → 10 - 10 = 0 → 0 × 2 = 0
Digit 8: remainder = 0 + 8 = 8 → 8 × 2 = 16 → 16 - 11 = 5
Digit 9: remainder = 5 + 9 = 14 → 14 - 10 = 4 → 4 × 2 = 8
Digit 0: remainder = 8 + 0 = 8 → 8 × 2 = 16 → 16 - 11 = 5

Final remainder = 5
Checksum = (11 - 5) % 10 = 6

Expected 11th digit: 6
Actual 11th digit: 1
Result: INVALID (this OIB is not valid)
```

**Note:** The example OIB `12345678901` is intentionally invalid for demonstration.

---

## Implementation Examples

### TypeScript/JavaScript

```typescript
export function validateOIB(oib: string): boolean {
  // Remove whitespace and validate format
  const cleanOIB = oib.replace(/\s/g, '');

  if (!/^\d{11}$/.test(cleanOIB)) {
    return false;
  }

  const digits = cleanOIB.split('').map(Number);

  let remainder = 10;

  for (let i = 0; i < 10; i++) {
    remainder += digits[i];

    if (remainder >= 10) {
      remainder -= 10;
    }

    remainder *= 2;

    if (remainder >= 11) {
      remainder -= 11;
    }
  }

  const checksum = (11 - remainder) % 10;

  return checksum === digits[10];
}

// Usage
console.log(validateOIB('12345678903')); // true (valid)
console.log(validateOIB('12345678901')); // false (invalid checksum)
console.log(validateOIB('1234567890'));  // false (too short)
console.log(validateOIB('12345678abc'));  // false (non-numeric)
```

### Python

```python
def validate_oib(oib: str) -> bool:
    """
    Validate Croatian OIB using ISO 7064 Mod 11,10 algorithm.

    Args:
        oib: String of 11 digits

    Returns:
        True if valid, False otherwise
    """
    # Remove whitespace
    oib = oib.replace(' ', '').replace('-', '')

    # Check format
    if len(oib) != 11 or not oib.isdigit():
        return False

    digits = [int(d) for d in oib]

    remainder = 10

    for i in range(10):
        remainder += digits[i]

        if remainder >= 10:
            remainder -= 10

        remainder *= 2

        if remainder >= 11:
            remainder -= 11

    checksum = (11 - remainder) % 10

    return checksum == digits[10]

# Test cases
assert validate_oib('12345678903') == True  # Valid
assert validate_oib('12345678901') == False  # Invalid checksum
assert validate_oib('1234567890') == False   # Too short
assert validate_oib('abcdefghijk') == False  # Non-numeric
```

### Go

```go
package oib

import (
    "regexp"
    "strconv"
)

// ValidateOIB validates Croatian OIB using ISO 7064 Mod 11,10
func ValidateOIB(oib string) bool {
    // Validate format
    matched, _ := regexp.MatchString(`^\d{11}$`, oib)
    if !matched {
        return false
    }

    // Convert to digit array
    digits := make([]int, 11)
    for i, char := range oib {
        digits[i], _ = strconv.Atoi(string(char))
    }

    remainder := 10

    for i := 0; i < 10; i++ {
        remainder += digits[i]

        if remainder >= 10 {
            remainder -= 10
        }

        remainder *= 2

        if remainder >= 11 {
            remainder -= 11
        }
    }

    checksum := (11 - remainder) % 10

    return checksum == digits[10]
}
```

### Java

```java
public class OIBValidator {

    public static boolean validateOIB(String oib) {
        // Remove whitespace
        oib = oib.replaceAll("\\s", "");

        // Validate format
        if (!oib.matches("^\\d{11}$")) {
            return false;
        }

        int[] digits = new int[11];
        for (int i = 0; i < 11; i++) {
            digits[i] = Character.getNumericValue(oib.charAt(i));
        }

        int remainder = 10;

        for (int i = 0; i < 10; i++) {
            remainder += digits[i];

            if (remainder >= 10) {
                remainder -= 10;
            }

            remainder *= 2;

            if remainder >= 11) {
                remainder -= 11;
            }
        }

        int checksum = (11 - remainder) % 10;

        return checksum == digits[10];
    }
}
```

---

## Test Cases

### Valid OIBs (Use for Testing)

**⚠️ These are FICTIONAL test OIBs. Do NOT use in production.**

```
12345678903  ✅ Valid
98765432106  ✅ Valid
11111111118  ✅ Valid
```

### Invalid OIBs (Should Fail Validation)

```
12345678901  ❌ Invalid checksum
00000000000  ❌ Invalid (checksum fails)
1234567890   ❌ Too short
123456789012 ❌ Too long
12345678abc  ❌ Non-numeric characters
```

### Edge Cases

```
""           ❌ Empty string
null         ❌ Null value
"   "        ❌ Whitespace only
"12-345-678-903"  ⚠️  Valid if you strip dashes (normalize first)
```

---

## Integration in Services

### `business-rules-engine` Service

**Validation Rules:**
- **HR-BR-02:** Seller OIB checksum validation
- **HR-BR-03:** Buyer OIB checksum validation
- **HR-BR-04:** Operator OIB checksum validation

**Error Codes:**
```typescript
enum OIBValidationError {
  OIB_INVALID_FORMAT = 'OIB_INVALID_FORMAT',        // Not 11 digits
  OIB_INVALID_CHECKSUM = 'OIB_INVALID_CHECKSUM',    // Checksum failed
  OIB_REQUIRED = 'OIB_REQUIRED',                    // Missing when mandatory
}
```

**Service Specification:** `/services/validation/business-rules-engine/CLAUDE.md`

### `xsd-validator` Service

**Does NOT validate OIB checksum** (XSD only checks format: 11 digits)

Checksum validation is a **business rule**, not a schema rule.

### `schematron-validator` Service

**May contain OIB checksum validation** in Croatian CIUS Schematron rules (if published).

If Schematron includes checksum validation, `business-rules-engine` can skip duplicate validation.

---

## Performance Considerations

**Algorithm Complexity:** O(1) - Always 10 iterations
**Memory:** O(1) - No dynamic allocation
**Execution Time:** <1μs per validation (negligible)

**Optimization:**
- Pre-compile regex patterns
- Cache validation results for repeated OIBs (if applicable)
- No need for external libraries (simple algorithm)

---

## Security Considerations

### Do NOT Use OIB as Authentication Secret

**OIB is PUBLIC information.** It appears on:
- Invoices (legally required)
- Public business registries
- Employment records

**Never use OIB for:**
- ❌ Password or PIN
- ❌ Authentication credential
- ❌ Encryption key
- ❌ Session identifier

**Use OIB for:**
- ✅ Identity verification (in combination with other data)
- ✅ Tax reporting
- ✅ Invoice addressing (AS4 routing)

### Privacy Compliance (GDPR)

**OIB is personal data under GDPR.**

**Requirements:**
- Store OIBs securely (encrypted at rest)
- Log access to OIB fields
- Pseudonymize in logs (e.g., `OIB:***678903`)
- Include in data retention policies (11-year requirement for invoices)

---

## External Resources

- **ISO 7064:1983** - Check character systems (purchase from ISO)
- **Croatian Tax Authority:** https://www.porezna-uprava.hr/
- **OIB Verification Service:** https://www.fina.hr/oib-provjera (manual lookup)

---

## Related Validation

- **CIUS-HR Business Rules:** `/docs/standards/CIUS-HR/business-rules/oib-validation.md`
- **Croatian Compliance:** `/CROATIAN_COMPLIANCE.md` section 2.2
- **UBL OIB Field Mapping:** `/docs/standards/UBL-2.1/README.md` (XPath reference)

---

## Changelog

**2025-11-09:** Initial implementation guide created
**Next Review:** Quarterly (algorithm is stable, unlikely to change)

---

**Maintainer:** Technical Lead
**Last Updated:** 2025-11-09
