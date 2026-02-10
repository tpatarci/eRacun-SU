# KLASUS 2025 - Croatian Product Classification System (KPD Codes)

**Full Name:** Klasifikacija Proizvoda po Djelatnostima 2025
**Version:** 2025
**Authority:** Državni zavod za statistiku (Croatian Bureau of Statistics)
**Status:** ✅ ACTIVE - Mandatory for all invoice line items from 1 Jan 2026
**Last Verified:** 2025-11-09

---

## Official Source

**Primary:** https://www.dzs.hr/ (Croatian Bureau of Statistics)
**KLASUS Application:** https://klasus.dzs.hr/ (web-based lookup tool)
**Support Contact:** KPD@dzs.hr

**Croatian Requirement:** See `/CROATIAN_COMPLIANCE.md` section 2.3

---

## What is KPD?

KPD (Klasifikacija Proizvoda po Djelatnostima) is the **Croatian product classification system**. Every line item on an e-invoice **MUST** have a valid 6-digit KPD code.

**Penalty for Missing KPD:** Tax Authority will **reject the entire invoice**.

---

## Directory Contents

```
KLASUS-2025/
├── README.md              # This file
├── kpd_registry.csv       # Complete KPD code list (to be downloaded)
├── kpd_structure.md       # Hierarchical structure explanation
└── examples/              # Common product mappings
    ├── services.md        # Service industry codes
    ├── goods.md           # Physical goods codes
    └── agriculture.md     # Agricultural products
```

---

## Code Format

**Format:** Minimum 6 digits (can be more specific with additional digits)

**Example:**
```
62.01.0   - Computer programming activities
  62       - Information technology services
    62.01   - Computer programming
      62.01.0 - General computer programming
```

---

## How to Find KPD Codes

### Option 1: Web Application
1. Visit https://klasus.dzs.hr/
2. Search by product/service description (Croatian language)
3. Select most specific applicable code

### Option 2: CSV Registry
1. Download complete registry: `kpd_registry.csv`
2. Search locally (faster for bulk operations)
3. Import into database for validation service

### Option 3: Email Support
- **For unclear classifications:** KPD@dzs.hr
- **Response time:** 3-5 business days

---

## Required Before 31 Dec 2025

**⚠️ CRITICAL PRE-LAUNCH TASK:**

All customers **MUST** map their products/services to KPD codes before production launch.

**Workflow:**
1. Customer provides product/service catalog
2. Platform assists in KPD mapping (semi-automated + manual review)
3. Mapping stored in customer database
4. Invoice generation auto-populates KPD codes

**See:** `/CROATIAN_COMPLIANCE.md` section 4.1 (Customer Onboarding)

---

## Common Codes (Reference)

**⚠️ ALWAYS verify current codes in official registry. These are examples only.**

### Services
| KPD Code | Description (Croatian) | Description (English) |
|----------|------------------------|------------------------|
| 62.01.0 | Programiranje | Computer programming |
| 62.02.0 | Savjetovanje | IT consultancy |
| 69.10.0 | Pravne djelatnosti | Legal activities |
| 70.22.0 | Poslovno i drugo savjetovanje | Business consulting |
| 71.12.0 | Inženjering | Engineering services |

### Goods
| KPD Code | Description (Croatian) | Description (English) |
|----------|------------------------|------------------------|
| 26.20.1 | Računala | Computers |
| 26.30.0 | Komunikacijska oprema | Communication equipment |
| 28.99.0 | Ostali strojevi | Other machinery |

### Agriculture
| KPD Code | Description (Croatian) | Description (English) |
|----------|------------------------|------------------------|
| 01.11.1 | Uzgoj žitarica | Growing of cereals |
| 01.13.0 | Uzgoj povrća | Growing of vegetables |

---

## Validation Requirements

### In `kpd-validator` Service:

**Validation Checks:**
1. **Format:** Minimum 6 digits
2. **Exists:** Code present in official registry
3. **Active:** Code not deprecated
4. **Appropriate:** Code matches product category (optional warning)

**Error Codes:**
- `KPD_INVALID_FORMAT` - Not 6+ digits
- `KPD_NOT_FOUND` - Code not in registry
- `KPD_DEPRECATED` - Code exists but is deprecated
- `KPD_INAPPROPRIATE` - Code doesn't match product (warning only)

---

## Registry File Format

**File:** `kpd_registry.csv`

```csv
code,description_hr,description_en,status,parent_code,effective_date
620100,"Programiranje","Computer programming","active","6201","2025-01-01"
620200,"Savjetovanje u vezi s računalnom opremom","IT consultancy","active","6202","2025-01-01"
010110,"Uzgoj žitarica","Growing of cereals","active","0101","2025-01-01"
```

**Columns:**
- `code` - KPD code (string, leading zeros preserved)
- `description_hr` - Croatian description
- `description_en` - English description (for reference)
- `status` - `active` | `deprecated`
- `parent_code` - Parent category code
- `effective_date` - When code became active

---

## Update Frequency

**Official Updates:** Annually (usually January)

**Monitoring:**
- Subscribe to DZS announcements
- Check for updates quarterly
- Re-download registry before each major release

**This directory contains IMMUTABLE reference materials.**

**Update Policy:**
- ❌ Do NOT edit or prune historical registry snapshots once committed.
- ❌ Do NOT transcribe codes manually—always import the official CSV.
- ✅ When DZS publishes a new registry, add a timestamped CSV (e.g., `kpd_registry-20251109.csv`) and update references.
- ✅ Document the download date and official announcement link in commit messages and `TBD.md`.

**Version Control:**
```bash
# Tag registry with download date
git add docs/standards/KLASUS-2025/kpd_registry.csv
git commit -m "data(klasus): update KPD registry from dzs.hr (2025-11-09)"
git tag klasus-2025-20251109
```

---

## Integration in Services

### `kpd-validator` Service
- Loads `kpd_registry.csv` at startup
- Caches in Redis (TTL: 24 hours)
- Daily sync with official source
- Exposes gRPC validation API

### `ubl-generator` Service
- Reads KPD from invoice line item metadata
- Inserts into UBL XML:
  ```xml
  <cac:StandardItemIdentification>
    <cbc:ID schemeID="HR:KPD">620100</cbc:ID>
  </cac:StandardItemIdentification>
  ```

### `web-gateway` API
- Product catalog UI includes KPD search
- Auto-suggest KPD codes based on product name
- Manual override for edge cases

---

## Service References

**Services MUST reference this directory:**

### ✅ Correct (in service CLAUDE.md):
```markdown
## KPD Validation
**Registry:** `/docs/standards/KLASUS-2025/kpd_registry.csv`
**Authority:** Croatian Bureau of Statistics (DZS)
**See:** `/docs/standards/KLASUS-2025/README.md` for details
```

### ❌ Wrong (duplication):
```markdown
## KPD Codes
Here is a list of all KPD codes:
620100 - Programming
620200 - Consulting
[... 10,000 lines ...]
```

---

## External Resources

- **DZS Homepage:** https://www.dzs.hr/
- **KLASUS Web App:** https://klasus.dzs.hr/
- **Official Documentation:** Contact KPD@dzs.hr for PDF guides

---

**Maintainer:** Compliance Team + Technical Lead
**Last Updated:** 2025-11-09
**Next Review:** Quarterly (check for DZS updates)
