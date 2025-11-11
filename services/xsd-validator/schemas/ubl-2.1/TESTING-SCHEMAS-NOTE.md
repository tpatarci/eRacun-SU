# ⚠️ TESTING SCHEMAS - NOT FOR PRODUCTION

## What These Schemas Are

These are **MINIMAL, SIMPLIFIED** UBL 2.1 XSD schemas created for:
- ✅ Development and testing
- ✅ Running the test suite
- ✅ Local validation during development
- ✅ CI/CD automated testing

## What These Schemas Are NOT

These are **NOT** the official OASIS UBL 2.1 schemas and should **NEVER** be used in production.

**Missing from these minimal schemas:**
- ❌ Complete element definitions
- ❌ All data types and restrictions
- ❌ Complex business rules
- ❌ Full Croatian CIUS extensions
- ❌ Comprehensive validation rules

## For Production Use

**MANDATORY:** Download official UBL 2.1 schemas from OASIS:

```bash
# Download official UBL 2.1 package
wget http://docs.oasis-open.org/ubl/os-UBL-2.1/UBL-2.1.zip

# Extract (overwrites these minimal schemas)
unzip UBL-2.1.zip -d .

# Verify
ls -la maindoc/UBL-Invoice-2.1.xsd
```

**Source:** http://docs.oasis-open.org/ubl/os-UBL-2.1/

**License:** OASIS Open License
**Copyright:** © OASIS Open 2001-2013

---

## Why Minimal Schemas Exist

**Problem:** Official UBL 2.1 schemas are ~20MB, not suitable for git repository

**Solution:**
- Minimal schemas (5KB) in git for development
- Official schemas downloaded during deployment
- Tests work with both minimal and official schemas

---

## Schema Comparison

| Feature | Minimal (Testing) | Official (Production) |
|---------|-------------------|----------------------|
| Size | ~5KB | ~20MB |
| Elements | ~20 elements | 1000+ elements |
| Validation | Basic structure | Comprehensive |
| Business rules | None | Full UBL 2.1 spec |
| Croatian CIUS | Not included | Required separately |
| Use case | Dev/test only | Production required |

---

## Deployment Checklist

Before deploying to **staging** or **production**:

- [ ] Download official UBL 2.1 schemas
- [ ] Verify schemas load correctly (`npm run dev` and check logs)
- [ ] Run full test suite with official schemas
- [ ] Validate against real invoice samples
- [ ] Compare validation results with FINA test environment

---

## Test Coverage

**With Minimal Schemas:**
- ✅ Schema loading works
- ✅ Validation logic works
- ✅ Error handling works
- ⚠️ Limited validation rules

**With Official Schemas:**
- ✅ All of the above
- ✅ Complete UBL 2.1 validation
- ✅ Production-grade accuracy

---

**Created:** 2025-11-10
**Purpose:** Enable development without 20MB schemas in git
**Status:** FOR TESTING ONLY - NOT PRODUCTION
