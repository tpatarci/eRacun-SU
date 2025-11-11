# UBL 2.1 XSD Schemas

This directory contains the official OASIS UBL 2.1 XSD schemas required for invoice validation.

## Required Schemas

**Version:** UBL 2.1 (OASIS Standard)
**Source:** http://docs.oasis-open.org/ubl/os-UBL-2.1/

### Download Instructions

1. **Download UBL 2.1 Package:**
   ```bash
   wget http://docs.oasis-open.org/ubl/os-UBL-2.1/UBL-2.1.zip
   ```

2. **Extract to this directory:**
   ```bash
   unzip UBL-2.1.zip -d ubl-2.1/
   ```

3. **Verify directory structure:**
   ```
   schemas/
   └── ubl-2.1/
       ├── maindoc/
       │   ├── UBL-Invoice-2.1.xsd
       │   ├── UBL-CreditNote-2.1.xsd
       │   └── ...
       └── common/
           ├── UBL-CommonAggregateComponents-2.1.xsd
           ├── UBL-CommonBasicComponents-2.1.xsd
           └── ...
   ```

### Required Files

**Main Document Schemas:**
- `maindoc/UBL-Invoice-2.1.xsd`
- `maindoc/UBL-CreditNote-2.1.xsd`

**Common Components (imported by main schemas):**
- `common/UBL-CommonAggregateComponents-2.1.xsd`
- `common/UBL-CommonBasicComponents-2.1.xsd`
- `common/UBL-CommonExtensionComponents-2.1.xsd`
- `common/UBL-QualifiedDataTypes-2.1.xsd`
- `common/UBL-UnqualifiedDataTypes-2.1.xsd`
- `common/UBL-CommonSignatureComponents-2.1.xsd`
- `common/UBL-SignatureAggregateComponents-2.1.xsd`
- `common/UBL-SignatureBasicComponents-2.1.xsd`
- `common/UBL-XAdESv132-2.1.xsd`
- `common/UBL-XAdESv141-2.1.xsd`
- `common/UBL-xmldsig-core-schema-2.1.xsd`

### Alternative: Clone from Git

```bash
git clone https://github.com/oasis-open/ubl-2.1.git ubl-2.1/
```

### Verification

After downloading, verify the schemas load correctly:

```bash
npm run dev
```

Check logs for:
```
[INFO] Loading XSD schemas
[INFO] XSD schemas loaded { schemas: [ 'UBL-Invoice-2.1', 'UBL-CreditNote-2.1' ] }
```

---

## License

UBL 2.1 schemas are published by OASIS under the OASIS IPR Policy.

**License:** OASIS Open License
**Copyright:** © OASIS Open 2001-2013
**Website:** http://www.oasis-open.org/

### Usage Rights

The UBL schemas may be used freely for:
- ✅ Development and testing
- ✅ Production systems
- ✅ Commercial applications
- ✅ Open source projects

**Attribution Required:** Yes, retain copyright notices in schema files

---

## Croatian CIUS Extensions

**Note:** The base UBL 2.1 schemas are validated here. Croatian CIUS (Core Invoice Usage Specification) business rules are validated separately by the `schematron-validator` service.

For CIUS specifications, see:
- `/docs/standards/CROATIAN_COMPLIANCE.md`
- Schematron rules in `/services/schematron-validator/rules/`

---

**Last Updated:** 2025-11-10
**Maintainer:** eRacun Development Team
