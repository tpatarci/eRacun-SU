# Croatian E-Invoice Compliance Requirements

## Fiskalizacija 2.0 Compliance

**⚠️ CRITICAL - HARD DEADLINE: 1 January 2026**

### Legal Framework
Croatian Fiscalization Law (NN 89/25)

**NON-COMPLIANCE PENALTIES:**
- **Fines:** Up to 66,360 EUR
- **VAT Deduction Loss:** Retroactive tax liability
- **Criminal Liability:** For intentional destruction of records

---

## 1. Mandatory Standards

### Document Formats
- **UBL 2.1** (OASIS Universal Business Language) - PRIMARY
- **EN 16931-1:2017** (European e-invoicing semantic model) - REQUIRED
- **Croatian CIUS** (Core Invoice Usage Specification with extensions) - REQUIRED
- **Alternative:** UN/CEFACT CII v.2.0 (less common)

### Mandatory Data Elements
- **OIB Numbers:** Issuer (BT-31), Operator (HR-BT-5), Recipient (BT-48)
- **KPD Classification:** 6-digit KLASUS 2025 codes for EVERY line item
- **VAT Breakdown:** Category codes + rates (25%, 13%, 5%, 0%)
- **Digital Signature:** XMLDSig with FINA X.509 certificate
- **Qualified Timestamp:** eIDAS-compliant for B2B invoices

---

## 2. Validation Layers

The system implements six validation layers to ensure compliance:

1. **Syntactic:** XSD schema validation (UBL 2.1)
2. **Business Rules:** Schematron validator (Croatian CIUS)
3. **KPD Validation:** Against official KLASUS registry
4. **Semantic:** Business rules engine (tax rates, VAT validation)
5. **Cross-Reference:** AI-based anomaly detection
6. **Consensus:** Triple redundancy with majority voting

---

## 3. Integration Endpoints

### Production Endpoints
- **B2C Fiscalization:** SOAP API `https://cis.porezna-uprava.hr:8449/FiskalizacijaService`
- **B2B Exchange:** AS4 protocol via Access Point (four-corner model)

### Test Environment
- **Test API:** `https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest`
- **Available:** From 1 September 2025

---

## 4. Audit & Archiving Requirements

### Retention Period
**11 YEARS** (NOT 7 years)

### Format Requirements
✅ **REQUIRED:**
- Original XML with UBL 2.1 structure
- Preserved digital signatures (must remain valid)
- Preserved qualified timestamps
- Submission confirmations (JIR for B2C, UUID for B2B)

❌ **NOT COMPLIANT:**
- PDF conversion
- Paper printouts

### Storage Characteristics
- **Immutability:** WORM (Write Once Read Many) required
- **Encryption:** AES-256 at rest (minimum)
- **Geographic Redundancy:** EU region + backup location
- **Integrity Verification:** Automated signature checks (monthly minimum)
- **Access Control:** Audit trail of all retrievals
- **Archive Tier:** Cold storage after 1 year (cost optimization)

### Audit Trail Requirements
- Every document transformation logged
- Request IDs propagated through entire processing chain
- Error context captured (never swallow exceptions)
- Cryptographic signatures on audit entries
- Cross-referenced with Tax Authority submission records

---

## 5. Compliance Timeline

### 1 September 2025
- Testing environment live
- Begin certificate acquisition (5-10 day processing)
- Start KPD product mapping
- Register with FiskAplikacija (ePorezna portal)

### 1 September - 31 December 2025 (Transition Period)
- Confirm information system provider
- Grant fiscalization authorization
- Register endpoints with AMS (Address Metadata Service)
- Complete integration testing
- Obtain production FINA certificates

### 1 January 2026 (MANDATORY COMPLIANCE)
- **VAT Entities:** Issue + receive + fiscalize all B2B/B2G/B2C invoices
- **Non-VAT Entities:** Receive + fiscalize incoming invoices only

### Monthly Reporting
- **By 20th of following month:** eIzvještavanje (e-Reporting) - Payment data + rejection reports

### 1 January 2027
- **Non-VAT Entities:** Issuing e-invoices becomes mandatory

---

## 6. Certificate Management

### FINA Application Certificates (X.509)

**Certificate Details:**
- **Type:** Qualified digital certificates for fiscalization
- **Cost:** ~39.82 EUR + VAT per 5-year certificate
- **Demo Certificates:** FREE for testing (1-year validity)
- **Issuance Time:** 5-10 business days
- **Issuer:** FINA (primary) or AKD (alternative)
- **Format:** .p12 soft certificate (PKCS#12)

### Cryptographic Requirements
- **Signature Algorithm:** SHA-256 with RSA
- **Standard:** XMLDSig (enveloped signature)
- **PKI Hierarchy:** Fina Root CA → Fina RDC 2015 CA → Application Certificate
- **ZKI Code:** MD5 hash signed with private key (B2C receipts)

### Lifecycle Management
- **Renewal:** 30 days before expiration
- **Revocation:** Immediate notification to FINA required
- **Key Storage:** Hardware Security Module (HSM) preferred for production
- **Access Control:** Minimum privilege, audit logging

### Acquisition Contacts
- **FINA Support:** 01 4404 707
- **Portal:** cms.fina.hr
- **CMS Activation:** Online via NIAS authentication

---

## Related Documentation

- **Technical Implementation:** @docs/api-contracts/fina-integration.md
- **Test Environment Setup:** @docs/guides/fina-testing.md
- **Certificate Acquisition Guide:** @docs/guides/certificate-setup.md
- **UBL Standards:** @docs/standards/ubl-2.1-specification.pdf
- **Croatian CIUS:** @docs/standards/croatian-cius.pdf

---

**Last Updated:** 2025-11-12
**Document Owner:** Compliance Team
**Review Cadence:** Monthly
