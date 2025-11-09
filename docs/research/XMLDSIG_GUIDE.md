# XMLDSig Implementation Guide - Croatian E-Invoice Digital Signatures

**Standard:** XML Signature (XMLDSig) - W3C Recommendation
**Version:** XMLDSig 1.0 (Second Edition)
**Published:** June 2008
**Croatian Requirement:** Mandatory for B2B/B2G invoices
**Certificate Authority:** FINA (primary) or AKD (alternative)
**Effective Date:** 1 January 2026

---

## Official Sources

**W3C Specification:** https://www.w3.org/TR/xmldsig-core/
**FINA Certificates:** https://cms.fina.hr/ (CMS portal)
**Croatian eIDAS:** https://www.nias.hr/ (NIAS authentication portal)

**Legal Framework:** See `/CROATIAN_COMPLIANCE.md` section 4

---

## What is XMLDSig?

**XMLDSig** = XML Digital Signature

Provides:
- **Integrity:** Detect any modification to signed data
- **Authentication:** Verify who signed the document
- **Non-repudiation:** Signer cannot deny signing

**In Croatian e-invoicing:**
- **B2B/B2G invoices:** Qualified electronic signature MANDATORY
- **B2C fiscalized receipts:** Simplified signature (ZKI code) sufficient
- **Qualified timestamp:** Required alongside signature (eIDAS-compliant)

---

## Directory Contents

```
docs/research/
├── XMLDSIG_GUIDE.md           # This file
└── examples/
    ├── signed_invoice.xml     # Complete signed UBL invoice
    ├── zki_calculation.md     # ZKI code algorithm (B2C)
    └── timestamp_request.xml  # eIDAS timestamp request
```

---

## Croatian E-Invoice Signature Requirements

### B2B/B2G Invoices (Four-Corner Model)

**Signature Type:** Qualified Electronic Signature (QES)
**Standard:** XMLDSig Enveloped Signature
**Certificate:** FINA Application Certificate (X.509)
**Timestamp:** eIDAS-qualified timestamp service
**Canonicalization:** Exclusive XML Canonicalization (c14n)
**Digest Algorithm:** SHA-256
**Signature Algorithm:** RSA-SHA256 (minimum 2048-bit key)

**Structure:**
```xml
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">
  <!-- Invoice content here -->
  <ext:UBLExtensions>
    <ext:UBLExtension>
      <ext:ExtensionContent>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <!-- Signature elements -->
        </ds:Signature>
      </ext:ExtensionContent>
    </ext:UBLExtension>
  </ext:UBLExtensions>
</Invoice>
```

### B2C Fiscalized Receipts

**Signature Type:** ZKI (Zaštitni kod izdavatelja) - Security Code
**Algorithm:** MD5 hash signed with private key
**Certificate:** FINA Demo Certificate (testing) or FINA Application Certificate (production)
**Real-time Validation:** FINA SOAP API verifies ZKI during fiscalization

**ZKI Calculation:**
```
ZKI = MD5(OIB + IssueDateTime + InvoiceNumber + BusinessPremises + CashRegister + TotalAmount + PrivateKey)
```

**Example:**
```
OIB: 12345678901
IssueDateTime: 2026-01-15T10:30:00
InvoiceNumber: 1
BusinessPremises: ZAGREB1
CashRegister: POS1
TotalAmount: 125.00
PrivateKey: [from FINA certificate .p12 file]

ZKI = MD5("123456789012026-01-15T10:30:001ZAGREB1POS1125.00<private_key_bytes>")
    = "a1b2c3d4e5f6789012345678901234ab" (32 hex characters)
```

**See:** ZKI calculation service in `signature-service/CLAUDE.md`

---

## XMLDSig Structure (Enveloped Signature)

### Complete Signature Template

```xml
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <!-- 1. What is being signed -->
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue>BASE64_ENCODED_HASH_OF_INVOICE</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>

  <!-- 2. Cryptographic signature -->
  <ds:SignatureValue>BASE64_ENCODED_RSA_SIGNATURE</ds:SignatureValue>

  <!-- 3. Certificate and public key -->
  <ds:KeyInfo>
    <ds:X509Data>
      <ds:X509Certificate>BASE64_ENCODED_FINA_CERTIFICATE</ds:X509Certificate>
      <ds:X509IssuerSerial>
        <ds:X509IssuerName>CN=Fina RDC 2015 CA,O=Financijska agencija,C=HR</ds:X509IssuerName>
        <ds:X509SerialNumber>123456789</ds:X509SerialNumber>
      </ds:X509IssuerSerial>
    </ds:X509Data>
  </ds:KeyInfo>

  <!-- 4. Qualified timestamp (optional but recommended) -->
  <ds:Object>
    <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
      <xades:SignedProperties>
        <xades:SignedSignatureProperties>
          <xades:SigningTime>2026-01-15T10:30:00Z</xades:SigningTime>
          <xades:SigningCertificate>
            <xades:Cert>
              <xades:CertDigest>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>CERT_HASH</ds:DigestValue>
              </xades:CertDigest>
            </xades:Cert>
          </xades:SigningCertificate>
        </xades:SignedSignatureProperties>
      </xades:SignedProperties>
    </xades:QualifyingProperties>
  </ds:Object>
</ds:Signature>
```

---

## Signing Process (Step-by-Step)

### 1. Prepare Invoice XML

Generate complete UBL 2.1 invoice with all required fields:
- Seller/Buyer OIBs
- KPD codes on all line items
- VAT calculations
- Monetary totals

**Important:** Do NOT include `<ds:Signature>` element yet.

### 2. Canonicalize Document

Apply **Exclusive XML Canonicalization (c14n)** to ensure consistent formatting.

**Why?** XML allows whitespace/namespace variations that don't change meaning but change byte representation.

**Algorithm:** http://www.w3.org/2001/10/xml-exc-c14n#

**Libraries:**
- **Node.js:** `xmldsigjs`, `xml-crypto`
- **Python:** `signxml`, `lxml`
- **Java:** Apache Santuario (`org.apache.xml.security`)
- **Go:** `github.com/russellhaering/goxmldsig`

### 3. Calculate Digest (Hash)

Compute SHA-256 hash of canonicalized invoice:

```
digest = SHA256(canonicalized_xml)
digest_base64 = Base64(digest)
```

**Insert into `<ds:DigestValue>`**

### 4. Create SignedInfo

Build `<ds:SignedInfo>` element with:
- Canonicalization method
- Signature algorithm (RSA-SHA256)
- Reference to document (URI="")
- Digest value from step 3

### 5. Sign SignedInfo

Canonicalize `<ds:SignedInfo>`, then sign with **private key** from FINA certificate:

```
canonicalized_signed_info = C14N(SignedInfo)
signature_bytes = RSA_Sign(canonicalized_signed_info, private_key, SHA256)
signature_base64 = Base64(signature_bytes)
```

**Insert into `<ds:SignatureValue>`**

### 6. Embed Certificate

Extract X.509 certificate from FINA .p12 file:

```
certificate_der = ExtractCertFromP12(fina_cert.p12, password)
certificate_base64 = Base64(certificate_der)
```

**Insert into `<ds:X509Certificate>`**

### 7. Add Qualified Timestamp (Optional but Recommended)

Request timestamp from eIDAS-qualified Time Stamping Authority (TSA):

```
POST https://timestamp-authority.example.hr/tsa
Content-Type: application/timestamp-query

<timestamp_request>
  <hash_algorithm>SHA256</hash_algorithm>
  <message_digest>BASE64_SIGNATURE_HASH</message_digest>
</timestamp_request>
```

**Embed TSA response in `<ds:Object>` or as separate UBL extension.**

### 8. Embed Signature in Invoice

Insert complete `<ds:Signature>` into UBL `<ext:UBLExtensions>`:

```xml
<Invoice>
  <ext:UBLExtensions>
    <ext:UBLExtension>
      <ext:ExtensionContent>
        <ds:Signature>
          <!-- Complete signature from steps 1-7 -->
        </ds:Signature>
      </ext:ExtensionContent>
    </ext:UBLExtension>
  </ext:UBLExtensions>
  <!-- Rest of invoice -->
</Invoice>
```

---

## Verification Process

### Recipient Validation Steps

1. **Extract Signature:** Parse `<ds:Signature>` from UBL extensions
2. **Extract Certificate:** Parse `<ds:X509Certificate>`
3. **Verify Certificate Chain:**
   - Check issuer: FINA RDC 2015 CA
   - Verify not expired
   - Verify not revoked (OCSP or CRL check)
   - Confirm trusted root CA
4. **Extract Public Key:** From certificate
5. **Verify DigestValue:**
   - Canonicalize invoice (excluding signature)
   - Calculate SHA-256 hash
   - Compare with `<ds:DigestValue>` (must match)
6. **Verify SignatureValue:**
   - Canonicalize `<ds:SignedInfo>`
   - Decrypt `<ds:SignatureValue>` with public key
   - Compare decrypted hash with calculated hash (must match)
7. **Verify Timestamp (if present):**
   - Extract timestamp token
   - Verify TSA signature
   - Confirm timestamp within acceptable range

**Result:**
- ✅ **Valid:** All checks pass → Invoice integrity confirmed
- ❌ **Invalid:** Any check fails → Invoice rejected

---

## FINA Certificate Acquisition

### Certificate Types

| Type | Use Case | Validity | Cost |
|------|----------|----------|------|
| **Demo Certificate** | Testing (cistest environment) | 1 year | FREE |
| **Application Certificate** | Production fiscalization | 5 years | ~39.82 EUR + VAT |
| **Qualified Certificate** | Advanced signatures (eIDAS) | Variable | Contact FINA |

### Acquisition Process

**Step 1: Prepare Documentation**
- Company registration (Izvadak iz sudskog registra)
- OIB confirmation
- Authorized signatory identification
- Power of attorney (if applicable)

**Step 2: Submit Request**
- Portal: https://cms.fina.hr/
- Authentication: NIAS (Croatian eID)
- Form: "Zahtjev za izdavanje digitalnog certifikata"

**Step 3: Payment**
- Invoice sent via email
- Payment: Bank transfer or online
- Processing begins after payment confirmation

**Step 4: Certificate Issuance**
- Processing time: **5-10 business days**
- Delivery: Download from CMS portal
- Format: .p12 file (PKCS#12)
- Password: Sent via SMS to registered mobile

**Step 5: Installation**
- Import .p12 into application keystore
- Extract private key (store securely)
- Extract certificate chain
- Configure signature service

**Support Contact:**
- FINA CMS Support: 01 4404 707
- Email: cms@fina.hr

---

## Security Best Practices

### Private Key Protection

**CRITICAL:** Private key compromise = forged invoices = legal liability

**Production Requirements:**
- ✅ Store in **Hardware Security Module (HSM)** (preferred)
- ✅ Or use **encrypted keystore** with strong password
- ✅ Restrict access: Only signature service can read
- ✅ Audit all key usage
- ✅ Rotate certificates before expiry
- ❌ NEVER commit private keys to Git
- ❌ NEVER log private key contents
- ❌ NEVER transmit private keys over network

**Key Storage Options:**
1. **HSM (Best):** Dedicated hardware (e.g., Thales, Gemalto)
2. **Cloud KMS:** AWS KMS, Azure Key Vault, Google Cloud KMS
3. **Encrypted File (Acceptable for testing):** .p12 with strong password

### Certificate Validation

**Always verify:**
- Certificate not expired
- Certificate not revoked (OCSP/CRL)
- Issuer is trusted FINA CA
- Certificate purpose includes "Digital Signature"

**OCSP Endpoint (FINA):**
```
http://ocsp.fina.hr/
```

**CRL Distribution (FINA):**
```
http://www.fina.hr/crl/finardc2015.crl
```

### Timestamp Authority

**Croatian eIDAS Qualified TSA:**
- To be announced (check Porezna uprava documentation)
- Alternative: EU-recognized TSAs (eIDAS trust list)

**Timestamp Requirements:**
- RFC 3161 compliant
- SHA-256 digest algorithm
- Qualified status (eIDAS Regulation 910/2014)

---

## Implementation Libraries

### Node.js/TypeScript

**Library:** `xmldsigjs` (modern, Promise-based)

```typescript
import * as xmldsig from 'xmldsigjs';
import * as crypto from 'crypto';
import * as fs from 'fs';

async function signInvoice(invoiceXml: string, certPath: string, certPassword: string) {
  // Load certificate
  const p12Buffer = fs.readFileSync(certPath);
  const p12 = crypto.createPrivateKey({
    key: p12Buffer,
    format: 'p12',
    passphrase: certPassword,
  });

  // Parse XML
  const xmlDoc = xmldsig.Parse(invoiceXml);

  // Create signature
  const signature = new xmldsig.SignedXml();

  // Configure algorithms
  signature.SigningKey = p12;
  signature.SignatureMethod = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  signature.CanonicalizationMethod = 'http://www.w3.org/2001/10/xml-exc-c14n#';

  // Add reference to document
  const reference = new xmldsig.Reference();
  reference.Uri = '';
  reference.DigestMethod = 'http://www.w3.org/2001/04/xmlenc#sha256';
  reference.AddTransform('http://www.w3.org/2000/09/xmldsig#enveloped-signature');
  reference.AddTransform('http://www.w3.org/2001/10/xml-exc-c14n#');
  signature.AddReference(reference);

  // Compute signature
  await signature.ComputeSignature(xmlDoc);

  // Embed in UBL extensions
  const signedXml = signature.GetXml();
  // ... insert into <ext:UBLExtensions>

  return signedXml;
}
```

### Python

**Library:** `signxml`

```python
from signxml import XMLSigner, XMLVerifier
from lxml import etree
import OpenSSL.crypto

def sign_invoice(invoice_xml: str, cert_path: str, cert_password: str) -> str:
    # Load certificate
    with open(cert_path, 'rb') as f:
        p12 = OpenSSL.crypto.load_pkcs12(f.read(), cert_password.encode())

    private_key = OpenSSL.crypto.dump_privatekey(
        OpenSSL.crypto.FILETYPE_PEM,
        p12.get_privatekey()
    )
    certificate = OpenSSL.crypto.dump_certificate(
        OpenSSL.crypto.FILETYPE_PEM,
        p12.get_certificate()
    )

    # Parse XML
    root = etree.fromstring(invoice_xml.encode())

    # Sign
    signer = XMLSigner(
        method='enveloped',
        digest_algorithm='sha256',
        signature_algorithm='rsa-sha256',
        c14n_algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'
    )

    signed_root = signer.sign(root, key=private_key, cert=certificate)

    return etree.tostring(signed_root, encoding='unicode')
```

### Java

**Library:** Apache Santuario XML Security

```java
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;

public class InvoiceSigner {
    public Document signInvoice(Document invoice, KeyStore keyStore, String keyAlias, char[] password)
            throws Exception {
        // Initialize Apache Santuario
        org.apache.xml.security.Init.init();

        // Get private key and certificate
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, password);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(keyAlias);

        // Create signature
        XMLSignature signature = new XMLSignature(
            invoice,
            "",
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256,
            Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS
        );

        // Add transforms
        Transforms transforms = new Transforms(invoice);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

        // Add reference
        signature.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA256);

        // Add certificate
        signature.addKeyInfo(cert);

        // Sign
        signature.sign(privateKey);

        // Embed in UBL extensions
        Element signatureElement = signature.getElement();
        // ... insert into <ext:UBLExtensions>

        return invoice;
    }
}
```

---

## Testing and Validation

### Test Signature in Demo Environment

**FINA Test Endpoint:**
```
https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest
```

**Demo Certificate:**
- Request from FINA (free, 1-year validity)
- Use ONLY in test environment
- DO NOT use in production

### Validation Tools

**Online Validators:**
- FINA Signature Validator (if available)
- EU eIDAS Signature Validation (DSS - Digital Signature Service)

**Command-Line:**
```bash
# Verify signature with xmlsec1 (Linux)
xmlsec1 --verify --trusted-pem fina-ca.pem signed_invoice.xml

# Extract certificate info
openssl pkcs12 -in fina_cert.p12 -info -noout
```

---

## Performance Considerations

**Signing Performance:**
- Typical time: 50-200ms per signature (software key)
- HSM signing: 100-500ms (network latency)

**Optimization:**
- Cache parsed certificate chains
- Reuse XML parser instances
- Pre-load canonicalization libraries
- Batch signature operations if possible

**Scalability:**
- For high throughput: Use HSM with connection pooling
- Consider async signing (queue-based)

---

## Troubleshooting

### Common Errors

**"Signature verification failed"**
- Cause: Invoice modified after signing
- Solution: Re-sign document, do not modify signed XML

**"Certificate chain invalid"**
- Cause: Missing intermediate CA certificate
- Solution: Include full certificate chain in `<ds:X509Data>`

**"Certificate expired"**
- Cause: FINA certificate past validity period
- Solution: Renew certificate before expiration

**"Invalid digest value"**
- Cause: Incorrect canonicalization or namespace handling
- Solution: Use Exclusive C14N, preserve all namespaces

---

## Related Documentation

- **FINA Certificate Guide:** `/CROATIAN_COMPLIANCE.md` section 4
- **Signature Service Spec:** `/services/transformation/signature-service/CLAUDE.md`
- **UBL Extensions:** `/docs/standards/UBL-2.1/README.md`
- **CIUS-HR Requirements:** `/docs/standards/CIUS-HR/README.md` (HR-BR-08)

---

## External Resources

- **W3C XMLDSig Spec:** https://www.w3.org/TR/xmldsig-core/
- **FINA CMS Portal:** https://cms.fina.hr/
- **eIDAS Regulation:** https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32014R0910
- **Apache Santuario:** https://santuario.apache.org/

---

**Maintainer:** Security Team + Technical Lead
**Last Updated:** 2025-11-09
**Next Review:** Quarterly (monitor FINA certificate policy changes)
