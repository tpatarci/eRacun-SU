# TASK 8: Data Archiving and Retention Compliance

## Task Priority
**CRITICAL** - Legal requirement for 11-year retention with severe penalties

## Objective
Verify that the data archiving system meets the mandatory 11-year retention requirement for e-invoices, maintains data integrity with WORM storage, and preserves digital signatures and timestamps as legally required.

## Scope
Complete audit of:
- Archive storage configuration (WORM compliance)
- 11-year retention policy implementation
- Digital signature preservation
- Data integrity verification
- Recovery procedures
- Storage capacity planning

## Detailed Approach

### 1. Retention Policy Verification (Day 1)
**Current configuration audit:**
```bash
# Check archive policy configuration
cat /etc/eracun/archive/retention-policy.yaml

# Verify policy enforcement
psql -U eracun -c "
  SELECT table_name, retention_period
  FROM archive_policies
  WHERE retention_period < INTERVAL '11 years';
"
```

**Retention requirements checklist:**
- [ ] 11-year retention configured (NOT 7 years)
- [ ] Policy covers all invoice types
- [ ] Includes all supporting documents
- [ ] Original XML preserved
- [ ] Digital signatures intact
- [ ] Timestamps preserved

### 2. WORM Storage Validation (Day 1-2)
**Write-Once-Read-Many verification:**
```bash
# Test immutability
# Attempt to modify archived invoice (should fail)
echo "test" >> /archive/invoices/2025/01/INV-12345.xml
# Expected: Permission denied

# Verify archive filesystem
mount | grep /archive
# Should show: ro,noatime or WORM flags
```

**WORM compliance checklist:**
- [ ] Storage configured as immutable
- [ ] No delete operations possible
- [ ] No modify operations possible
- [ ] Append-only for new data
- [ ] Audit log immutable
- [ ] Compliance mode enabled

### 3. Digital Signature Preservation (Day 2)
**Signature validation over time:**
```bash
# Validate signatures on archived documents
for year in 2024 2025; do
  find /archive/invoices/${year} -name "*.xml" -print0 | \
    xargs -0 -I {} xmlsec1 verify --enabled-reference-uris same-doc {}
done

# Check certificate chain preservation
openssl verify -CAfile /archive/certs/ca-chain.pem \
  /archive/certs/fina-2025.crt
```

**Signature preservation checklist:**
- [ ] XMLDSig signatures intact
- [ ] Certificate chains archived
- [ ] Timestamp tokens preserved
- [ ] CRL/OCSP responses archived
- [ ] Validation possible after 11 years
- [ ] Re-signing strategy for expiry

### 4. Storage Capacity Planning (Day 2-3)
**Current usage and projections:**
```bash
# Analyze current storage
du -sh /archive/*
df -h /archive

# Calculate growth rate
psql -U eracun -c "
  SELECT
    date_trunc('month', created_at) as month,
    COUNT(*) as invoice_count,
    AVG(file_size) as avg_size,
    SUM(file_size) as total_size
  FROM archived_invoices
  GROUP BY month
  ORDER BY month;
"
```

**Capacity planning checklist:**
- [ ] Current usage documented
- [ ] Growth rate calculated
- [ ] 11-year projection made
- [ ] Storage costs budgeted
- [ ] Archive tiers configured
- [ ] Compression evaluated

### 5. Data Integrity Verification (Day 3)
**Checksum validation:**
```bash
# Verify checksums for archived files
while IFS= read -r file; do
  stored_hash=$(psql -U eracun -t -c "
    SELECT checksum FROM archived_invoices
    WHERE file_path = '${file}';
  ")

  calculated_hash=$(sha256sum "${file}" | cut -d' ' -f1)

  if [ "${stored_hash}" != "${calculated_hash}" ]; then
    echo "INTEGRITY FAILURE: ${file}"
  fi
done < /tmp/archive-files.list
```

**Integrity checklist:**
- [ ] Checksums calculated on archive
- [ ] Regular integrity checks scheduled
- [ ] Corruption detection automated
- [ ] Backup verification process
- [ ] Recovery procedures tested
- [ ] Audit trail protected

### 6. Recovery Testing (Day 3-4)
**Archive retrieval simulation:**
```bash
# Test retrieval of old invoice
INVOICE_ID="INV-2024-00001"

# Retrieve from archive
time aws s3 cp \
  s3://eracun-archive/2024/01/${INVOICE_ID}.xml \
  /tmp/retrieved.xml

# Verify integrity
xmlsec1 verify /tmp/retrieved.xml

# Check retrieval audit log
tail -f /var/log/eracun/archive-access.log
```

**Recovery capability checklist:**
- [ ] Retrieval <1 hour for any document
- [ ] Bulk export capability
- [ ] Search functionality working
- [ ] Metadata indexes maintained
- [ ] Audit trail for all access
- [ ] Legal hold procedures

### 7. Compliance Documentation (Day 4)
**Archive compliance report:**
- [ ] Retention policy documented
- [ ] WORM configuration proven
- [ ] Integrity verification logs
- [ ] Recovery test results
- [ ] Capacity planning report
- [ ] Cost projection model

## Required Tools
- Storage analysis tools (du, df)
- XML signature verification (xmlsec1)
- Database query tools
- Checksum validators
- Archive management system
- Compliance reporting tools

## Pass/Fail Criteria

### MUST PASS (Legal requirements)
- ✅ 11-year retention guaranteed
- ✅ WORM storage operational
- ✅ Digital signatures preserved
- ✅ Retrieval within 1 hour
- ✅ Data integrity maintained

### RED FLAGS (Compliance failures)
- ❌ Retention <11 years
- ❌ Documents modifiable
- ❌ Signatures invalid
- ❌ No backup strategy
- ❌ Capacity insufficient

## Deliverables
1. **Archive Compliance Certificate** - 11-year retention proof
2. **Capacity Planning Report** - Storage needs for 11 years
3. **Integrity Verification Log** - All documents validated
4. **Recovery Test Results** - Retrieval performance
5. **Cost Projection** - 11-year storage costs

## Time Estimate
- **Duration:** 4 days
- **Effort:** 1 senior engineer + compliance expert
- **Prerequisites:** Archive system operational

## Risk Factors
- **Critical Risk:** Non-compliant retention period
- **Critical Risk:** Lost digital signatures
- **High Risk:** Storage capacity exhaustion
- **Medium Risk:** Slow retrieval times
- **Low Risk:** Metadata inconsistencies

## Escalation Path
For archive compliance issues:
1. Legal team immediate notification
2. Storage vendor engagement
3. Emergency capacity procurement
4. Compliance consultant if needed
5. Regulatory notification if required

## Legal Requirements Summary
**Croatian Fiscalization Law (NN 89/25):**
- **Retention:** 11 years mandatory
- **Format:** Original UBL 2.1 XML
- **Signatures:** Must remain verifiable
- **Immutability:** No modifications allowed
- **Accessibility:** Available for audit

**Penalties for Non-Compliance:**
- Fines up to €66,360
- Loss of VAT deduction rights
- Criminal liability for destruction
- Business operation suspension

## Storage Architecture
```
┌─────────────────┐
│   Hot Storage   │ (0-1 year)
│   NVMe SSD      │ Instant access
└────────┬────────┘
         │
┌────────▼────────┐
│  Warm Storage   │ (1-3 years)
│   HDD RAID      │ <1 hour access
└────────┬────────┘
         │
┌────────▼────────┐
│  Cold Storage   │ (3-11 years)
│  Object Store   │ <24 hour access
└─────────────────┘
```

## Related Documentation
- @docs/COMPLIANCE_REQUIREMENTS.md (Section 4: Audit & Archiving)
- @docs/guides/archive-setup.md
- @docs/operations/disaster-recovery.md
- Croatian Fiscalization Law (NN 89/25)
- GDPR Article 5 (Storage Limitation)

## Archive Checklist
- [ ] WORM storage configured
- [ ] 11-year retention active
- [ ] Geographic redundancy (2+ regions)
- [ ] Encryption at rest (AES-256)
- [ ] Access logging enabled
- [ ] Legal hold capability
- [ ] Automated integrity checks
- [ ] Disaster recovery tested
- [ ] Compliance audit passed
- [ ] Cost optimization applied

## Notes
The 11-year retention requirement is non-negotiable and critical for legal compliance. Archive system failures could result in severe penalties and business disruption. Regular testing and verification are essential.