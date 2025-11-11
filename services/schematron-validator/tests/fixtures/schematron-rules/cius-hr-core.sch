<?xml version="1.0" encoding="UTF-8"?>
<!--
  Minimal Croatian CIUS Schematron Rules for Testing

  NOTE: This is a SIMPLIFIED version for development/testing.
  Production systems MUST use official Croatian CIUS rules.

  This file contains a subset of rules to test Schematron validation:
  - BR-S-01: VAT rate validation
  - BR-HR-01: OIB validation
  - BR-E-01: Invoice total calculation
  - BR-CO-01: Required fields validation
-->
<schema xmlns="http://purl.oclc.org/dsdl/schematron"
        xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
        xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
        queryBinding="xslt2">

  <title>Croatian CIUS Core Business Rules (Test Subset)</title>

  <ns prefix="cbc" uri="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"/>
  <ns prefix="cac" uri="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"/>
  <ns prefix="ubl" uri="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"/>

  <!-- ================================================================== -->
  <!-- PATTERN 1: VAT Rules                                               -->
  <!-- ================================================================== -->

  <pattern id="VAT-rules">
    <title>VAT rate and category validation</title>

    <!-- BR-S-01: Standard rate VAT must be 25% -->
    <rule context="//cac:TaxCategory[cbc:ID='S']">
      <assert id="BR-S-01"
              test="cbc:Percent = 25"
              flag="error">
        VAT rate MUST be 25% when category code is 'S' (standard rate).
      </assert>
    </rule>

    <!-- BR-S-02: Reduced rate VAT must be 13% or 5% -->
    <rule context="//cac:TaxCategory[cbc:ID='R']">
      <assert id="BR-S-02"
              test="cbc:Percent = 13 or cbc:Percent = 5"
              flag="error">
        VAT rate MUST be 13% or 5% when category code is 'R' (reduced rate).
      </assert>
    </rule>

    <!-- BR-S-03: Zero rate VAT must be 0% -->
    <rule context="//cac:TaxCategory[cbc:ID='Z']">
      <assert id="BR-S-03"
              test="cbc:Percent = 0"
              flag="error">
        VAT rate MUST be 0% when category code is 'Z' (zero rate).
      </assert>
    </rule>
  </pattern>

  <!-- ================================================================== -->
  <!-- PATTERN 2: Croatian-specific Rules                                 -->
  <!-- ================================================================== -->

  <pattern id="Croatian-rules">
    <title>Croatian business rules (OIB, currency)</title>

    <!-- BR-HR-01: Supplier OIB must be 11 digits -->
    <rule context="//cac:AccountingSupplierParty/cac:Party">
      <assert id="BR-HR-01"
              test="string-length(cac:PartyTaxScheme/cbc:CompanyID) = 11"
              flag="error">
        Supplier OIB (CompanyID) MUST be exactly 11 digits.
      </assert>
    </rule>

    <!-- BR-HR-02: Currency must be EUR or HRK -->
    <rule context="//ubl:Invoice">
      <assert id="BR-HR-02"
              test="cbc:DocumentCurrencyCode = 'EUR' or cbc:DocumentCurrencyCode = 'HRK'"
              flag="error">
        Invoice currency MUST be EUR or HRK.
      </assert>
    </rule>
  </pattern>

  <!-- ================================================================== -->
  <!-- PATTERN 3: Calculation Rules                                       -->
  <!-- ================================================================== -->

  <pattern id="Calculation-rules">
    <title>Invoice calculation and totals</title>

    <!-- BR-E-01: Invoice total must equal sum of line totals plus VAT -->
    <!-- Simplified version - production rules are more complex -->
    <rule context="//ubl:Invoice">
      <assert id="BR-E-01"
              test="cac:LegalMonetaryTotal/cbc:PayableAmount"
              flag="error">
        Invoice MUST contain payable amount (LegalMonetaryTotal/PayableAmount).
      </assert>
    </rule>
  </pattern>

  <!-- ================================================================== -->
  <!-- PATTERN 4: Required Fields (Cardinality)                           -->
  <!-- ================================================================== -->

  <pattern id="Cardinality-rules">
    <title>Required field validation</title>

    <!-- BR-CO-01: Invoice ID is mandatory -->
    <rule context="//ubl:Invoice">
      <assert id="BR-CO-01"
              test="cbc:ID"
              flag="error">
        Invoice ID (cbc:ID) is MANDATORY.
      </assert>
    </rule>

    <!-- BR-CO-02: Issue date is mandatory -->
    <rule context="//ubl:Invoice">
      <assert id="BR-CO-02"
              test="cbc:IssueDate"
              flag="error">
        Invoice issue date (cbc:IssueDate) is MANDATORY.
      </assert>
    </rule>

    <!-- BR-CO-03: Supplier party is mandatory -->
    <rule context="//ubl:Invoice">
      <assert id="BR-CO-03"
              test="cac:AccountingSupplierParty"
              flag="error">
        Accounting supplier party is MANDATORY.
      </assert>
    </rule>
  </pattern>

  <!-- ================================================================== -->
  <!-- PATTERN 5: Warnings (Non-critical)                                 -->
  <!-- ================================================================== -->

  <pattern id="Warning-rules">
    <title>Warning rules (best practices)</title>

    <!-- BR-W-01: Payment due date should be within 90 days -->
    <rule context="//cbc:DueDate">
      <report id="BR-W-01"
              test="."
              flag="warning">
        Consider setting payment due date within 90 days of issue date (best practice).
      </report>
    </rule>
  </pattern>

</schema>
