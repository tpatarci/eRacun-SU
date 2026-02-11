/**
 * UBL Invoice Fixtures for E2E Testing
 *
 * Provides valid UBL 2.1 invoice structures compliant with:
 * - EN 16931 (European Invoice Standard)
 * - CIUS-HR (Croatian Invoice Extension)
 * - Croatian Fiskalizacija 2.0 requirements
 */

export interface UBLInvoiceFixture {
  name: string;
  description: string;
  xml: string;
  expected: {
    invoiceNumber: string;
    oib: string;
    amount: number;
    vatAmount: number;
    totalAmount: number;
  };
}

/**
 * Standard B2B Invoice with full CIUS-HR extensions
 */
export const standardB2BInvoice: UBLInvoiceFixture = {
  name: 'Standard B2B Invoice',
  description: 'Complete B2B invoice with all mandatory CIUS-HR fields',
  xml: `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:UBLVersionID>2.1</cbc:UBLVersionID>
  <cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:fin.gov.hr:fiskalizacija:2.0</cbc:CustomizationID>
  <cbc:ID>INV-2024-001</cbc:ID>
  <cbc:IssueDate>2024-02-11</cbc:IssueDate>
  <cbc:InvoiceTypeCode>380</cbc:InvoiceTypeCode>
  <cbc:DocumentCurrencyCode>EUR</cbc:DocumentCurrencyCode>
  <cbc:BuyerReference>PO-2024-001</cbc:BuyerReference>

  <!-- Supplier (Seller) -->
  <cac:AccountingSupplierParty>
    <cac:Party>
      <cac:PartyIdentification>
        <cbc:ID schemeID="HR:OIB">12345678903</cbc:ID>
      </cac:PartyIdentification>
      <cac:PartyName>
        <cbc:Name>OPG Dario d.o.o.</cbc:Name>
      </cac:PartyName>
      <cac:PostalAddress>
        <cbc:StreetName>Ilica 123</cbc:StreetName>
        <cbc:CityName>Zagreb</cbc:CityName>
        <cbc:PostalZone>10000</cbc:PostalZone>
        <cac:Country>
          <cbc:IdentificationCode>HR</cbc:IdentificationCode>
        </cac:Country>
      </cac:PostalAddress>
      <cac:PartyTaxScheme>
        <cbc:CompanyID>12345678903</cbc:CompanyID>
        <cac:TaxScheme>
          <cbc:ID>VAT</cbc:ID>
        </cac:TaxScheme>
      </cac:PartyTaxScheme>
      <cac:PartyLegalEntity>
        <cbc:RegistrationName>OPG Dario d.o.o.</cbc:RegistrationName>
      </cac:PartyLegalEntity>
    </cac:Party>
  </cac:AccountingSupplierParty>

  <!-- Customer (Buyer) -->
  <cac:AccountingCustomerParty>
    <cac:Party>
      <cac:PartyIdentification>
        <cbc:ID schemeID="HR:OIB">98765432106</cbc:ID>
      </cac:PartyIdentification>
      <cac:PartyName>
        <cbc:Name>ABC d.o.o.</cbc:Name>
      </cac:PartyName>
      <cac:PostalAddress>
        <cbc:StreetName>Vukovarska 45</cbc:StreetName>
        <cbc:CityName>Split</cbc:CityName>
        <cbc:PostalZone>21000</cbc:PostalZone>
        <cac:Country>
          <cbc:IdentificationCode>HR</cbc:IdentificationCode>
        </cac:Country>
      </cac:PostalAddress>
      <cac:PartyTaxScheme>
        <cbc:CompanyID>98765432106</cbc:CompanyID>
        <cac:TaxScheme>
          <cbc:ID>VAT</cbc:ID>
        </cac:TaxScheme>
      </cac:PartyTaxScheme>
      <cac:PartyLegalEntity>
        <cbc:RegistrationName>ABC d.o.o.</cbc:RegistrationName>
      </cac:PartyLegalEntity>
    </cac:Party>
  </cac:AccountingCustomerParty>

  <!-- Payment Terms -->
  <cac:PaymentTerms>
    <cbc:Note>Payment due within 15 days</cbc:Note>
  </cac:PaymentTerms>

  <!-- Tax Total -->
  <cac:TaxTotal>
    <cbc:TaxAmount currencyID="EUR">250.00</cbc:TaxAmount>
    <cac:TaxSubtotal>
      <cbc:TaxableAmount currencyID="EUR">1250.00</cbc:TaxableAmount>
      <cbc:TaxAmount currencyID="EUR">250.00</cbc:TaxAmount>
      <cac:TaxCategory>
        <cbc:ID schemeID="UNCL5305">S</cbc:ID>
        <cbc:Percent>20</cbc:Percent>
        <cac:TaxScheme>
          <cbc:ID>VAT</cbc:ID>
        </cac:TaxScheme>
      </cac:TaxCategory>
    </cac:TaxSubtotal>
  </cac:TaxTotal>

  <!-- Legal Monetary Total -->
  <cac:LegalMonetaryTotal>
    <cbc:LineExtensionAmount currencyID="EUR">1250.00</cbc:LineExtensionAmount>
    <cbc:TaxExclusiveAmount currencyID="EUR">1250.00</cbc:TaxExclusiveAmount>
    <cbc:TaxInclusiveAmount currencyID="EUR">1500.00</cbc:TaxInclusiveAmount>
    <cbc:PayableAmount currencyID="EUR">1500.00</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>

  <!-- Invoice Line 1 -->
  <cac:InvoiceLine>
    <cbc:ID>1</cbc:ID>
    <cbc:InvoicedQuantity unitCode="H87">10</cbc:InvoicedQuantity>
    <cbc:LineExtensionAmount currencyID="EUR">500.00</cbc:LineExtensionAmount>
    <cac:Item>
      <cbc:Description>Konzultacijske usluge</cbc:Description>
      <cbc:Name>Konzultacije</cbc:Name>
      <cac:SellersItemIdentification>
        <cbc:ID>SVC-001</cbc:ID>
      </cac:SellersItemIdentification>
      <cac:CommodityClassification>
        <cbc:ItemClassificationCode listID="KLASUS-2025">620000</cbc:ItemClassificationCode>
      </cac:CommodityClassification>
      <cac:ClassifiedTaxCategory>
        <cbc:ID schemeID="UNCL5305">S</cbc:ID>
        <cbc:Percent>20</cbc:Percent>
        <cac:TaxScheme>
          <cbc:ID>VAT</cbc:ID>
        </cac:TaxScheme>
      </cac:ClassifiedTaxCategory>
    </cac:Item>
    <cac:Price>
      <cbc:PriceAmount currencyID="EUR">50.00</cbc:PriceAmount>
    </cac:Price>
  </cac:InvoiceLine>

  <!-- Invoice Line 2 -->
  <cac:InvoiceLine>
    <cbc:ID>2</cbc:ID>
    <cbc:InvoicedQuantity unitCode="H87">15</cbc:InvoicedQuantity>
    <cbc:LineExtensionAmount currencyID="EUR">750.00</cbc:LineExtensionAmount>
    <cac:Item>
      <cbc:Description>Programerske usluge</cbc:Description>
      <cbc:Name>Razvoj aplikacija</cbc:Name>
      <cac:SellersItemIdentification>
        <cbc:ID>SVC-002</cbc:ID>
      </cac:SellersItemIdentification>
      <cac:CommodityClassification>
        <cbc:ItemClassificationCode listID="KLASUS-2025">620100</cbc:ItemClassificationCode>
      </cac:CommodityClassification>
      <cac:ClassifiedTaxCategory>
        <cbc:ID schemeID="UNCL5305">S</cbc:ID>
        <cbc:Percent>20</cbc:Percent>
        <cac:TaxScheme>
          <cbc:ID>VAT</cbc:ID>
        </cac:TaxScheme>
      </cac:ClassifiedTaxCategory>
    </cac:Item>
    <cac:Price>
      <cbc:PriceAmount currencyID="EUR">50.00</cbc:PriceAmount>
    </cac:Price>
  </cac:InvoiceLine>
</Invoice>`,
  expected: {
    invoiceNumber: 'INV-2024-001',
    oib: '12345678903',
    amount: 1250.00,
    vatAmount: 250.00,
    totalAmount: 1500.00,
  },
};

/**
 * B2C Invoice (Retail) - Simplified
 */
export const retailInvoice: UBLInvoiceFixture = {
  name: 'Retail B2C Invoice',
  description: 'Simplified retail invoice for end consumer',
  xml: `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:UBLVersionID>2.1</cbc:UBLVersionID>
  <cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:fin.gov.hr:fiskalizacija:2.0</cbc:CustomizationID>
  <cbc:ID>RAC-2024-001</cbc:ID>
  <cbc:IssueDate>2024-02-11</cbc:IssueDate>
  <cbc:InvoiceTypeCode>380</cbc:InvoiceTypeCode>
  <cbc:DocumentCurrencyCode>EUR</cbc:DocumentCurrencyCode>
  <cbc:BuyerReference>N/A</cbc:BuyerReference>

  <cac:AccountingSupplierParty>
    <cac:Party>
      <cac:PartyIdentification>
        <cbc:ID schemeID="HR:OIB">12345678903</cbc:ID>
      </cac:PartyIdentification>
      <cac:PartyName>
        <cbc:Name>Trgovina "Ivan" d.o.o.</cbc:Name>
      </cac:PartyName>
      <cac:PostalAddress>
        <cbc:StreetName>Glavna 1</cbc:StreetName>
        <cbc:CityName>Zagreb</cbc:CityName>
        <cbc:PostalZone>10000</cbc:PostalZone>
        <cac:Country>
          <cbc:IdentificationCode>HR</cbc:IdentificationCode>
        </cac:Country>
      </cac:PostalAddress>
      <cac:PartyTaxScheme>
        <cbc:CompanyID>12345678903</cbc:CompanyID>
      </cac:PartyTaxScheme>
    </cac:Party>
  </cac:AccountingSupplierParty>

  <cac:AccountingCustomerParty>
    <cac:Party>
      <cac:PartyIdentification>
        <cbc:ID schemeID="HR:OIB">99999999999</cbc:ID>
      </cac:PartyIdentification>
      <cac:PartyName>
        <cbc:Name>Ivan Horvat</cbc:Name>
      </cac:PartyName>
    </cac:Party>
  </cac:AccountingCustomerParty>

  <cac:TaxTotal>
    <cbc:TaxAmount currencyID="EUR">52.00</cbc:TaxAmount>
  </cac:TaxTotal>

  <cac:LegalMonetaryTotal>
    <cbc:LineExtensionAmount currencyID="EUR">260.00</cbc:LineExtensionAmount>
    <cbc:TaxInclusiveAmount currencyID="EUR">312.00</cbc:TaxInclusiveAmount>
    <cbc:PayableAmount currencyID="EUR">312.00</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>

  <cac:InvoiceLine>
    <cbc:ID>1</cbc:ID>
    <cbc:InvoicedQuantity unitCode="H87">2</cbc:InvoicedQuantity>
    <cbc:LineExtensionAmount currencyID="EUR">260.00</cbc:LineExtensionAmount>
    <cac:Item>
      <cbc:Description>Laptop računalo</cbc:Description>
      <cbc:Name>Laptop</cbc:Name>
      <cac:CommodityClassification>
        <cbc:ItemClassificationCode listID="KLASUS-2025">470000</cbc:ItemClassificationCode>
      </cac:CommodityClassification>
      <cac:ClassifiedTaxCategory>
        <cbc:ID schemeID="UNCL5305">S</cbc:ID>
        <cbc:Percent>20</cbc:Percent>
      </cac:ClassifiedTaxCategory>
    </cac:Item>
    <cac:Price>
      <cbc:PriceAmount currencyID="EUR">130.00</cbc:PriceAmount>
    </cac:Price>
  </cac:InvoiceLine>
</Invoice>`,
  expected: {
    invoiceNumber: 'RAC-2024-001',
    oib: '12345678903',
    amount: 260.00,
    vatAmount: 52.00,
    totalAmount: 312.00,
  },
};

/**
 * Proforma Invoice
 */
export const proformaInvoice: UBLInvoiceFixture = {
  name: 'Proforma Invoice',
  description: 'Pre-payment invoice with 0% VAT',
  xml: `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:UBLVersionID>2.1</cbc:UBLVersionID>
  <cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:fin.gov.hr:fiskalizacija:2.0</cbc:CustomizationID>
  <cbc:ID>PROF-2024-001</cbc:ID>
  <cbc:IssueDate>2024-02-11</cbc:IssueDate>
  <cbc:InvoiceTypeCode>388</cbc:InvoiceTypeCode>
  <cbc:DocumentCurrencyCode>EUR</cbc:DocumentCurrencyCode>

  <cac:AccountingSupplierParty>
    <cac:Party>
      <cac:PartyIdentification>
        <cbc:ID schemeID="HR:OIB">12345678903</cbc:ID>
      </cac:PartyIdentification>
      <cac:PartyName>
        <cbc:Name>IT Usluge d.o.o.</cbc:Name>
      </cac:PartyName>
    </cac:Party>
  </cac:AccountingSupplierParty>

  <cac:AccountingCustomerParty>
    <cac:Party>
      <cac:PartyIdentification>
        <cbc:ID schemeID="HR:OIB">98765432106</cbc:ID>
      </cac:PartyIdentification>
      <cac:PartyName>
        <cbc:Name>Kupac d.o.o.</cbc:Name>
      </cac:PartyName>
    </cac:Party>
  </cac:AccountingCustomerParty>

  <cac:TaxTotal>
    <cbc:TaxAmount currencyID="EUR">0.00</cbc:TaxAmount>
  </cac:TaxTotal>

  <cac:LegalMonetaryTotal>
    <cbc:LineExtensionAmount currencyID="EUR">1000.00</cbc:LineExtensionAmount>
    <cbc:TaxInclusiveAmount currencyID="EUR">1000.00</cbc:TaxInclusiveAmount>
    <cbc:PayableAmount currencyID="EUR">1000.00</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>

  <cac:InvoiceLine>
    <cbc:ID>1</cbc:ID>
    <cbc:InvoicedQuantity unitCode="H87">1</cbc:InvoicedQuantity>
    <cbc:LineExtensionAmount currencyID="EUR">1000.00</cbc:LineExtensionAmount>
    <cac:Item>
      <cbc:Description>Avansna uplata za usluge</cbc:Description>
      <cbc:Name>Avans</cbc:Name>
      <cac:ClassifiedTaxCategory>
        <cbc:ID schemeID="UNCL5305">Z</cbc:ID>
        <cbc:Percent>0</cbc:Percent>
      </cac:ClassifiedTaxCategory>
    </cac:Item>
    <cac:Price>
      <cbc:PriceAmount currencyID="EUR">1000.00</cbc:PriceAmount>
    </cac:Price>
  </cac:InvoiceLine>
</Invoice>`,
  expected: {
    invoiceNumber: 'PROF-2024-001',
    oib: '12345678903',
    amount: 1000.00,
    vatAmount: 0.00,
    totalAmount: 1000.00,
  },
};

/**
 * Export all fixtures
 */
export const ublInvoiceFixtures: UBLInvoiceFixture[] = [
  standardB2BInvoice,
  retailInvoice,
  proformaInvoice,
];

/**
 * Helper function to get fixture by name
 */
export function getFixtureByName(name: string): UBLInvoiceFixture | undefined {
  return ublInvoiceFixtures.find(f => f.name === name);
}

/**
 * Helper function to get fixture by invoice number
 */
export function getFixtureByInvoiceNumber(invoiceNumber: string): UBLInvoiceFixture | undefined {
  return ublInvoiceFixtures.find(f => f.expected.invoiceNumber === invoiceNumber);
}
