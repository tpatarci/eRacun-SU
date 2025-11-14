/**
 * XML Test Data Generator
 * Generates UBL 2.1 compliant XML documents
 */

import { UBLInvoice } from '@eracun/contracts';

export class XMLGenerator {
  /**
   * Generate UBL 2.1 XML from invoice object
   */
  static generateUBL21XML(invoice: UBLInvoice): string {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:fina.hr:cius-hr:2.0</cbc:CustomizationID>
  <cbc:ProfileID>urn:fina.hr:profile:01</cbc:ProfileID>
  <cbc:ID>${this.escapeXML(invoice.invoiceNumber)}</cbc:ID>
  <cbc:IssueDate>${invoice.issueDate}</cbc:IssueDate>
  <cbc:DueDate>${invoice.dueDate || invoice.issueDate}</cbc:DueDate>
  <cbc:InvoiceTypeCode>380</cbc:InvoiceTypeCode>
  <cbc:DocumentCurrencyCode>${invoice.amounts.currency}</cbc:DocumentCurrencyCode>

  <!-- Supplier Party -->
  <cac:AccountingSupplierParty>
    <cac:Party>
      <cac:PartyName>
        <cbc:Name>${this.escapeXML(invoice.supplier.name)}</cbc:Name>
      </cac:PartyName>
      <cac:PostalAddress>
        <cbc:StreetName>${this.escapeXML(invoice.supplier.address.street)}</cbc:StreetName>
        <cbc:CityName>${this.escapeXML(invoice.supplier.address.city)}</cbc:CityName>
        <cbc:PostalZone>${invoice.supplier.address.postalCode}</cbc:PostalZone>
        <cac:Country>
          <cbc:IdentificationCode>${invoice.supplier.address.country}</cbc:IdentificationCode>
        </cac:Country>
      </cac:PostalAddress>
      <cac:PartyTaxScheme>
        <cbc:CompanyID>${invoice.supplier.vatNumber}</cbc:CompanyID>
        <cac:TaxScheme>
          <cbc:ID>VAT</cbc:ID>
        </cac:TaxScheme>
      </cac:PartyTaxScheme>
      <cac:PartyLegalEntity>
        <cbc:RegistrationName>${this.escapeXML(invoice.supplier.name)}</cbc:RegistrationName>
        <cbc:CompanyID>${invoice.supplier.registrationNumber || ''}</cbc:CompanyID>
      </cac:PartyLegalEntity>
      <cac:Contact>
        <cbc:ElectronicMail>${invoice.supplier.email || ''}</cbc:ElectronicMail>
      </cac:Contact>
    </cac:Party>
  </cac:AccountingSupplierParty>

  <!-- Customer Party -->
  <cac:AccountingCustomerParty>
    <cac:Party>
      <cac:PartyName>
        <cbc:Name>${this.escapeXML(invoice.buyer.name)}</cbc:Name>
      </cac:PartyName>
      <cac:PostalAddress>
        <cbc:StreetName>${this.escapeXML(invoice.buyer.address.street)}</cbc:StreetName>
        <cbc:CityName>${this.escapeXML(invoice.buyer.address.city)}</cbc:CityName>
        <cbc:PostalZone>${invoice.buyer.address.postalCode}</cbc:PostalZone>
        <cac:Country>
          <cbc:IdentificationCode>${invoice.buyer.address.country}</cbc:IdentificationCode>
        </cac:Country>
      </cac:PostalAddress>
      <cac:PartyTaxScheme>
        <cbc:CompanyID>${invoice.buyer.vatNumber}</cbc:CompanyID>
        <cac:TaxScheme>
          <cbc:ID>VAT</cbc:ID>
        </cac:TaxScheme>
      </cac:PartyTaxScheme>
    </cac:Party>
  </cac:AccountingCustomerParty>

  <!-- Line Items -->
${invoice.lineItems.map((item, index) => this.generateLineItemXML(item, index + 1)).join('\n')}

  <!-- Tax Total -->
  <cac:TaxTotal>
    <cbc:TaxAmount currencyID="${invoice.amounts.currency}">${this.formatAmount(invoice.amounts.vat.reduce((sum, v) => sum + v.amount, 0))}</cbc:TaxAmount>
${invoice.amounts.vat.map(vat => this.generateTaxSubtotalXML(vat, invoice.amounts.currency)).join('\n')}
  </cac:TaxTotal>

  <!-- Legal Monetary Total -->
  <cac:LegalMonetaryTotal>
    <cbc:LineExtensionAmount currencyID="${invoice.amounts.currency}">${this.formatAmount(invoice.amounts.net)}</cbc:LineExtensionAmount>
    <cbc:TaxExclusiveAmount currencyID="${invoice.amounts.currency}">${this.formatAmount(invoice.amounts.net)}</cbc:TaxExclusiveAmount>
    <cbc:TaxInclusiveAmount currencyID="${invoice.amounts.currency}">${this.formatAmount(invoice.amounts.gross)}</cbc:TaxInclusiveAmount>
    <cbc:PayableAmount currencyID="${invoice.amounts.currency}">${this.formatAmount(invoice.amounts.gross)}</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>
</Invoice>`;

    return xml.trim();
  }

  /**
   * Generate line item XML
   */
  private static generateLineItemXML(item: any, index: number): string {
    return `  <cac:InvoiceLine>
    <cbc:ID>${index}</cbc:ID>
    <cbc:InvoicedQuantity unitCode="${item.unit}">${item.quantity}</cbc:InvoicedQuantity>
    <cbc:LineExtensionAmount currencyID="EUR">${this.formatAmount(item.netAmount)}</cbc:LineExtensionAmount>
    <cac:Item>
      <cbc:Description>${this.escapeXML(item.description)}</cbc:Description>
      <cbc:Name>${this.escapeXML(item.description)}</cbc:Name>
      <cac:ClassifiedTaxCategory>
        <cbc:ID>S</cbc:ID>
        <cbc:Percent>${item.vatRate}</cbc:Percent>
        <cac:TaxScheme>
          <cbc:ID>VAT</cbc:ID>
        </cac:TaxScheme>
      </cac:ClassifiedTaxCategory>
      <!-- Croatian CIUS Extension: KPD Code -->
      <cac:CommodityClassification>
        <cbc:ItemClassificationCode listID="KLASUS">${item.kpdCode}</cbc:ItemClassificationCode>
      </cac:CommodityClassification>
    </cac:Item>
    <cac:Price>
      <cbc:PriceAmount currencyID="EUR">${this.formatAmount(item.unitPrice)}</cbc:PriceAmount>
    </cac:Price>
  </cac:InvoiceLine>`;
  }

  /**
   * Generate tax subtotal XML
   */
  private static generateTaxSubtotalXML(vat: any, currency: string): string {
    return `    <cac:TaxSubtotal>
      <cbc:TaxableAmount currencyID="${currency}">${this.formatAmount(vat.base)}</cbc:TaxableAmount>
      <cbc:TaxAmount currencyID="${currency}">${this.formatAmount(vat.amount)}</cbc:TaxAmount>
      <cac:TaxCategory>
        <cbc:ID>S</cbc:ID>
        <cbc:Percent>${vat.rate}</cbc:Percent>
        <cac:TaxScheme>
          <cbc:ID>VAT</cbc:ID>
        </cac:TaxScheme>
      </cac:TaxCategory>
    </cac:TaxSubtotal>`;
  }

  /**
   * Format amount to 2 decimal places
   */
  private static formatAmount(amount: number): string {
    return amount.toFixed(2);
  }

  /**
   * Escape XML special characters
   */
  private static escapeXML(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  }

  /**
   * Generate invalid XML (for negative testing)
   */
  static generateInvalidXML(): string {
    return `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">
  <!-- Missing required fields -->
  <cbc:ID></cbc:ID>
</Invoice>`;
  }

  /**
   * Generate malformed XML (for XXE attack testing)
   */
  static generateMalformedXML(): string {
    return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<Invoice>
  <cbc:ID>&xxe;</cbc:ID>
</Invoice>`;
  }
}
