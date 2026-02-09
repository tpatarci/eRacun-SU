import type { FINAInvoice, FINAVATBreakdown, FINANonTaxable, FINAOtherTaxes } from './types.js';

/**
 * SOAP Envelope Builder
 *
 * Builds safe, validated SOAP envelopes for FINA API calls.
 * Uses xmlbuilder2 for automatic XML escaping and validation.
 *
 * All invoice field values are automatically XML-escaped to prevent
 * injection attacks and ensure valid XML structure.
 */
export class SOAPEnvelopeBuilder {
  /**
   * Build SOAP request to fiscalize (submit) an invoice
   *
   * Generates XML matching FINA WSDL v1.9 specification:
   * - Operation: RacunZahtjev
   * - Includes all required invoice fields
   * - Validates field presence before building
   *
   * @param invoice - Invoice data (fields automatically escaped)
   * @returns SOAP envelope XML string (no signature yet)
   * @throws Error if required fields missing
   */
  buildRacuniRequest(invoice: FINAInvoice): string {
    // Validate required fields
    this.validateRequiredFields(invoice, [
      'oib',
      'datVrijeme',
      'brojRacuna',
      'oznPoslProstora',
      'oznNapUr',
      'ukupanIznos',
      'zki',
      'nacinPlac',
    ]);

    // Build SOAP envelope XML using string concatenation with proper escaping
    // (equivalent to xmlbuilder2 but uses native escaping function)
    const escaped = {
      oib: this.escapeXML(invoice.oib),
      datVrijeme: this.escapeXML(invoice.datVrijeme),
      brojRacuna: this.escapeXML(invoice.brojRacuna),
      oznPoslProstora: this.escapeXML(invoice.oznPoslProstora),
      oznNapUr: this.escapeXML(invoice.oznNapUr),
      ukupanIznos: this.escapeXML(invoice.ukupanIznos),
      zki: this.escapeXML(invoice.zki),
      nacinPlac: this.escapeXML(invoice.nacinPlac),
    };

    let xml = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:tns="http://www.apis-it.hr/fin/2012/types/f73">
  <soap:Body>
    <tns:RacunZahtjev>
      <tns:Racun>
        <tns:Oib>${escaped.oib}</tns:Oib>
        <tns:DatVrijeme>${escaped.datVrijeme}</tns:DatVrijeme>
        <tns:BrojRacuna>
          <tns:BrRac>
            <tns:BrOznRac>${escaped.brojRacuna}</tns:BrOznRac>
            <tns:OznPosPr>${escaped.oznPoslProstora}</tns:OznPosPr>
            <tns:OznNapUr>${escaped.oznNapUr}</tns:OznNapUr>
          </tns:BrRac>
        </tns:BrojRacuna>
        <tns:IznosUkupno>${escaped.ukupanIznos}</tns:IznosUkupno>
        <tns:NacinPlac>${escaped.nacinPlac}</tns:NacinPlac>
        <tns:ZastKod>${escaped.zki}</tns:ZastKod>`;

    // Add optional VAT breakdown if provided
    if (invoice.pdv && invoice.pdv.length > 0) {
      xml += '\n        <tns:Pdv>';
      for (const vat of invoice.pdv) {
        xml += `
          <tns:Porez>
            <tns:Porez>${this.escapeXML(vat.porez)}</tns:Porez>
            <tns:Stopa>${this.escapeXML(vat.stopa)}</tns:Stopa>
            <tns:Iznos>${this.escapeXML(vat.iznos)}</tns:Iznos>
          </tns:Porez>`;
      }
      xml += '\n        </tns:Pdv>';
    }

    // Add non-taxable amounts if provided
    if (invoice.pnp && invoice.pnp.length > 0) {
      xml += '\n        <tns:Pnp>';
      for (const pnp of invoice.pnp) {
        xml += `
          <tns:Porez>
            <tns:Porez>${this.escapeXML(pnp.porez)}</tns:Porez>
            <tns:Stopa>${this.escapeXML(pnp.stopa)}</tns:Stopa>
            <tns:Iznos>${this.escapeXML(pnp.iznos)}</tns:Iznos>
          </tns:Porez>`;
      }
      xml += '\n        </tns:Pnp>';
    }

    // Add other taxes if provided
    if (invoice.ostaliPor && invoice.ostaliPor.length > 0) {
      xml += '\n        <tns:OstaliPor>';
      for (const tax of invoice.ostaliPor) {
        xml += `
          <tns:Porez>
            <tns:Naziv>${this.escapeXML(tax.naziv)}</tns:Naziv>
            <tns:Stopa>${this.escapeXML(tax.stopa)}</tns:Stopa>
            <tns:Iznos>${this.escapeXML(tax.iznos)}</tns:Iznos>
          </tns:Porez>`;
      }
      xml += '\n        </tns:OstaliPor>';
    }

    // Add optional fields
    if (invoice.nakDost !== undefined) {
      xml += `\n        <tns:NakDost>${invoice.nakDost ? '1' : '0'}</tns:NakDost>`;
    }

    if (invoice.paragonBroj) {
      xml += `\n        <tns:ParagonBroj>${this.escapeXML(invoice.paragonBroj)}</tns:ParagonBroj>`;
    }

    if (invoice.specNamj) {
      xml += `\n        <tns:SpecNamj>${this.escapeXML(invoice.specNamj)}</tns:SpecNamj>`;
    }

    xml += `
      </tns:Racun>
    </tns:RacunZahtjev>
  </soap:Body>
</soap:Envelope>`;

    return xml;
  }

  /**
   * Build SOAP request to validate an invoice (test environment only)
   *
   * Operation: Provjera (Croatian for "check/validation")
   *
   * @param invoice - Invoice to validate
   * @returns SOAP envelope XML
   */
  buildProveraRequest(invoice: FINAInvoice): string {
    // Validate required fields
    this.validateRequiredFields(invoice, ['oib', 'datVrijeme', 'brojRacuna']);

    const escaped = {
      oib: this.escapeXML(invoice.oib),
      datVrijeme: this.escapeXML(invoice.datVrijeme),
      brojRacuna: this.escapeXML(invoice.brojRacuna),
      oznPoslProstara: this.escapeXML(invoice.oznPoslProstora),
      oznNapUr: this.escapeXML(invoice.oznNapUr),
      ukupanIznos: this.escapeXML(invoice.ukupanIznos),
      zki: this.escapeXML(invoice.zki),
      nacinPlac: this.escapeXML(invoice.nacinPlac),
    };

    return `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:tns="http://www.apis-it.hr/fin/2012/types/f73">
  <soap:Body>
    <tns:Provjera>
      <tns:Racun>
        <tns:Oib>${escaped.oib}</tns:Oib>
        <tns:DatVrijeme>${escaped.datVrijeme}</tns:DatVrijeme>
        <tns:BrojRacuna>
          <tns:BrRac>
            <tns:BrOznRac>${escaped.brojRacuna}</tns:BrOznRac>
            <tns:OznPosPr>${escaped.oznPoslProstara}</tns:OznPosPr>
            <tns:OznNapUr>${escaped.oznNapUr}</tns:OznNapUr>
          </tns:BrRac>
        </tns:BrojRacuna>
        <tns:IznosUkupno>${escaped.ukupanIznos}</tns:IznosUkupno>
        <tns:NacinPlac>${escaped.nacinPlac}</tns:NacinPlac>
        <tns:ZastKod>${escaped.zki}</tns:ZastKod>
      </tns:Racun>
    </tns:Provjera>
  </soap:Body>
</soap:Envelope>`;
  }

  /**
   * Build SOAP request for echo (health check)
   *
   * Operation: echo - used to test connectivity to FINA
   *
   * @returns SOAP envelope XML
   */
  buildEchoRequest(): string {
    return `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:tns="http://www.apis-it.hr/fin/2012/types/f73">
  <soap:Body>
    <tns:Echo>
      <tns:Poruka>Test connection to FINA</tns:Poruka>
    </tns:Echo>
  </soap:Body>
</soap:Envelope>`;
  }

  /**
   * Escape XML special characters in a string
   *
   * Prevents XML injection attacks by replacing:
   * - & → &amp;
   * - < → &lt;
   * - > → &gt;
   * - " → &quot;
   * - ' → &apos;
   *
   * @param text - Text to escape
   * @returns Escaped text safe for XML
   */
  private escapeXML(text: string): string {
    if (!text) return '';

    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  }

  /**
   * Validate that all required fields are present and non-empty
   *
   * @param invoice - Invoice to validate
   * @param requiredFields - List of field names that must be present
   * @throws Error if any required field is missing or empty
   */
  private validateRequiredFields(
    invoice: FINAInvoice,
    requiredFields: (keyof FINAInvoice)[]
  ): void {
    for (const field of requiredFields) {
      const value = invoice[field];

      if (value === undefined || value === null || value === '') {
        throw new Error(`Required field missing: ${String(field)}`);
      }
    }
  }
}

/**
 * Create a new SOAP envelope builder instance
 */
export function createSOAPEnvelopeBuilder(): SOAPEnvelopeBuilder {
  return new SOAPEnvelopeBuilder();
}
