import { describe, it, expect, jest } from '@jest/globals';
import fc from 'fast-check';
import { XMLParser, XMLValidator } from 'fast-xml-parser';
import {
  parseXML,
  validateXMLSecurity,
  validateXMLStructure,
  extractElement,
  toXML,
  parseXMLBatch,
} from '../../src/xml-parser';

describe('XML Parser', () => {
  describe('validateXMLSecurity', () => {
    it('should accept valid XML', () => {
      const xml = '<root><child>value</child></root>';
      const result = validateXMLSecurity(xml);
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it('should reject empty XML', () => {
      const result = validateXMLSecurity('');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('XML content is required');
    });

    it('should reject whitespace-only XML', () => {
      const result = validateXMLSecurity('   ');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('XML content is required');
    });

    it('should reject non-string XML', () => {
      const result = validateXMLSecurity(123 as any);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('XML content is required');
    });

    it('should reject null XML', () => {
      const result = validateXMLSecurity(null as any);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('XML content is required');
    });

    it('should reject undefined XML', () => {
      const result = validateXMLSecurity(undefined as any);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('XML content is required');
    });

    it('should reject XML exceeding size limit', () => {
      const largeXML = '<root>' + 'x'.repeat(11 * 1024 * 1024) + '</root>';
      const result = validateXMLSecurity(largeXML);
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('exceeds maximum size');
    });

    it('should reject XML with custom size limit', () => {
      const xml = '<root>' + 'x'.repeat(2000) + '</root>';
      const result = validateXMLSecurity(xml, { maxSize: 1000 });
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('exceeds maximum size');
    });

    it('should reject XML with DOCTYPE (XXE prevention)', () => {
      const xml = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>';
      const result = validateXMLSecurity(xml);
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('potentially dangerous entities');
    });

    it('should reject XML with ENTITY (XXE prevention)', () => {
      const xml = '<!ENTITY test "value"><root>&test;</root>';
      const result = validateXMLSecurity(xml);
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('potentially dangerous entities');
    });

    it('should reject XML with excessive entities (billion laughs)', () => {
      const entities = Array.from({ length: 150 }, (_, i) => `&entity${i};`).join('');
      const xml = `<root>${entities}</root>`;
      const result = validateXMLSecurity(xml);
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('excessive entity references');
    });

    it('should reject XML exceeding depth limit', () => {
      // Create deeply nested XML with many tags to trigger depth check
      const depth = 50;
      let xml = '';
      for (let i = 0; i < depth; i++) {
        xml += `<level>`;
      }
      xml += 'value';
      for (let i = 0; i < depth; i++) {
        xml += `</level>`;
      }
      const result = validateXMLSecurity(xml, { maxDepth: 10 });
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('exceeds maximum nesting depth');
    });

    it('should accept XML within all limits', () => {
      const xml = '<Invoice><ID>123</ID><IssueDate>2025-01-01</IssueDate></Invoice>';
      const result = validateXMLSecurity(xml);
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });
  });

  describe('parseXML', () => {
    afterEach(() => {
      // Ensure all mocks are restored after each test
      jest.restoreAllMocks();
    });

    it('should parse valid XML', () => {
      const xml = '<root><child>value</child></root>';
      const result = parseXML(xml);
      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data.root.child).toBe('value');
      expect(result.errors).toEqual([]);
    });

    it('should parse XML with attributes', () => {
      const xml = '<root attr="value"><child>text</child></root>';
      const result = parseXML(xml);
      expect(result.success).toBe(true);
      expect(result.data.root['@_attr']).toBe('value');
      expect(result.data.root.child).toBe('text');
    });

    it('should parse XML without attributes when disabled', () => {
      const xml = '<root attr="value"><child>text</child></root>';
      const result = parseXML(xml, { allowAttributes: false });
      expect(result.success).toBe(true);
      expect(result.data.root['@_attr']).toBeUndefined();
    });

    it('should parse XML with multiple children', () => {
      const xml = '<root><item>1</item><item>2</item><item>3</item></root>';
      const result = parseXML(xml);
      expect(result.success).toBe(true);
      expect(Array.isArray(result.data.root.item)).toBe(true);
      expect(result.data.root.item).toHaveLength(3);
    });

    it('should parse XML with namespaces', () => {
      const xml = '<ubl:Invoice xmlns:ubl="urn:oasis"><ubl:ID>123</ubl:ID></ubl:Invoice>';
      const result = parseXML(xml);
      expect(result.success).toBe(true);
      expect(result.data['ubl:Invoice']).toBeDefined();
    });

    it('should parse XML with CDATA', () => {
      const xml = '<root><![CDATA[Special <characters> & symbols]]></root>';
      const result = parseXML(xml);
      expect(result.success).toBe(true);
      expect(result.data.root.__cdata).toContain('Special');
    });

    it('should reject invalid XML syntax', () => {
      const xml = '<root><unclosed>';
      const result = parseXML(xml);
      expect(result.success).toBe(false);
      expect(result.errors[0]).toContain('Invalid XML syntax');
    });

    it('should reject XML with security violations', () => {
      const xml = '<!DOCTYPE foo><root>test</root>';
      const result = parseXML(xml);
      expect(result.success).toBe(false);
      expect(result.errors[0]).toContain('dangerous entities');
    });

    it('should include metadata in result', () => {
      const xml = '<?xml version="1.0"?><root><child>value</child></root>';
      const result = parseXML(xml);
      expect(result.success).toBe(true);
      expect(result.metadata.sizeBytes).toBeGreaterThan(0);
      expect(result.metadata.hasDeclaration).toBe(true);
      expect(result.metadata.rootElement).toBe('root');
      expect(result.metadata.depth).toBeGreaterThan(0);
    });

    it('should detect XML without declaration', () => {
      const xml = '<root><child>value</child></root>';
      const result = parseXML(xml);
      expect(result.success).toBe(true);
      expect(result.metadata.hasDeclaration).toBe(false);
    });

    it('should trim text values by default', () => {
      const xml = '<root><child>  value  </child></root>';
      const result = parseXML(xml);
      expect(result.success).toBe(true);
      expect(result.data.root.child).toBe('value');
    });

    it('should parse attribute values', () => {
      const xml = '<root count="123" active="true"><child>value</child></root>';
      const result = parseXML(xml);
      expect(result.success).toBe(true);
      expect(result.data.root['@_count']).toBe(123);
      expect(result.data.root['@_active']).toBe(true);
    });

    it('should handle empty elements', () => {
      const xml = '<root><empty/><notEmpty>value</notEmpty></root>';
      const result = parseXML(xml);
      expect(result.success).toBe(true);
      expect(result.data.root.empty).toBe('');
      expect(result.data.root.notEmpty).toBe('value');
    });

    it('should handle parsing errors gracefully', () => {
      const xml = '<root><<invalid</root>';
      const result = parseXML(xml);
      expect(result.success).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should handle unexpected parser exceptions', () => {
      // Mock XMLParser to throw an error during parsing
      const mockParse = jest.spyOn(XMLParser.prototype, 'parse').mockImplementationOnce(() => {
        throw new Error('Unexpected parser error');
      });

      const xml = '<root><child>value</child></root>';
      const result = parseXML(xml);

      expect(result.success).toBe(false);
      expect(result.errors[0]).toContain('XML parsing error');
      expect(result.errors[0]).toContain('Unexpected parser error');
      expect(result.metadata.sizeBytes).toBeGreaterThan(0);

      mockParse.mockRestore();
    });

    it('should handle non-Error exceptions from parser', () => {
      // Mock XMLParser to throw a non-Error exception
      const mockParse = jest.spyOn(XMLParser.prototype, 'parse').mockImplementationOnce(() => {
        throw 'String error from parser';
      });

      const xml = '<root><child>value</child></root>';
      const result = parseXML(xml);

      expect(result.success).toBe(false);
      expect(result.errors[0]).toContain('XML parsing error');
      expect(result.errors[0]).toContain('Unknown error');

      mockParse.mockRestore();
    });

    it('should handle validation errors without error message', () => {
      // Mock XMLValidator to return error with empty msg
      const mockValidate = jest.spyOn(XMLValidator, 'validate').mockImplementationOnce(() => ({
        err: { code: 'ERR', msg: '', line: 1, col: 1 },
      }));

      const xml = '<root><child>value</child></root>';
      const result = parseXML(xml);

      expect(result.success).toBe(false);
      expect(result.errors[0]).toContain('Unknown error');
      expect(result.errors[0]).toContain('at line 1');

      mockValidate.mockRestore();
    });

    it('should handle parsed XML with no root element', () => {
      // Mock XMLParser to return only XML declaration (no root element)
      const mockParse = jest.spyOn(XMLParser.prototype, 'parse').mockImplementationOnce(() => ({
        '?xml': { '@_version': '1.0', '@_encoding': 'UTF-8' },
      }));

      // Provide valid XML that passes security checks, but mock will simulate no root
      const xml = '<?xml version="1.0" encoding="UTF-8"?><root></root>';
      const result = parseXML(xml);

      expect(result.success).toBe(true);
      expect(result.metadata.rootElement).toBeUndefined();

      mockParse.mockRestore();
    });
  });

  describe('toXML', () => {
    it('should convert object to XML', () => {
      const obj = { root: { child: 'value' } };
      const xml = toXML(obj);
      expect(xml).toContain('<root>');
      expect(xml).toContain('<child>');
      expect(xml).toContain('value');
      expect(xml).toContain('</child>');
      expect(xml).toContain('</root>');
    });

    it('should convert object with attributes', () => {
      const obj = { root: { '@_attr': 'value', child: 'text' } };
      const xml = toXML(obj);
      expect(xml).toContain('attr="value"');
      expect(xml).toContain('<child>');
      expect(xml).toContain('text');
    });

    it('should convert object with arrays', () => {
      const obj = { root: { item: ['1', '2', '3'] } };
      const xml = toXML(obj);
      expect(xml).toContain('<item>1</item>');
      expect(xml).toContain('<item>2</item>');
      expect(xml).toContain('<item>3</item>');
    });

    it('should format XML with indentation', () => {
      const obj = { root: { child: { grandchild: 'value' } } };
      const xml = toXML(obj);
      expect(xml).toContain('  '); // Should have indentation
    });

    it('should handle empty objects', () => {
      const obj = { root: {} };
      const xml = toXML(obj);
      expect(xml).toContain('<root');
      expect(xml).toContain('</root>');
    });
  });

  describe('extractElement', () => {
    const data = {
      Invoice: {
        ID: '123',
        IssueDate: '2025-01-01',
        InvoiceLine: [
          { ID: '1', Item: { Name: 'Product A' } },
          { ID: '2', Item: { Name: 'Product B' } },
        ],
      },
    };

    it('should extract simple element', () => {
      const value = extractElement(data, 'Invoice.ID');
      expect(value).toBe('123');
    });

    it('should extract nested element', () => {
      const value = extractElement(data, 'Invoice.IssueDate');
      expect(value).toBe('2025-01-01');
    });

    it('should extract array element by index', () => {
      const value = extractElement(data, 'Invoice.InvoiceLine.0.ID');
      expect(value).toBe('1');
    });

    it('should extract deeply nested element', () => {
      const value = extractElement(data, 'Invoice.InvoiceLine.1.Item.Name');
      expect(value).toBe('Product B');
    });

    it('should return undefined for non-existent path', () => {
      const value = extractElement(data, 'Invoice.NonExistent');
      expect(value).toBeUndefined();
    });

    it('should return undefined for invalid array index', () => {
      const value = extractElement(data, 'Invoice.InvoiceLine.10.ID');
      expect(value).toBeUndefined();
    });

    it('should handle null data', () => {
      const value = extractElement(null, 'path');
      expect(value).toBeUndefined();
    });

    it('should handle undefined data', () => {
      const value = extractElement(undefined, 'path');
      expect(value).toBeUndefined();
    });

    it('should handle empty path', () => {
      const value = extractElement(data, '');
      expect(value).toBeUndefined();
    });

    it('should handle path to null value', () => {
      const dataWithNull = { root: { child: null } };
      const value = extractElement(dataWithNull, 'root.child.nested');
      expect(value).toBeUndefined();
    });

    it('should return undefined when using array index on non-array', () => {
      const dataWithObject = { root: { child: 'value' } };
      const value = extractElement(dataWithObject, 'root.child.0');
      expect(value).toBeUndefined();
    });
  });

  describe('validateXMLStructure', () => {
    const data = {
      Invoice: {
        ID: '123',
        IssueDate: '2025-01-01',
        AccountingSupplierParty: {
          Party: {
            PartyName: { Name: 'Supplier Inc.' },
          },
        },
      },
    };

    it('should validate required fields present', () => {
      const result = validateXMLStructure(data, [
        'Invoice.ID',
        'Invoice.IssueDate',
      ]);
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it('should detect missing required fields', () => {
      const result = validateXMLStructure(data, [
        'Invoice.ID',
        'Invoice.MissingField',
      ]);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Required field missing or empty: Invoice.MissingField');
    });

    it('should detect empty required fields', () => {
      const dataWithEmpty = { Invoice: { ID: '', IssueDate: '2025-01-01' } };
      const result = validateXMLStructure(dataWithEmpty, ['Invoice.ID']);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Required field missing or empty: Invoice.ID');
    });

    it('should detect null required fields', () => {
      const dataWithNull = { Invoice: { ID: null, IssueDate: '2025-01-01' } };
      const result = validateXMLStructure(dataWithNull, ['Invoice.ID']);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Required field missing or empty: Invoice.ID');
    });

    it('should validate nested fields', () => {
      const result = validateXMLStructure(data, [
        'Invoice.AccountingSupplierParty.Party.PartyName.Name',
      ]);
      expect(result.valid).toBe(true);
    });

    it('should handle empty required fields array', () => {
      const result = validateXMLStructure(data, []);
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it('should reject invalid data structure', () => {
      const result = validateXMLStructure(null, ['field']);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Invalid XML data structure');
    });

    it('should reject non-object data', () => {
      const result = validateXMLStructure('string', ['field']);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Invalid XML data structure');
    });

    it('should report multiple missing fields', () => {
      const result = validateXMLStructure(data, [
        'Invoice.Missing1',
        'Invoice.Missing2',
        'Invoice.Missing3',
      ]);
      expect(result.valid).toBe(false);
      expect(result.errors).toHaveLength(3);
    });
  });

  describe('parseXMLBatch', () => {
    it('should parse multiple XML documents', () => {
      const xmlDocs = [
        '<Invoice><ID>1</ID></Invoice>',
        '<Invoice><ID>2</ID></Invoice>',
        '<Invoice><ID>3</ID></Invoice>',
      ];
      const results = parseXMLBatch(xmlDocs);
      expect(results).toHaveLength(3);
      expect(results[0].success).toBe(true);
      expect(results[1].success).toBe(true);
      expect(results[2].success).toBe(true);
      expect(results[0].data.Invoice.ID).toBe(1);
      expect(results[1].data.Invoice.ID).toBe(2);
      expect(results[2].data.Invoice.ID).toBe(3);
    });

    it('should handle empty array', () => {
      const results = parseXMLBatch([]);
      expect(results).toEqual([]);
    });

    it('should parse each document independently', () => {
      const xmlDocs = [
        '<Invoice><ID>1</ID></Invoice>',
        '<Invalid><unclosed>',
        '<Invoice><ID>3</ID></Invoice>',
      ];
      const results = parseXMLBatch(xmlDocs);
      expect(results).toHaveLength(3);
      expect(results[0].success).toBe(true);
      expect(results[1].success).toBe(false);
      expect(results[2].success).toBe(true);
    });

    it('should apply config to all documents', () => {
      const xmlDocs = [
        '<root>x</root>',
        '<root>y</root>',
      ];
      const results = parseXMLBatch(xmlDocs, { maxSize: 1000 });
      expect(results[0].success).toBe(true);
      expect(results[1].success).toBe(true);
    });
  });

  // Property-based tests
  describe('Property-Based Tests', () => {
    it('should round-trip: parse(toXML(obj)) === obj', () => {
      fc.assert(
        fc.property(
          fc.record({
            root: fc.record({
              value: fc.string({ minLength: 1, maxLength: 50 }).filter((s) => s.trim() !== ''),
            }),
          }),
          (obj) => {
            const xml = toXML(obj);
            const result = parseXML(xml);
            // Account for trimming behavior and parseAttributeValue (numeric strings become numbers)
            const expected = obj.root.value.trim();
            const actual = String(result.data.root.value);
            return result.success && actual === expected;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should consistently parse the same XML', () => {
      fc.assert(
        fc.property(fc.constantFrom(
          '<root><child>value</child></root>',
          '<Invoice><ID>123</ID></Invoice>',
          '<ubl:Invoice xmlns:ubl="urn:test"><ubl:ID>456</ubl:ID></ubl:Invoice>'
        ), (xml) => {
          const result1 = parseXML(xml);
          const result2 = parseXML(xml);
          return result1.success === result2.success;
        }),
        { numRuns: 20 }
      );
    });
  });

  // Edge cases
  describe('Edge Cases', () => {
    it('should handle very simple XML', () => {
      const xml = '<root>value</root>';
      const result = parseXML(xml);
      expect(result.success).toBe(true);
      expect(result.data.root).toBe('value');
    });

    it('should handle XML with only whitespace content', () => {
      const xml = '<root>   </root>';
      const result = parseXML(xml);
      expect(result.success).toBe(true);
    });

    it('should handle XML with special characters', () => {
      const xml = '<root>&lt;&gt;&amp;&quot;&apos;</root>';
      const result = parseXML(xml);
      expect(result.success).toBe(true);
      expect(result.data.root).toContain('<');
      expect(result.data.root).toContain('>');
      expect(result.data.root).toContain('&');
    });

    it('should handle XML with numeric values', () => {
      const xml = '<root><number>123.45</number></root>';
      const result = parseXML(xml);
      expect(result.success).toBe(true);
      expect(result.data.root.number).toBe(123.45);
    });

    it('should handle XML with boolean values', () => {
      const xml = '<root><flag>true</flag></root>';
      const result = parseXML(xml);
      expect(result.success).toBe(true);
      expect(result.data.root.flag).toBe(true);
    });
  });
});
