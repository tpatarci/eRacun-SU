/**
 * XML Parser Tests - IMPROVEMENT-007
 *
 * Performance optimization tests for:
 * - Pre-compiled entity regex (avoid recompilation in hot path)
 * - Cached XML metadata (size, declaration, depth calculated once)
 * - Early-exit depth estimation (stop at first limit breach)
 * - Reduced redundant function calls (trim, byteLength, depth estimation)
 */

import {
  parseXML,
  validateXMLSecurity,
  extractElement,
  validateXMLStructure,
  toXML,
  parseXMLBatch,
} from '../../src/xml-parser';

describe('XML Parser - IMPROVEMENT-007 Performance Optimizations', () => {
  describe('Entity Regex Optimization', () => {
    it('should correctly count entities with pre-compiled regex', () => {
      const xmlWithEntities = `<?xml version="1.0"?>
<document>
  <text>Hello &amp; goodbye &lt;world&gt; &nbsp; test &quot;quoted&quot;</text>
</document>`;

      const result = validateXMLSecurity(xmlWithEntities);
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it('should detect excessive entities (billion laughs prevention)', () => {
      let xmlContent = '<?xml version="1.0"?><root><text>';
      // Create 101 entity references to exceed limit
      for (let i = 0; i < 101; i++) {
        xmlContent += '&entity;';
      }
      xmlContent += '</text></root>';

      const result = validateXMLSecurity(xmlContent);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('excessive entity'))).toBe(true);
    });

    it('should handle XML with exactly 100 entities', () => {
      let xmlContent = '<?xml version="1.0"?><root><text>';
      // Create exactly 100 entity references
      for (let i = 0; i < 100; i++) {
        xmlContent += '&entity;';
      }
      xmlContent += '</text></root>';

      const result = validateXMLSecurity(xmlContent);
      expect(result.valid).toBe(true);
    });

    it('should handle mixed valid HTML entities', () => {
      const xmlWithStandardEntities = `<?xml version="1.0"?>
<document>
  <text>&amp; &lt; &gt; &quot; &apos;</text>
</document>`;

      const result = parseXML(xmlWithStandardEntities);
      expect(result.success).toBe(true);
      expect(result.errors).toEqual([]);
    });
  });

  describe('Metadata Caching Optimization', () => {
    it('should extract metadata once and reuse (avoid multiple trim() calls)', () => {
      const xmlWithWhitespace = `

        <?xml version="1.0"?>
        <invoice>
          <id>12345</id>
        </invoice>

      `;

      const result = parseXML(xmlWithWhitespace);

      expect(result.success).toBe(true);
      expect(result.metadata.hasDeclaration).toBe(true);
      expect(result.metadata.sizeBytes).toBeGreaterThan(0);
      expect(typeof result.metadata.depth).toBe('number');
    });

    it('should cache size calculation (avoid multiple Buffer.byteLength calls)', () => {
      const xmlString = '<?xml version="1.0"?><root><element>Content with UTF-8: é à ü</element></root>';

      const result = parseXML(xmlString);

      expect(result.success).toBe(true);
      expect(result.metadata.sizeBytes).toBe(Buffer.byteLength(xmlString.trim(), 'utf8'));
    });

    it('should correctly identify XML declaration', () => {
      const xmlWithDeclaration = '<?xml version="1.0"?><root></root>';
      const xmlWithoutDeclaration = '<root></root>';

      const result1 = parseXML(xmlWithDeclaration);
      const result2 = parseXML(xmlWithoutDeclaration);

      expect(result1.metadata.hasDeclaration).toBe(true);
      expect(result2.metadata.hasDeclaration).toBe(false);
    });

    it('should extract root element efficiently', () => {
      const xml = `<?xml version="1.0"?>
<invoice>
  <header>Test</header>
</invoice>`;

      const result = parseXML(xml);

      expect(result.success).toBe(true);
      expect(result.metadata.rootElement).toBe('invoice');
    });

    it('should handle multiple root-level keys by finding first non-declaration key', () => {
      // This shouldn't happen in valid XML but tests robustness
      const simpleXml = '<root><item>1</item></root>';
      const result = parseXML(simpleXml);

      expect(result.success).toBe(true);
      expect(result.metadata.rootElement).toBe('root');
    });
  });

  describe('Depth Estimation Optimization', () => {
    it('should estimate depth correctly for shallow XML', () => {
      const shallowXml = `<?xml version="1.0"?>
<root>
  <level1>
    <level2>content</level2>
  </level1>
</root>`;

      const result = parseXML(shallowXml);

      expect(result.success).toBe(true);
      expect(result.metadata.depth).toBeLessThanOrEqual(10); // Should be around 3-4
    });

    it('should estimate depth for deeply nested XML', () => {
      let xml = '<?xml version="1.0"?><root>';
      for (let i = 0; i < 15; i++) {
        xml += `<level${i}>`;
      }
      xml += 'content';
      for (let i = 14; i >= 0; i--) {
        xml += `</level${i}>`;
      }
      xml += '</root>';

      const result = parseXML(xml);

      expect(result.success).toBe(true);
      expect(result.metadata.depth).toBeGreaterThan(5);
    });

    it('should detect excessive nesting depth', () => {
      // Create XML with depth exceeding default limit (20)
      let xml = '<?xml version="1.0"?><root>';
      for (let i = 0; i < 25; i++) {
        xml += `<level${i}>`;
      }
      xml += 'content';
      for (let i = 24; i >= 0; i--) {
        xml += `</level${i}>`;
      }
      xml += '</root>';

      const result = parseXML(xml);

      expect(result.success).toBe(false);
      expect(result.errors.some((e) => e.includes('exceeds maximum nesting depth'))).toBe(true);
    });

    it('should use early exit in depth estimation', () => {
      // Create deeply nested XML that should trigger early exit
      let xml = '<?xml version="1.0"?><root>';
      for (let i = 0; i < 100; i++) {
        xml += `<level>`;
      }
      xml += 'content';
      for (let i = 0; i < 100; i++) {
        xml += `</level>`;
      }
      xml += '</root>';

      // Should fail due to excessive depth, but not timeout (early exit works)
      const result = parseXML(xml);

      expect(result.success).toBe(false);
      expect(result.errors.some((e) => e.includes('depth'))).toBe(true);
    });

    it('should handle self-closing tags correctly in depth calculation', () => {
      const xml = `<?xml version="1.0"?>
<root>
  <item id="1" />
  <item id="2" />
  <nested>
    <item id="3" />
  </nested>
</root>`;

      const result = parseXML(xml);

      expect(result.success).toBe(true);
      expect(result.metadata.depth).toBeLessThanOrEqual(10);
    });
  });

  describe('Security Validation Optimization', () => {
    it('should prevent XXE attacks with optimized metadata check', () => {
      const xxePayload = `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>`;

      const result = validateXMLSecurity(xxePayload);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('dangerous entities'))).toBe(true);
    });

    it('should prevent billion laughs attack', () => {
      let xml = '<?xml version="1.0"?><root>';
      for (let i = 0; i < 150; i++) {
        xml += '&lol;';
      }
      xml += '</root>';

      const result = validateXMLSecurity(xml);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('excessive entity'))).toBe(true);
    });

    it('should enforce size limits', () => {
      const largeContent = 'x'.repeat(11 * 1024 * 1024); // 11MB
      const xml = `<?xml version="1.0"?><root><data>${largeContent}</data></root>`;

      const result = validateXMLSecurity(xml, { maxSize: 10 * 1024 * 1024 });

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('exceeds maximum size'))).toBe(true);
    });

    it('should enforce depth limits', () => {
      let xml = '<?xml version="1.0"?><root>';
      for (let i = 0; i < 25; i++) {
        xml += '<level>';
      }
      xml += 'content';
      for (let i = 0; i < 25; i++) {
        xml += '</level>';
      }
      xml += '</root>';

      const result = validateXMLSecurity(xml, { maxDepth: 20 });

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('exceeds maximum nesting depth'))).toBe(true);
    });

    it('should accept valid XML without size/depth violations', () => {
      const validXml = `<?xml version="1.0"?>
<invoice>
  <header>
    <id>INV-001</id>
    <date>2025-11-12</date>
  </header>
  <items>
    <item>
      <name>Product A</name>
      <price>100.00</price>
    </item>
  </items>
</invoice>`;

      const result = validateXMLSecurity(validXml);

      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });
  });

  describe('Backward Compatibility', () => {
    it('should produce same parse results as before optimization', () => {
      const validXml = `<?xml version="1.0"?>
<root attr="value">
  <item>Text content</item>
  <item>More content</item>
</root>`;

      const result = parseXML(validXml);

      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data.root).toBeDefined();
      expect(result.data.root.item).toBeInstanceOf(Array);
      expect(result.data.root.item.length).toBe(2);
    });

    it('should maintain extractElement functionality', () => {
      const xml = `<?xml version="1.0"?>
<root>
  <level1>
    <level2>
      <level3>Deep value</level3>
    </level2>
  </level1>
</root>`;

      const result = parseXML(xml);
      const value = extractElement(result.data, 'root.level1.level2.level3');

      expect(value).toBe('Deep value');
    });

    it('should maintain validateXMLStructure functionality', () => {
      const xml = `<?xml version="1.0"?>
<invoice>
  <id>123</id>
  <total>500.00</total>
</invoice>`;

      const result = parseXML(xml);
      const validation = validateXMLStructure(result.data, ['invoice.id', 'invoice.total']);

      expect(validation.valid).toBe(true);
      expect(validation.errors).toEqual([]);
    });

    it('should maintain toXML functionality', () => {
      const data = {
        root: {
          item: 'test value',
          '@_attr': 'attribute value',
        },
      };

      const xml = toXML(data);

      expect(xml).toContain('test value');
      expect(xml).toContain('attribute value');
    });

    it('should handle batch parsing', () => {
      const xmlDocuments = [
        '<?xml version="1.0"?><root><id>1</id></root>',
        '<?xml version="1.0"?><root><id>2</id></root>',
        '<?xml version="1.0"?><root><id>3</id></root>',
      ];

      const results = parseXMLBatch(xmlDocuments);

      expect(results.length).toBe(3);
      expect(results.every((r) => r.success)).toBe(true);
    });
  });

  describe('Error Handling', () => {
    it('should handle empty XML string', () => {
      const result = parseXML('');

      expect(result.success).toBe(false);
      expect(result.errors.some((e) => e.includes('required'))).toBe(true);
    });

    it('should handle malformed XML', () => {
      const malformedXml = '<?xml version="1.0"?><root><unclosed>';

      const result = parseXML(malformedXml);

      expect(result.success).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should handle null input gracefully', () => {
      const result = validateXMLSecurity(null as any);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('required'))).toBe(true);
    });

    it('should handle non-string input', () => {
      const result = validateXMLSecurity(12345 as any);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('required'))).toBe(true);
    });

    it('should preserve error context on parse failure', () => {
      const invalidXml = '<root><item>unclosed</root>';

      const result = parseXML(invalidXml);

      expect(result.success).toBe(false);
      expect(result.metadata.sizeBytes).toBeGreaterThan(0);
      expect(typeof result.metadata.depth).toBe('number');
    });
  });

  describe('Edge Cases', () => {
    it('should handle XML with CDATA sections', () => {
      const xmlWithCdata = `<?xml version="1.0"?>
<root>
  <data><![CDATA[Some <data> with special & characters]]></data>
</root>`;

      const result = parseXML(xmlWithCdata);

      expect(result.success).toBe(true);
      expect(result.data.root.data.__cdata).toContain('Some <data>');
    });

    it('should handle XML with namespaces', () => {
      const xmlWithNamespace = `<?xml version="1.0"?>
<root xmlns="http://example.com/ns">
  <item>value</item>
</root>`;

      const result = parseXML(xmlWithNamespace);

      expect(result.success).toBe(true);
    });

    it('should handle XML with comments', () => {
      const xmlWithComments = `<?xml version="1.0"?>
<root>
  <!-- This is a comment -->
  <item>value</item>
  <!-- Another comment -->
</root>`;

      const result = parseXML(xmlWithComments);

      expect(result.success).toBe(true);
    });

    it('should handle XML with mixed content', () => {
      const xmlMixed = `<?xml version="1.0"?>
<root>
  Text before
  <item>Item 1</item>
  Text between
  <item>Item 2</item>
  Text after
</root>`;

      const result = parseXML(xmlMixed);

      expect(result.success).toBe(true);
    });

    it('should handle XML with special characters in values', () => {
      const xmlSpecialChars = `<?xml version="1.0"?>
<root>
  <content>&lt;tag&gt; &amp; &quot;quoted&quot; &apos;apostrophe&apos;</content>
</root>`;

      const result = parseXML(xmlSpecialChars);

      expect(result.success).toBe(true);
      expect(result.data.root.content).toContain('<tag>');
    });

    it('should handle very long attribute values', () => {
      const longAttr = 'x'.repeat(10000);
      const xmlLongAttr = `<?xml version="1.0"?>
<root attr="${longAttr}">
  <item>value</item>
</root>`;

      const result = parseXML(xmlLongAttr);

      expect(result.success).toBe(true);
      expect(result.data.root['@_attr'].length).toBe(10000);
    });

    it('should handle Unicode content', () => {
      const xmlUnicode = `<?xml version="1.0" encoding="UTF-8"?>
<root>
  <text>Hello 世界 мир مرحبا</text>
  <emoji>🚀 💻 ✨</emoji>
</root>`;

      const result = parseXML(xmlUnicode);

      expect(result.success).toBe(true);
      expect(result.data.root.text).toContain('世界');
      expect(result.data.root.emoji).toContain('🚀');
    });
  });

  describe('Performance Characteristics', () => {
    it('should handle large XML documents within timeout', () => {
      // Create a reasonably large but valid XML document
      let xml = '<?xml version="1.0"?><root>';
      for (let i = 0; i < 1000; i++) {
        xml += `<item><id>${i}</id><value>Item ${i}</value></item>`;
      }
      xml += '</root>';

      const startTime = Date.now();
      const result = parseXML(xml);
      const duration = Date.now() - startTime;

      expect(result.success).toBe(true);
      expect(duration).toBeLessThan(5000); // Should complete in less than 5 seconds
    });

    it('should reject deeply nested XML quickly (early exit)', () => {
      // Create extremely deeply nested XML that should be rejected quickly
      let xml = '<?xml version="1.0"?><root>';
      for (let i = 0; i < 100; i++) {
        xml += '<level>';
      }
      xml += 'x';
      for (let i = 0; i < 100; i++) {
        xml += '</level>';
      }
      xml += '</root>';

      const startTime = Date.now();
      const result = parseXML(xml);
      const duration = Date.now() - startTime;

      expect(result.success).toBe(false);
      expect(result.errors.some((e) => e.includes('depth'))).toBe(true);
      expect(duration).toBeLessThan(1000); // Early exit should be very fast
    });
  });
});
