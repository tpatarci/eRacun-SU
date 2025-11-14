interface ValidationError {
  message: string;
  line?: number;
  column?: number;
}

interface DocumentMetadata {
  rootName?: string;
  schemaTargetRoot?: string;
}

class SimpleXmlDocument {
  public validationErrors: ValidationError[] = [];
  private xml: string;
  private metadata: DocumentMetadata;

  constructor(xml: string, metadata: DocumentMetadata) {
    this.xml = xml;
    this.metadata = metadata;
  }

  validate(schemaDoc?: SimpleXmlDocument): boolean {
    this.validationErrors = [];
    const expectedRoot = schemaDoc?.getMetadata().schemaTargetRoot;

    if (expectedRoot && expectedRoot !== this.metadata.rootName) {
      this.validationErrors.push({
        message: `Root element mismatch. Expected ${expectedRoot}, found ${this.metadata.rootName || 'unknown'}.`,
        line: 1,
        column: 1,
      });
      return false;
    }

    if (this.metadata.rootName?.includes('Invoice')) {
      if (!this.xml.includes('<cbc:ID>') || !this.xml.includes('</cbc:ID>')) {
        this.validationErrors.push({ message: 'Missing required element cbc:ID', line: 1, column: 1 });
        return false;
      }
      if (!this.xml.includes('<cbc:IssueDate>') || !this.xml.includes('</cbc:IssueDate>')) {
        this.validationErrors.push({ message: 'Missing required element cbc:IssueDate', line: 1, column: 1 });
        return false;
      }
    }

    return true;
  }

  getMetadata(): DocumentMetadata {
    return this.metadata;
  }
}

function parseXml(xmlContent: string): SimpleXmlDocument {
  if (typeof xmlContent !== 'string') {
    throw new Error('XML input must be a string');
  }

  const trimmed = xmlContent.trim();
  if (!trimmed.startsWith('<')) {
    throw new Error('XML parsing error: content must start with < (line 1, column 1)');
  }

  validateStructure(xmlContent);

  const metadata: DocumentMetadata = {
    rootName: extractRootName(xmlContent),
  };

  if (trimmed.includes('<xs:schema')) {
    const rootMatch = trimmed.match(/<xs:element[^>]*name\s*=\s*"([^"]+)"/i);
    if (rootMatch) {
      metadata.schemaTargetRoot = rootMatch[1];
    }
  }

  return new SimpleXmlDocument(xmlContent, metadata);
}

function extractRootName(xml: string): string | undefined {
  const match = xml.match(/<([A-Za-z0-9_:\-]+)(\s|>)/);
  if (!match) {
    return undefined;
  }
  const tagName = match[1];
  const parts = tagName.split(':');
  return parts.length === 2 ? parts[1] : parts[0];
}

function validateStructure(xml: string): void {
  const tagRegex = /<([^>]+)>/g;
  const stack: string[] = [];
  let match: RegExpExecArray | null;

  while ((match = tagRegex.exec(xml))) {
    const raw = match[1].trim();
    if (raw.startsWith('?') || raw.startsWith('!') || raw.startsWith('!--')) {
      continue;
    }

    if (raw.startsWith('/')) {
      const tagName = raw.slice(1).split(/\s+/)[0];
      const last = stack.pop();
      if (last !== tagName) {
        throw createParseError(`Mismatched closing tag </${tagName}>`, xml, match.index);
      }
    } else {
      const selfClosing = raw.endsWith('/') || raw.includes('/>');
      if (!selfClosing) {
        const tagName = raw.split(/\s+/)[0];
        stack.push(tagName);
      }
    }
  }

  if (stack.length > 0) {
    const unclosed = stack.pop();
    throw createParseError(`Unclosed tag <${unclosed}>`, xml, xml.length - 1);
  }
}

function createParseError(message: string, xml: string, index: number): Error {
  const { line, column } = computePosition(xml, index);
  return new Error(`${message} at line ${line}, column ${column}`);
}

function computePosition(xml: string, index: number): { line: number; column: number } {
  const substring = xml.slice(0, index);
  const lines = substring.split('\n');
  const line = lines.length;
  const column = lines[lines.length - 1].length + 1;
  return { line, column };
}

export { parseXml };
