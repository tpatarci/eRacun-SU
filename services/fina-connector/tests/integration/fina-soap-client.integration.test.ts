import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore - nock types not bundled in repo
import nock from 'nock';
import { FINASOAPClient } from '../../src/soap-client.js';

const wsdlContent = `<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:tns="http://fina.example.hr/wsdl"
             xmlns:xsd="http://www.w3.org/2001/XMLSchema"
             targetNamespace="http://fina.example.hr/wsdl">
  <types>
    <xsd:schema targetNamespace="http://fina.example.hr/wsdl">
      <xsd:element name="EchoRequest">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element name="poruka" type="xsd:string" />
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>
      <xsd:element name="EchoResponse">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element name="poruka" type="xsd:string" />
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>
    </xsd:schema>
  </types>
  <message name="EchoRequest">
    <part name="parameters" element="tns:EchoRequest" />
  </message>
  <message name="EchoResponse">
    <part name="parameters" element="tns:EchoResponse" />
  </message>
  <portType name="FinaPortType">
    <operation name="Echo">
      <input message="tns:EchoRequest" />
      <output message="tns:EchoResponse" />
    </operation>
  </portType>
  <binding name="FinaBinding" type="tns:FinaPortType">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http" />
    <operation name="Echo">
      <soap:operation soapAction="Echo" />
      <input>
        <soap:body use="literal" />
      </input>
      <output>
        <soap:body use="literal" />
      </output>
    </operation>
  </binding>
  <service name="FinaService">
    <port name="FinaPort" binding="tns:FinaBinding">
      <soap:address location="https://fina.example.hr/soap-endpoint" />
    </port>
  </service>
</definitions>`;

const echoResponse = `<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <EchoResponse xmlns="http://fina.example.hr/wsdl">
      <poruka>HELLO::ACK</poruka>
    </EchoResponse>
  </soap:Body>
</soap:Envelope>`;

describe('FINASOAPClient integration with mocked SOAP endpoint', () => {
  beforeAll(() => {
    nock.disableNetConnect();
  });

  afterAll(() => {
    nock.cleanAll();
    nock.enableNetConnect();
  });

  it('initializes client and completes echo round-trip via nock', async () => {
    const wsdlScope = nock('https://fina.example.hr')
      .get('/service.wsdl')
      .twice()
      .reply(200, wsdlContent, { 'Content-Type': 'text/xml' });

    const soapScope = nock('https://fina.example.hr')
      .post('/soap-endpoint', (body: string) => body.includes('<poruka>HELLO</poruka>'))
      .reply(200, echoResponse, { 'Content-Type': 'text/xml' });

    const client = new FINASOAPClient({
      wsdlUrl: 'https://fina.example.hr/service.wsdl',
      endpointUrl: 'https://fina.example.hr/soap-endpoint',
      timeout: 2000,
      disableCache: true,
      wsdlRefreshIntervalHours: 1,
      wsdlRequestTimeoutMs: 5000,
    });

    await client.initialize();
    const response = await client.echo({ message: 'HELLO' });

    expect(response.message).toBe('HELLO::ACK');
    expect(wsdlScope.isDone()).toBe(true);
    expect(soapScope.isDone()).toBe(true);
  });
});
