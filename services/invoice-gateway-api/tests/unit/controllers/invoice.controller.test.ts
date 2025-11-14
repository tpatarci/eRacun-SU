/**
 * Invoice Controller Tests
 */

import { Request, Response } from 'express';
import { Container } from 'inversify';
import { InvoiceController } from '../../../src/controllers/invoice.controller';

describe('InvoiceController', () => {
  let controller: InvoiceController;
  let container: Container;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let jsonSpy: jest.Mock;
  let statusSpy: jest.Mock;

  beforeEach(() => {
    container = new Container();
    controller = new InvoiceController(container);

    jsonSpy = jest.fn().mockReturnThis();
    statusSpy = jest.fn().mockReturnThis();

    mockRequest = {
      body: {},
      params: {},
      protocol: 'https',
      get: jest.fn().mockReturnValue('api.eracun.hr'),
      requestId: 'test-request-id',
      idempotencyKey: 'test-idempotency-key',
    };

    mockResponse = {
      status: statusSpy,
      json: jsonSpy,
    };
  });

  describe('submitInvoice', () => {
    it('should accept valid invoice submission', async () => {
      const validInvoice = {
        invoiceNumber: 'INV-2025-001',
        issueDate: '2025-11-14',
        supplier: {
          name: 'Test d.o.o.',
          address: {
            street: 'Ilica 1',
            city: 'Zagreb',
            postalCode: '10000',
            country: 'HR',
          },
          vatNumber: 'HR12345678901',
        },
        buyer: {
          name: 'Buyer d.o.o.',
          address: {
            street: 'Trg 2',
            city: 'Split',
            postalCode: '21000',
            country: 'HR',
          },
          vatNumber: 'HR98765432109',
        },
        lineItems: [
          {
            id: 'line-1',
            description: 'Services',
            quantity: 1,
            unit: 'EA',
            unitPrice: 1000,
            kpdCode: '123456',
            vatRate: 25,
          },
        ],
        amounts: {
          net: 1000,
          vat: [{ rate: 25, base: 1000, amount: 250, category: 'STANDARD' }],
          gross: 1250,
          currency: 'EUR',
        },
      };

      mockRequest.body = validInvoice;

      await controller.submitInvoice(mockRequest as Request, mockResponse as Response);

      expect(statusSpy).toHaveBeenCalledWith(202);
      expect(jsonSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          invoiceId: expect.stringMatching(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i),
          status: 'QUEUED',
          trackingUrl: expect.stringContaining('/api/v1/invoices/'),
          acceptedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/),
        })
      );
    });

    it('should generate tracking URL with correct protocol and host', async () => {
      mockRequest.body = {
        invoiceNumber: 'INV-001',
        issueDate: '2025-11-14',
        supplier: { name: 'Test', address: { street: 'A', city: 'B', postalCode: '10000', country: 'HR' }, vatNumber: 'HR12345678901' },
        buyer: { name: 'Test', address: { street: 'A', city: 'B', postalCode: '10000', country: 'HR' }, vatNumber: 'HR98765432109' },
        lineItems: [{ id: '1', description: 'X', quantity: 1, unit: 'EA', unitPrice: 100, kpdCode: '123456', vatRate: 25 }],
        amounts: { net: 100, vat: [{ rate: 25, base: 100, amount: 25, category: 'STANDARD' }], gross: 125, currency: 'EUR' },
      };

      await controller.submitInvoice(mockRequest as Request, mockResponse as Response);

      const callArg = jsonSpy.mock.calls[0][0];
      expect(callArg.trackingUrl).toMatch(/^https:\/\/api\.eracun\.hr\/api\/v1\/invoices\//);
    });
  });

  describe('getInvoiceStatus', () => {
    it('should return 404 for non-existent invoice', async () => {
      mockRequest.params = { invoiceId: '00000000-0000-0000-0000-000000000000' };

      await expect(
        controller.getInvoiceStatus(mockRequest as Request, mockResponse as Response)
      ).rejects.toThrow('Invoice not found');
    });

    it('should return invoice status for existing invoice', async () => {
      // First submit an invoice
      mockRequest.body = {
        invoiceNumber: 'INV-002',
        issueDate: '2025-11-14',
        supplier: { name: 'Test', address: { street: 'A', city: 'B', postalCode: '10000', country: 'HR' }, vatNumber: 'HR12345678901' },
        buyer: { name: 'Test', address: { street: 'A', city: 'B', postalCode: '10000', country: 'HR' }, vatNumber: 'HR98765432109' },
        lineItems: [{ id: '1', description: 'X', quantity: 1, unit: 'EA', unitPrice: 100, kpdCode: '123456', vatRate: 25 }],
        amounts: { net: 100, vat: [{ rate: 25, base: 100, amount: 25, category: 'STANDARD' }], gross: 125, currency: 'EUR' },
      };

      await controller.submitInvoice(mockRequest as Request, mockResponse as Response);
      const submissionResult = jsonSpy.mock.calls[0][0];
      const invoiceId = submissionResult.invoiceId;

      // Reset mocks
      jsonSpy.mockClear();
      statusSpy.mockClear();

      // Now get status
      mockRequest.params = { invoiceId };

      await controller.getInvoiceStatus(mockRequest as Request, mockResponse as Response);

      expect(statusSpy).toHaveBeenCalledWith(200);
      expect(jsonSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          invoiceId,
          invoiceNumber: 'INV-002',
          status: 'QUEUED',
          progress: expect.objectContaining({
            currentStep: 'Queued for processing',
            totalSteps: 6,
            percentage: 10,
          }),
        })
      );
    });
  });
});
