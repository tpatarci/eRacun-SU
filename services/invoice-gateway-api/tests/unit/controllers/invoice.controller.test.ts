/**
 * Invoice Controller Tests
 */

import { Request, Response } from 'express';
import { InvoiceController } from '../../../src/controllers/invoice.controller';
import { InvoiceRepository } from '../../../src/repositories/invoice.repository';
import { ProcessInvoiceCommandPublisher } from '../../../src/messaging/process-invoice.publisher';

describe('InvoiceController', () => {
  let controller: InvoiceController;
  let repository: jest.Mocked<InvoiceRepository>;
  let publisher: jest.Mocked<ProcessInvoiceCommandPublisher>;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let jsonSpy: jest.Mock;
  let statusSpy: jest.Mock;

  beforeEach(() => {
    repository = {
      saveInvoice: jest.fn(),
      findById: jest.fn(),
      findByIdempotencyKey: jest.fn(),
      updateStatus: jest.fn(),
      close: jest.fn(),
    } as unknown as jest.Mocked<InvoiceRepository>;
    publisher = {
      publish: jest.fn(),
    } as jest.Mocked<ProcessInvoiceCommandPublisher>;

    const baseRecord = {
      id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      idempotencyKey: 'test-idempotency-key',
      invoiceNumber: 'INV-BASE',
      supplierOIB: '12345678901',
      buyerOIB: '10987654321',
      totalAmount: 125,
      currency: 'EUR',
      status: 'QUEUED' as const,
      createdAt: new Date('2025-01-01T00:00:00.000Z'),
      updatedAt: new Date('2025-01-01T00:00:00.000Z'),
    };

    repository.saveInvoice.mockResolvedValue(baseRecord);
    repository.findById.mockResolvedValue(baseRecord);
    publisher.publish.mockResolvedValue();

    controller = new InvoiceController(repository, publisher);

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

      const persistedRecord = {
        id: '11111111-1111-1111-1111-111111111111',
        idempotencyKey: mockRequest.idempotencyKey!,
        invoiceNumber: validInvoice.invoiceNumber,
        supplierOIB: '12345678901',
        buyerOIB: '10987654321',
        totalAmount: validInvoice.amounts.gross,
        currency: validInvoice.amounts.currency,
        status: 'QUEUED' as const,
        createdAt: new Date('2025-01-01T00:00:00.000Z'),
        updatedAt: new Date('2025-01-01T00:00:00.000Z'),
      };

      repository.saveInvoice.mockResolvedValue(persistedRecord);
      publisher.publish.mockResolvedValue();

      await controller.submitInvoice(mockRequest as Request, mockResponse as Response);

      expect(statusSpy).toHaveBeenCalledWith(202);
      expect(jsonSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          invoiceId: persistedRecord.id,
          status: persistedRecord.status,
          trackingUrl: expect.stringContaining(`/api/v1/invoices/${persistedRecord.id}`),
          acceptedAt: persistedRecord.createdAt.toISOString(),
        })
      );

      expect(repository.saveInvoice).toHaveBeenCalledWith(
        expect.objectContaining({
          invoiceNumber: validInvoice.invoiceNumber,
          status: 'QUEUED',
        })
      );
      expect(publisher.publish).toHaveBeenCalled();
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
      repository.findById.mockResolvedValue(null);

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

      const storedRecord = {
        id: '22222222-2222-2222-2222-222222222222',
        idempotencyKey: mockRequest.idempotencyKey!,
        invoiceNumber: 'INV-002',
        supplierOIB: '12345678901',
        buyerOIB: '10987654321',
        totalAmount: 125,
        currency: 'EUR',
        status: 'QUEUED' as const,
        createdAt: new Date('2025-01-01T00:00:00.000Z'),
        updatedAt: new Date('2025-01-01T00:00:00.000Z'),
      };

      repository.saveInvoice.mockResolvedValue(storedRecord);
      publisher.publish.mockResolvedValue();

      await controller.submitInvoice(mockRequest as Request, mockResponse as Response);

      repository.findById.mockResolvedValue(storedRecord);

      // Reset mocks
      jsonSpy.mockClear();
      statusSpy.mockClear();

      // Now get status
      mockRequest.params = { invoiceId: storedRecord.id };

      await controller.getInvoiceStatus(mockRequest as Request, mockResponse as Response);

      expect(statusSpy).toHaveBeenCalledWith(200);
      expect(jsonSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          invoiceId: storedRecord.id,
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
