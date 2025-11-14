"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const index_1 = require("../../src/index");
describe('AIValidationService', () => {
    let service;
    beforeEach(() => {
        service = new index_1.AIValidationService();
    });
    it('should validate a normal invoice', async () => {
        const invoice = {
            invoiceNumber: 'INV-2025-001',
            issuerOIB: '12345678901',
            recipientOIB: '10987654321',
            issueDate: new Date('2025-11-14'),
            dueDate: new Date('2025-12-14'),
            currency: 'EUR',
            totalAmount: 1000,
            vatAmount: 250,
            lineItems: []
        };
        const result = await service.validateInvoice(invoice);
        expect(result).toHaveProperty('valid');
        expect(result).toHaveProperty('anomalies');
        expect(result).toHaveProperty('riskScore');
        expect(typeof result.valid).toBe('boolean');
        expect(Array.isArray(result.anomalies)).toBe(true);
        expect(typeof result.riskScore).toBe('number');
    });
});
