/**
 * Mock FINA Service
 * Simulates Croatian Tax Authority submission
 */

import { injectable } from 'injectable';
import {
  IFINAService,
  IPoreznaService,
  FINASubmissionRequest,
  FINASubmissionResponse,
  FINAStatusResponse,
  PoreznaSubmissionResponse,
  MonthlyReport
} from '@eracun/adapters';
import { UBLInvoice, ErrorCode } from '@eracun/contracts';

@injectable()
export class MockFINAService implements IFINAService {
  private submissions = new Map<string, FINAStatusResponse>();

  async submitInvoice(request: FINASubmissionRequest): Promise<FINASubmissionResponse> {
    await this.simulateNetworkDelay(500, 1500);

    // 95% success rate
    const success = Math.random() > 0.05;

    if (success) {
      const jir = this.generateJIR();
      const invoiceId = request.invoice.id;

      // Store status
      this.submissions.set(invoiceId, {
        invoiceId,
        status: 'ACCEPTED',
        jir,
        submittedAt: new Date().toISOString()
      });

      return {
        success: true,
        jir,
        timestamp: new Date().toISOString()
      };
    } else {
      // Simulate rejection
      return {
        success: false,
        error: {
          code: 'FINA_001',
          message: 'Invalid signature',
          details: 'Certificate validation failed'
        }
      };
    }
  }

  async getStatus(invoiceId: string): Promise<FINAStatusResponse> {
    await this.simulateNetworkDelay(100, 300);

    const status = this.submissions.get(invoiceId);

    if (status) {
      return status;
    }

    // Default status if not found
    return {
      invoiceId,
      status: 'PENDING'
    };
  }

  async verifyJIR(jir: string): Promise<boolean> {
    await this.simulateNetworkDelay(200, 400);

    // Check format: 32 alphanumeric characters
    return /^[A-Z0-9]{32}$/.test(jir);
  }

  async healthCheck(): Promise<boolean> {
    await this.simulateNetworkDelay(50, 100);
    // 99% uptime
    return Math.random() > 0.01;
  }

  private generateJIR(): string {
    // Generate mock JIR: 32 character alphanumeric
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let jir = '';
    for (let i = 0; i < 32; i++) {
      jir += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return jir;
  }

  private async simulateNetworkDelay(min: number = 100, max: number = 500): Promise<void> {
    const delay = Math.random() * (max - min) + min;
    return new Promise(resolve => setTimeout(resolve, delay));
  }
}

@injectable()
export class MockPoreznaService implements IPoreznaService {
  async submitInvoice(invoice: UBLInvoice): Promise<PoreznaSubmissionResponse> {
    await this.simulateNetworkDelay(300, 800);

    // 97% success rate
    const success = Math.random() > 0.03;

    if (success) {
      return {
        success: true,
        confirmationNumber: this.generateConfirmationNumber(),
        timestamp: new Date().toISOString()
      };
    } else {
      return {
        success: false,
        error: {
          code: 'POREZNA_001',
          message: 'Invoice already submitted',
          details: 'Duplicate invoice number detected'
        }
      };
    }
  }

  async submitMonthlyReport(report: MonthlyReport): Promise<PoreznaSubmissionResponse> {
    await this.simulateNetworkDelay(500, 1200);

    // 98% success rate
    const success = Math.random() > 0.02;

    if (success) {
      return {
        success: true,
        confirmationNumber: this.generateConfirmationNumber(),
        timestamp: new Date().toISOString()
      };
    } else {
      return {
        success: false,
        error: {
          code: 'POREZNA_002',
          message: 'Report validation failed',
          details: 'VAT amount mismatch'
        }
      };
    }
  }

  async healthCheck(): Promise<boolean> {
    await this.simulateNetworkDelay(50, 100);
    // 99% uptime
    return Math.random() > 0.01;
  }

  private generateConfirmationNumber(): string {
    // Generate mock confirmation: format YYYY-MM-XXXXXXXX
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const random = Math.floor(Math.random() * 100000000).toString().padStart(8, '0');
    return `${year}-${month}-${random}`;
  }

  private async simulateNetworkDelay(min: number = 100, max: number = 500): Promise<void> {
    const delay = Math.random() * (max - min) + min;
    return new Promise(resolve => setTimeout(resolve, delay));
  }
}
