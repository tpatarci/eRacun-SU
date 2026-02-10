/**
 * Bank API Mock Service
 * Production-grade mock for Croatian banking API
 *
 * Features:
 * - IBAN validation (Croatian format)
 * - Account verification
 * - Transaction queries
 * - Payment status checks
 * - MT940 statement generation
 * - Realistic delays and responses
 */

import express from 'express';
import bodyParser from 'body-parser';
import winston from 'winston';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';

interface BankAccount {
  iban: string;
  accountNumber: string;
  accountHolder: string;
  oib: string;
  balance: number;
  currency: 'HRK' | 'EUR';
  status: 'active' | 'blocked' | 'closed';
}

interface Transaction {
  id: string;
  fromIban: string;
  toIban: string;
  amount: number;
  currency: string;
  purpose: string;
  reference: string;
  status: 'pending' | 'completed' | 'failed';
  executedAt?: Date;
  createdAt: Date;
}

interface MockConfig {
  port: number;
  simulateDelays: boolean;
  latency: { min: number; max: number };
}

class BankMockService {
  private app: express.Application;
  private config: MockConfig;
  private logger: winston.Logger;
  private accounts: Map<string, BankAccount> = new Map();
  private transactions: Map<string, Transaction> = new Map();
  private metrics: {
    requests: number;
    validations: number;
    transactions: number;
    startTime: Date;
  };

  constructor(config: Partial<MockConfig> = {}) {
    this.app = express();
    this.config = {
      port: config.port || 8452,
      simulateDelays: config.simulateDelays ?? true,
      latency: config.latency || { min: 200, max: 1000 }
    };

    this.metrics = {
      requests: 0,
      validations: 0,
      transactions: 0,
      startTime: new Date()
    };

    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        }),
        new winston.transports.File({ filename: 'bank-mock.log' })
      ]
    });

    this.app.use(bodyParser.json());
    this.setupRoutes();
    this.generateSampleAccounts();
  }

  private setupRoutes(): void {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'operational',
        accounts: this.accounts.size,
        transactions: this.transactions.size,
        uptime: Date.now() - this.metrics.startTime.getTime(),
        metrics: this.metrics
      });
    });

    // Validate IBAN
    this.app.post('/api/v1/validate/iban', async (req, res) => {
      await this.applyLatency();
      this.metrics.requests++;
      this.metrics.validations++;

      const { iban } = req.body;
      if (!iban) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'IBAN is required'
        });
      }

      const validation = this.validateIBAN(iban);
      res.json(validation);
    });

    // Get account info
    this.app.get('/api/v1/accounts/:iban', async (req, res) => {
      await this.applyLatency();
      this.metrics.requests++;

      const account = this.accounts.get(req.params.iban);
      if (!account) {
        return res.status(404).json({
          error: 'ACCOUNT_NOT_FOUND',
          message: 'Account not found'
        });
      }

      res.json({
        iban: account.iban,
        accountHolder: account.accountHolder,
        currency: account.currency,
        status: account.status
        // Don't expose balance in public API
      });
    });

    // Get account balance (requires authentication)
    this.app.get('/api/v1/accounts/:iban/balance', async (req, res) => {
      await this.applyLatency();
      this.metrics.requests++;

      const account = this.accounts.get(req.params.iban);
      if (!account) {
        return res.status(404).json({
          error: 'ACCOUNT_NOT_FOUND',
          message: 'Account not found'
        });
      }

      res.json({
        iban: account.iban,
        balance: account.balance,
        currency: account.currency,
        asOf: new Date().toISOString()
      });
    });

    // Get transactions
    this.app.get('/api/v1/accounts/:iban/transactions', async (req, res) => {
      await this.applyLatency();
      this.metrics.requests++;

      const account = this.accounts.get(req.params.iban);
      if (!account) {
        return res.status(404).json({
          error: 'ACCOUNT_NOT_FOUND',
          message: 'Account not found'
        });
      }

      const from = req.query.from ? new Date(req.query.from as string) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const to = req.query.to ? new Date(req.query.to as string) : new Date();

      const transactions = Array.from(this.transactions.values())
        .filter(t =>
          (t.fromIban === account.iban || t.toIban === account.iban) &&
          t.createdAt >= from &&
          t.createdAt <= to
        )
        .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

      res.json({
        iban: account.iban,
        from: from.toISOString(),
        to: to.toISOString(),
        count: transactions.length,
        transactions
      });
    });

    // Create payment
    this.app.post('/api/v1/payments', async (req, res) => {
      await this.applyLatency();
      this.metrics.requests++;
      this.metrics.transactions++;

      const { fromIban, toIban, amount, currency, purpose, reference } = req.body;

      if (!fromIban || !toIban || !amount) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'fromIban, toIban, and amount are required'
        });
      }

      const fromAccount = this.accounts.get(fromIban);
      if (!fromAccount) {
        return res.status(404).json({
          error: 'ACCOUNT_NOT_FOUND',
          message: 'Source account not found'
        });
      }

      if (fromAccount.balance < amount) {
        return res.status(400).json({
          error: 'INSUFFICIENT_FUNDS',
          message: 'Insufficient funds'
        });
      }

      const transaction: Transaction = {
        id: uuidv4(),
        fromIban,
        toIban,
        amount,
        currency: currency || fromAccount.currency,
        purpose: purpose || '',
        reference: reference || '',
        status: 'pending',
        createdAt: new Date()
      };

      this.transactions.set(transaction.id, transaction);

      // Simulate async processing
      setTimeout(() => {
        transaction.status = 'completed';
        transaction.executedAt = new Date();
        fromAccount.balance -= amount;

        const toAccount = this.accounts.get(toIban);
        if (toAccount) {
          toAccount.balance += amount;
        }

        this.logger.info(`Transaction ${transaction.id} completed`);
      }, 2000);

      res.status(202).json({
        transactionId: transaction.id,
        status: 'accepted',
        estimatedCompletionTime: new Date(Date.now() + 2000).toISOString(),
        statusUrl: `/api/v1/transactions/${transaction.id}`
      });
    });

    // Get transaction status
    this.app.get('/api/v1/transactions/:id', async (req, res) => {
      await this.applyLatency();
      this.metrics.requests++;

      const transaction = this.transactions.get(req.params.id);
      if (!transaction) {
        return res.status(404).json({
          error: 'TRANSACTION_NOT_FOUND',
          message: 'Transaction not found'
        });
      }

      res.json(transaction);
    });

    // Generate MT940 statement
    this.app.get('/api/v1/accounts/:iban/statement/mt940', async (req, res) => {
      await this.applyLatency();
      this.metrics.requests++;

      const account = this.accounts.get(req.params.iban);
      if (!account) {
        return res.status(404).json({
          error: 'ACCOUNT_NOT_FOUND',
          message: 'Account not found'
        });
      }

      const from = req.query.from ? new Date(req.query.from as string) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const to = req.query.to ? new Date(req.query.to as string) : new Date();

      const transactions = Array.from(this.transactions.values())
        .filter(t =>
          (t.fromIban === account.iban || t.toIban === account.iban) &&
          t.createdAt >= from &&
          t.createdAt <= to
        );

      const mt940 = this.generateMT940(account, transactions, from, to);

      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Content-Disposition', `attachment; filename="statement_${account.iban}_${from.toISOString().split('T')[0]}.mt940"`);
      res.send(mt940);
    });
  }

  private validateIBAN(iban: string): any {
    iban = iban.replace(/\s/g, '').toUpperCase();

    // Croatian IBAN: HR + 2 check digits + 17 digits
    const croatianIbanRegex = /^HR\d{19}$/;

    if (!croatianIbanRegex.test(iban)) {
      return {
        valid: false,
        iban,
        error: 'Invalid Croatian IBAN format',
        format: 'Expected: HRxx-xxxx-xxxx-xxxx-xxxx-x (21 characters)'
      };
    }

    // Validate checksum
    const rearranged = iban.slice(4) + iban.slice(0, 4);
    const numericIban = rearranged.replace(/[A-Z]/g, char =>
      (char.charCodeAt(0) - 55).toString()
    );

    const remainder = BigInt(numericIban) % 97n;
    const checksumValid = remainder === 1n;

    if (!checksumValid) {
      return {
        valid: false,
        iban,
        error: 'Invalid IBAN checksum'
      };
    }

    return {
      valid: true,
      iban,
      country: 'HR',
      bankCode: iban.slice(4, 11),
      accountNumber: iban.slice(11),
      formatted: `${iban.slice(0, 4)}-${iban.slice(4, 8)}-${iban.slice(8, 12)}-${iban.slice(12, 16)}-${iban.slice(16, 20)}-${iban.slice(20)}`
    };
  }

  private generateMT940(account: BankAccount, transactions: Transaction[], from: Date, to: Date): string {
    const statementNumber = Math.floor(Math.random() * 999) + 1;
    const sequenceNumber = 1;

    let mt940 = '';
    mt940 += `:20:${statementNumber}/${sequenceNumber}\n`;
    mt940 += `:25:${account.iban}\n`;
    mt940 += `:28C:${statementNumber}/${sequenceNumber}\n`;
    mt940 += `:60F:C${this.formatMT940Date(from)}${account.currency}${this.formatAmount(account.balance)}\n`;

    for (const tx of transactions) {
      const isCredit = tx.toIban === account.iban;
      const dcMark = isCredit ? 'C' : 'D';
      const date = tx.executedAt || tx.createdAt;

      mt940 += `:61:${this.formatMT940Date(date)}${dcMark}${this.formatAmount(tx.amount)}NTRF${tx.reference || 'NOTPROVIDED'}\n`;
      mt940 += `:86:${tx.purpose || 'Payment'}\n`;
    }

    const closingBalance = account.balance;
    mt940 += `:62F:C${this.formatMT940Date(to)}${account.currency}${this.formatAmount(closingBalance)}\n`;

    return mt940;
  }

  private formatMT940Date(date: Date): string {
    const yy = date.getFullYear().toString().slice(-2);
    const mm = (date.getMonth() + 1).toString().padStart(2, '0');
    const dd = date.getDate().toString().padStart(2, '0');
    return `${yy}${mm}${dd}`;
  }

  private formatAmount(amount: number): string {
    return amount.toFixed(2).replace('.', ',');
  }

  private generateSampleAccounts(): void {
    const sampleAccounts: BankAccount[] = [
      {
        iban: 'HR1210010051863000160',
        accountNumber: '1863000160',
        accountHolder: 'Test Company d.o.o.',
        oib: '12345678903',
        balance: 100000.00,
        currency: 'EUR',
        status: 'active'
      },
      {
        iban: 'HR6623400091110000123',
        accountNumber: '1110000123',
        accountHolder: 'Demo Ltd.',
        oib: '98765432109',
        balance: 50000.00,
        currency: 'EUR',
        status: 'active'
      }
    ];

    for (const account of sampleAccounts) {
      this.accounts.set(account.iban, account);
    }

    this.logger.info(`Generated ${this.accounts.size} sample bank accounts`);
  }

  private async applyLatency(): Promise<void> {
    if (!this.config.simulateDelays) return;

    const { min, max } = this.config.latency;
    const delay = Math.floor(Math.random() * (max - min + 1)) + min;
    await new Promise(resolve => setTimeout(resolve, delay));
  }

  public start(): void {
    this.app.listen(this.config.port, () => {
      this.logger.info(`Bank Mock Service started on port ${this.config.port}`);
      this.logger.info(`Simulate delays: ${this.config.simulateDelays}`);
    });
  }
}

// Start the service
if (require.main === module) {
  const config: Partial<MockConfig> = {
    port: parseInt(process.env.BANK_PORT || '8452'),
    simulateDelays: process.env.SIMULATE_DELAYS !== 'false'
  };

  const service = new BankMockService(config);
  service.start();
}

export { BankMockService, MockConfig, BankAccount, Transaction };
