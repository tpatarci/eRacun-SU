import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import request from 'supertest';
import express, { Application } from 'express';
import session from 'express-session';

// Mock all dependencies
jest.mock('../../src/shared/db', () => ({
  initDb: jest.fn(),
  query: jest.fn(),
  getPool: jest.fn().mockReturnValue({
    query: jest.fn().mockResolvedValue({ rows: [{ '?column?': 1 }] }),
  }),
  closePool: jest.fn(),
}));

jest.mock('../../src/shared/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

// Mock bcrypt BEFORE importing auth-related modules
jest.mock('bcrypt', () => ({
  hash: jest.fn().mockResolvedValue('$2b$12$mockhashedpasswordfortesting'),
  compare: jest.fn().mockResolvedValue(true),
}));

// Mock invoice submission job
jest.mock('../../src/jobs/invoice-submission', () => ({
  initializeInvoiceSubmission: jest.fn(),
  submitInvoiceForProcessing: jest.fn(),
  getInvoiceSubmissionService: jest.fn().mockReturnValue({
    shutdown: jest.fn().mockResolvedValue(undefined),
  }),
}));

import { query } from '../../src/shared/db.js';
import { validationMiddleware } from '../../src/api/middleware/validate.js';
import { requestIdMiddleware, errorHandler } from '../../src/api/app.js';
import { authMiddleware, type AuthenticatedRequest, generateSessionToken } from '../../src/shared/auth.js';
import { loginSchema } from '../../src/api/schemas.js';
import { invoiceSubmissionSchema } from '../../src/api/schemas.js';
import type { User } from '../../src/shared/types.js';

// Mock query function with proper typing
const mockQuery = query as jest.MockedFunction<typeof query>;

describe('Multi-User Invoice Flow E2E Tests (Mocked)', () => {
  let app: Application;
  const mockUsers: Map<string, User> = new Map();
  const mockUserConfigs: Map<string, Map<string, Record<string, unknown>>> = new Map();
  const mockInvoices: Map<string, Array<{ id: string; userId: string; oib: string; invoiceNumber: string }>> = new Map();

  // Test user data
  const userA: User = {
    id: '550e8400-e29b-41d4-a716-446655440001',
    email: 'usera@example.com',
    passwordHash: '$2b$12$mockhashedpasswordfortesting',
    name: 'User A',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const userB: User = {
    id: '550e8400-e29b-41d4-a716-446655440002',
    email: 'userb@example.com',
    passwordHash: '$2b$12$mockhashedpasswordfortesting',
    name: 'User B',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // Mock login handler
  const mockLoginHandler = async (req: any, res: any) => {
    const { email, password } = req.body;

    const foundUser = Array.from(mockUsers.values()).find(u => u.email === email);

    if (!foundUser || password !== 'TestPassword123!') {
      res.status(401).json({
        error: 'Invalid credentials',
        message: 'Email or password is incorrect',
        requestId: req.id,
      });
      return;
    }

    const token = generateSessionToken();

    if (req.session) {
      req.session.userId = foundUser.id;
      req.session.email = foundUser.email;
      req.session.token = token;
    }

    res.json({
      user: {
        id: foundUser.id,
        email: foundUser.email,
        name: foundUser.name || undefined,
      },
      token: req.sessionID || token,
    });
  };

  // Mock get configs handler
  const mockGetConfigsHandler = async (req: AuthenticatedRequest, res: any) => {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required',
        requestId: req.id,
      });
      return;
    }

    const configs = mockUserConfigs.get(userId) || new Map();
    const configMap: Record<string, Record<string, unknown>> = {};
    for (const [serviceName, config] of configs.entries()) {
      configMap[serviceName] = config;
    }

    res.json({ configs: configMap });
  };

  // Mock update config handler
  const mockUpdateConfigHandler = async (req: AuthenticatedRequest, res: any) => {
    const userId = req.user?.id;
    const { service } = req.params;

    if (!userId) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required',
        requestId: req.id,
      });
      return;
    }

    if (service !== 'fina' && service !== 'imap') {
      res.status(400).json({
        error: 'Invalid service name',
        message: 'Service must be either "fina" or "imap"',
        requestId: req.id,
      });
      return;
    }

    if (!mockUserConfigs.has(userId)) {
      mockUserConfigs.set(userId, new Map());
    }

    mockUserConfigs.get(userId)!.set(service, req.body);

    res.json({
      serviceName: service,
      config: req.body,
      updatedAt: new Date().toISOString(),
    });
  };

  // Mock invoice submission handler
  const mockSubmitInvoiceHandler = async (req: AuthenticatedRequest, res: any) => {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required',
        requestId: req.id,
      });
      return;
    }

    // Check if user has FINA config
    const userConfigs = mockUserConfigs.get(userId);
    if (!userConfigs || !userConfigs.has('fina')) {
      res.status(400).json({
        error: 'FINA configuration required',
        message: 'Please configure your FINA credentials before submitting invoices',
        requestId: req.id,
      });
      return;
    }

    // Create invoice
    const invoice = {
      id: `inv-${Date.now()}-${Math.random().toString(36).substring(7)}`,
      userId,
      oib: req.body.oib,
      invoiceNumber: req.body.invoiceNumber,
      status: 'queued',
      createdAt: new Date().toISOString(),
    };

    if (!mockInvoices.has(userId)) {
      mockInvoices.set(userId, []);
    }
    mockInvoices.get(userId)!.push(invoice);

    res.status(202).json({
      invoiceId: invoice.id,
      jobId: `job-${invoice.id}`,
      status: 'queued',
    });
  };

  // Mock get invoice handler
  const mockGetInvoiceHandler = async (req: AuthenticatedRequest, res: any) => {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required',
        requestId: req.id,
      });
      return;
    }

    const invoiceId = req.params.id;
    const userInvoices = mockInvoices.get(userId) || [];
    const invoice = userInvoices.find(inv => inv.id === invoiceId);

    if (!invoice) {
      res.status(404).json({
        error: 'Invoice not found',
        requestId: req.id,
      });
      return;
    }

    res.json(invoice);
  };

  // Mock get all invoices handler
  const mockGetInvoicesHandler = async (req: AuthenticatedRequest, res: any) => {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required',
        requestId: req.id,
      });
      return;
    }

    const userInvoices = mockInvoices.get(userId) || [];
    res.json({ invoices: userInvoices });
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockUsers.clear();
    mockUserConfigs.clear();
    mockInvoices.clear();

    // Setup test users
    mockUsers.set(userA.id, userA);
    mockUsers.set(userB.id, userB);

    // Mock query to simulate database operations
    mockQuery.mockImplementation((text: string, params?: any[]) => {
      if (text.includes('SELECT * FROM users WHERE email')) {
        const email = params?.[0];
        const foundUser = Array.from(mockUsers.values()).find(u => u.email === email);
        return Promise.resolve({ rows: foundUser ? [foundUser] : [] });
      }
      if (text.includes('SELECT * FROM users WHERE id')) {
        const id = params?.[0];
        const user = mockUsers.get(id);
        return Promise.resolve({ rows: user ? [user] : [] });
      }
      if (text.includes('SELECT * FROM user_configurations WHERE user_id')) {
        const userId = params?.[0];
        const configs = mockUserConfigs.get(userId) || new Map();
        const rows = Array.from(configs.entries()).map(([serviceName, config]) => ({
          serviceName,
          config,
        }));
        return Promise.resolve({ rows });
      }
      return Promise.resolve({ rows: [] });
    });

    // Create Express app for testing
    app = express();
    app.use(express.json());
    app.use(requestIdMiddleware);

    // Setup session middleware for testing
    app.use(session({
      secret: 'test-secret-key',
      resave: false,
      saveUninitialized: false,
      name: 'eracun.sid',
      cookie: {
        httpOnly: true,
        secure: false,
        maxAge: 24 * 60 * 60 * 1000,
      },
    }));

    // Setup routes
    app.post('/api/v1/auth/login',
      validationMiddleware(loginSchema),
      mockLoginHandler
    );

    app.get('/api/v1/users/me/config', authMiddleware, mockGetConfigsHandler);
    app.put('/api/v1/users/me/config/:service', authMiddleware, mockUpdateConfigHandler);

    app.post('/api/v1/invoices',
      validationMiddleware(invoiceSubmissionSchema),
      authMiddleware,
      mockSubmitInvoiceHandler
    );

    app.get('/api/v1/invoices/:id', authMiddleware, mockGetInvoiceHandler);
    app.get('/api/v1/invoices', authMiddleware, mockGetInvoicesHandler);

    app.use(errorHandler);
  });

  describe('Multi-User Invoice Submission Flow', () => {
    const validInvoiceData = {
      oib: '12345678903',
      invoiceNumber: 'TEST-001',
      amount: '1250.00',
      paymentMethod: 'T',
      businessPremises: 'PP1',
      cashRegister: '1',
      dateTime: '2026-02-09T10:30:00Z',
      originalXml: '<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"><ID>TEST-001</ID></Invoice>',
      signedXml: '<SignedInvoice><SignatureValue>abc123</SignatureValue></SignedInvoice>',
    };

    const userAFinaConfig = {
      wsdlUrl: 'https://fina-a.example.com/wsdl',
      certPath: '/certs/usera.p12',
      certPassphrase: 'UserA_Pass_123',
    };

    const userBFinaConfig = {
      wsdlUrl: 'https://fina-b.example.com/wsdl',
      certPath: '/certs/userb.p12',
      certPassphrase: 'UserB_Pass_456',
    };

    it('should allow two users to configure different FINA credentials', async () => {
      const agentA = request.agent(app);
      const agentB = request.agent(app);

      // Login as User A
      await agentA
        .post('/api/v1/auth/login')
        .send({
          email: 'usera@example.com',
          password: 'TestPassword123!',
        })
        .expect(200);

      // Configure User A's FINA credentials
      await agentA
        .put('/api/v1/users/me/config/fina')
        .send(userAFinaConfig)
        .expect(200);

      // Verify User A's config
      const configAResponse = await agentA
        .get('/api/v1/users/me/config')
        .expect(200);

      expect(configAResponse.body.configs.fina).toMatchObject(userAFinaConfig);

      // Login as User B
      await agentB
        .post('/api/v1/auth/login')
        .send({
          email: 'userb@example.com',
          password: 'TestPassword123!',
        })
        .expect(200);

      // Configure User B's FINA credentials
      await agentB
        .put('/api/v1/users/me/config/fina')
        .send(userBFinaConfig)
        .expect(200);

      // Verify User B's config
      const configBResponse = await agentB
        .get('/api/v1/users/me/config')
        .expect(200);

      expect(configBResponse.body.configs.fina).toMatchObject(userBFinaConfig);

      // Verify configs are different
      expect(configAResponse.body.configs.fina.wsdlUrl).not.toBe(
        configBResponse.body.configs.fina.wsdlUrl
      );
      expect(configAResponse.body.configs.fina.certPath).not.toBe(
        configBResponse.body.configs.fina.certPath
      );
    });

    it('should allow both users to submit invoices independently', async () => {
      const agentA = request.agent(app);
      const agentB = request.agent(app);

      // Login and configure User A
      await agentA
        .post('/api/v1/auth/login')
        .send({
          email: 'usera@example.com',
          password: 'TestPassword123!',
        })
        .expect(200);

      await agentA
        .put('/api/v1/users/me/config/fina')
        .send(userAFinaConfig)
        .expect(200);

      // Login and configure User B
      await agentB
        .post('/api/v1/auth/login')
        .send({
          email: 'userb@example.com',
          password: 'TestPassword123!',
        })
        .expect(200);

      await agentB
        .put('/api/v1/users/me/config/fina')
        .send(userBFinaConfig)
        .expect(200);

      // User A submits invoice
      const invoiceAResponse = await agentA
        .post('/api/v1/invoices')
        .send({
          ...validInvoiceData,
          invoiceNumber: 'INV-A-001',
        })
        .expect(202);

      expect(invoiceAResponse.body).toMatchObject({
        invoiceId: expect.any(String),
        jobId: expect.any(String),
        status: 'queued',
      });

      const invoiceAId = invoiceAResponse.body.invoiceId;

      // User B submits invoice
      const invoiceBResponse = await agentB
        .post('/api/v1/invoices')
        .send({
          ...validInvoiceData,
          invoiceNumber: 'INV-B-001',
        })
        .expect(202);

      expect(invoiceBResponse.body).toMatchObject({
        invoiceId: expect.any(String),
        jobId: expect.any(String),
        status: 'queued',
      });

      const invoiceBId = invoiceBResponse.body.invoiceId;

      // Verify both invoices have different IDs
      expect(invoiceAId).not.toBe(invoiceBId);
    });

    it('should enforce data isolation: User A cannot access User B invoices', async () => {
      const agentA = request.agent(app);
      const agentB = request.agent(app);

      // Login and configure User A
      await agentA
        .post('/api/v1/auth/login')
        .send({
          email: 'usera@example.com',
          password: 'TestPassword123!',
        })
        .expect(200);

      await agentA
        .put('/api/v1/users/me/config/fina')
        .send(userAFinaConfig)
        .expect(200);

      // Login and configure User B
      await agentB
        .post('/api/v1/auth/login')
        .send({
          email: 'userb@example.com',
          password: 'TestPassword123!',
        })
        .expect(200);

      await agentB
        .put('/api/v1/users/me/config/fina')
        .send(userBFinaConfig)
        .expect(200);

      // User B submits an invoice
      const invoiceBResponse = await agentB
        .post('/api/v1/invoices')
        .send({
          ...validInvoiceData,
          invoiceNumber: 'INV-B-SECRET',
        })
        .expect(202);

      const invoiceBId = invoiceBResponse.body.invoiceId;

      // User A tries to access User B's invoice
      const unauthorizedResponse = await agentA
        .get(`/api/v1/invoices/${invoiceBId}`)
        .expect(404);

      expect(unauthorizedResponse.body).toMatchObject({
        error: 'Invoice not found',
        requestId: expect.any(String),
      });

      // User B can still access their own invoice
      const authorizedResponse = await agentB
        .get(`/api/v1/invoices/${invoiceBId}`)
        .expect(200);

      expect(authorizedResponse.body.id).toBe(invoiceBId);
      expect(authorizedResponse.body.invoiceNumber).toBe('INV-B-SECRET');
    });

    it('should enforce data isolation: User B cannot access User A invoices', async () => {
      const agentA = request.agent(app);
      const agentB = request.agent(app);

      // Login and configure User A
      await agentA
        .post('/api/v1/auth/login')
        .send({
          email: 'usera@example.com',
          password: 'TestPassword123!',
        })
        .expect(200);

      await agentA
        .put('/api/v1/users/me/config/fina')
        .send(userAFinaConfig)
        .expect(200);

      // Login and configure User B
      await agentB
        .post('/api/v1/auth/login')
        .send({
          email: 'userb@example.com',
          password: 'TestPassword123!',
        })
        .expect(200);

      await agentB
        .put('/api/v1/users/me/config/fina')
        .send(userBFinaConfig)
        .expect(200);

      // User A submits an invoice
      const invoiceAResponse = await agentA
        .post('/api/v1/invoices')
        .send({
          ...validInvoiceData,
          invoiceNumber: 'INV-A-SECRET',
        })
        .expect(202);

      const invoiceAId = invoiceAResponse.body.invoiceId;

      // User B tries to access User A's invoice
      const unauthorizedResponse = await agentB
        .get(`/api/v1/invoices/${invoiceAId}`)
        .expect(404);

      expect(unauthorizedResponse.body).toMatchObject({
        error: 'Invoice not found',
        requestId: expect.any(String),
      });

      // User A can still access their own invoice
      const authorizedResponse = await agentA
        .get(`/api/v1/invoices/${invoiceAId}`)
        .expect(200);

      expect(authorizedResponse.body.id).toBe(invoiceAId);
      expect(authorizedResponse.body.invoiceNumber).toBe('INV-A-SECRET');
    });

    it('should return only user-specific invoices from list endpoint', async () => {
      const agentA = request.agent(app);
      const agentB = request.agent(app);

      // Login and configure User A
      await agentA
        .post('/api/v1/auth/login')
        .send({
          email: 'usera@example.com',
          password: 'TestPassword123!',
        })
        .expect(200);

      await agentA
        .put('/api/v1/users/me/config/fina')
        .send(userAFinaConfig)
        .expect(200);

      // Login and configure User B
      await agentB
        .post('/api/v1/auth/login')
        .send({
          email: 'userb@example.com',
          password: 'TestPassword123!',
        })
        .expect(200);

      await agentB
        .put('/api/v1/users/me/config/fina')
        .send(userBFinaConfig)
        .expect(200);

      // User A submits 3 invoices
      for (let i = 1; i <= 3; i++) {
        await agentA
          .post('/api/v1/invoices')
          .send({
            ...validInvoiceData,
            invoiceNumber: `INV-A-${String(i).padStart(3, '0')}`,
          })
          .expect(202);
      }

      // User B submits 2 invoices
      for (let i = 1; i <= 2; i++) {
        await agentB
          .post('/api/v1/invoices')
          .send({
            ...validInvoiceData,
            invoiceNumber: `INV-B-${String(i).padStart(3, '0')}`,
          })
          .expect(202);
      }

      // User A should see only their 3 invoices
      const listAResponse = await agentA
        .get('/api/v1/invoices')
        .expect(200);

      expect(listAResponse.body.invoices).toHaveLength(3);
      expect(listAResponse.body.invoices.every(
        (inv: any) => inv.invoiceNumber.startsWith('INV-A-')
      )).toBe(true);

      // User B should see only their 2 invoices
      const listBResponse = await agentB
        .get('/api/v1/invoices')
        .expect(200);

      expect(listBResponse.body.invoices).toHaveLength(2);
      expect(listBResponse.body.invoices.every(
        (inv: any) => inv.invoiceNumber.startsWith('INV-B-')
      )).toBe(true);
    });

    it('should reject invoice submission without FINA configuration', async () => {
      const agent = request.agent(app);

      // Login without configuring FINA
      await agent
        .post('/api/v1/auth/login')
        .send({
          email: 'usera@example.com',
          password: 'TestPassword123!',
        })
        .expect(200);

      // Try to submit invoice
      const response = await agent
        .post('/api/v1/invoices')
        .send(validInvoiceData)
        .expect(400);

      expect(response.body).toMatchObject({
        error: 'FINA configuration required',
        message: 'Please configure your FINA credentials before submitting invoices',
        requestId: expect.any(String),
      });
    });

    it('should handle concurrent invoice submissions from different users', async () => {
      const agentA = request.agent(app);
      const agentB = request.agent(app);

      // Login and configure both users
      await agentA
        .post('/api/v1/auth/login')
        .send({
          email: 'usera@example.com',
          password: 'TestPassword123!',
        })
        .expect(200);

      await agentA
        .put('/api/v1/users/me/config/fina')
        .send(userAFinaConfig)
        .expect(200);

      await agentB
        .post('/api/v1/auth/login')
        .send({
          email: 'userb@example.com',
          password: 'TestPassword123!',
        })
        .expect(200);

      await agentB
        .put('/api/v1/users/me/config/fina')
        .send(userBFinaConfig)
        .expect(200);

      // Submit invoices concurrently
      const [responseA, responseB] = await Promise.all([
        agentA
          .post('/api/v1/invoices')
          .send({
            ...validInvoiceData,
            invoiceNumber: `INV-A-${Date.now()}`,
          })
          .expect(202),
        agentB
          .post('/api/v1/invoices')
          .send({
            ...validInvoiceData,
            invoiceNumber: `INV-B-${Date.now()}`,
          })
          .expect(202),
      ]);

      expect(responseA.body.status).toBe('queued');
      expect(responseB.body.status).toBe('queued');
      expect(responseA.body.invoiceId).not.toBe(responseB.body.invoiceId);
    });

    it('should allow same invoice number for different users', async () => {
      const agentA = request.agent(app);
      const agentB = request.agent(app);

      // Login and configure both users
      await agentA
        .post('/api/v1/auth/login')
        .send({
          email: 'usera@example.com',
          password: 'TestPassword123!',
        })
        .expect(200);

      await agentA
        .put('/api/v1/users/me/config/fina')
        .send(userAFinaConfig)
        .expect(200);

      await agentB
        .post('/api/v1/auth/login')
        .send({
          email: 'userb@example.com',
          password: 'TestPassword123!',
        })
        .expect(200);

      await agentB
        .put('/api/v1/users/me/config/fina')
        .send(userBFinaConfig)
        .expect(200);

      // Both users submit invoices with the same number
      const invoiceNumber = 'DUPLICATE-001';

      const responseA = await agentA
        .post('/api/v1/invoices')
        .send({
          ...validInvoiceData,
          invoiceNumber,
        })
        .expect(202);

      const responseB = await agentB
        .post('/api/v1/invoices')
        .send({
          ...validInvoiceData,
          invoiceNumber,
        })
        .expect(202);

      expect(responseA.body.status).toBe('queued');
      expect(responseB.body.status).toBe('queued');
      expect(responseA.body.invoiceId).not.toBe(responseB.body.invoiceId);

      // Both users should be able to retrieve their invoice with the same number
      const invoicesA = await agentA.get('/api/v1/invoices').expect(200);
      const invoicesB = await agentB.get('/api/v1/invoices').expect(200);

      expect(invoicesA.body.invoices).toHaveLength(1);
      expect(invoicesB.body.invoices).toHaveLength(1);
      expect(invoicesA.body.invoices[0].invoiceNumber).toBe(invoiceNumber);
      expect(invoicesB.body.invoices[0].invoiceNumber).toBe(invoiceNumber);
    });
  });

  describe('Multi-User Configuration Isolation', () => {
    it('should prevent users from accessing other users configurations', async () => {
      const agentA = request.agent(app);
      const agentB = request.agent(app);

      // User A configures FINA
      await agentA
        .post('/api/v1/auth/login')
        .send({
          email: 'usera@example.com',
          password: 'TestPassword123!',
        })
        .expect(200);

      await agentA
        .put('/api/v1/users/me/config/fina')
        .send({
          wsdlUrl: 'https://secret-fina.example.com',
          certPath: '/certs/secret.p12',
          certPassphrase: 'SecretPass123',
        })
        .expect(200);

      // User B logs in and should not see User A's config
      await agentB
        .post('/api/v1/auth/login')
        .send({
          email: 'userb@example.com',
          password: 'TestPassword123!',
        })
        .expect(200);

      const configBResponse = await agentB
        .get('/api/v1/users/me/config')
        .expect(200);

      expect(configBResponse.body.configs).not.toHaveProperty('fina');
    });
  });
});
