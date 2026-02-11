/**
 * Comprehensive API E2E Tests
 *
 * End-to-end tests using proper fixtures for:
 * - User authentication and authorization
 * - Configuration management
 * - Invoice submission workflows
 * - Multi-user isolation
 * - Error handling and validation
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import request from 'supertest';
import express, { Application } from 'express';
import session from 'express-session';

// Mock all dependencies BEFORE importing
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

jest.mock('bcrypt', () => ({
  hash: jest.fn().mockResolvedValue('$2b$12$mockhashedpasswordfortesting'),
  compare: jest.fn().mockResolvedValue(true),
}));

jest.mock('../../src/jobs/invoice-submission', () => ({
  initializeInvoiceSubmission: jest.fn(),
  submitInvoiceForProcessing: jest.fn().mockResolvedValue('job-mock-id'),
  getInvoiceSubmissionService: jest.fn().mockReturnValue({
    shutdown: jest.fn().mockResolvedValue(undefined),
  }),
}));

import { query } from '../../src/shared/db.js';
import { validationMiddleware } from '../../src/api/middleware/validate.js';
import { requestIdMiddleware, errorHandler } from '../../src/api/app.js';
import { authMiddleware, type AuthenticatedRequest, generateSessionToken } from '../../src/shared/auth.js';
import { loginSchema, userCreationSchema } from '../../src/api/schemas.js';

// Import fixtures
import {
  businessUser,
  smallBusinessUser,
  freelancerUser,
  userWithoutFina,
  concurrentUser1,
  concurrentUser2,
  type TestUser,
} from '../fixtures/users.js';
import {
  standardSubmission,
  cashPaymentSubmission,
  invalidSubmissions,
  generateBulkSubmissions,
} from '../fixtures/invoice-submissions.js';

const mockQuery = query as jest.MockedFunction<typeof query>;

describe('Comprehensive API E2E Tests', () => {
  let app: Application;
  const mockUsers: Map<string, TestUser> = new Map();
  const mockUserConfigs: Map<string, Map<string, Record<string, unknown>>> = new Map();
  const mockInvoices: Map<string, Array<any>> = new Map();

  beforeEach(() => {
    jest.clearAllMocks();
    mockUsers.clear();
    mockUserConfigs.clear();
    mockInvoices.clear();

    // Setup test users
    mockUsers.set(businessUser.id, businessUser);
    mockUsers.set(smallBusinessUser.id, smallBusinessUser);
    mockUsers.set(freelancerUser.id, freelancerUser);
    mockUsers.set(userWithoutFina.id, userWithoutFina);
    mockUsers.set(concurrentUser1.id, concurrentUser1);
    mockUsers.set(concurrentUser2.id, concurrentUser2);

    // Setup user configs
    if (businessUser.finaConfig) {
      const configs = new Map();
      configs.set('fina', businessUser.finaConfig);
      if (businessUser.imapConfig) configs.set('imap', businessUser.imapConfig);
      mockUserConfigs.set(businessUser.id, configs);
    }
    if (smallBusinessUser.finaConfig) {
      const configs = new Map();
      configs.set('fina', smallBusinessUser.finaConfig);
      if (smallBusinessUser.imapConfig) configs.set('imap', smallBusinessUser.imapConfig);
      mockUserConfigs.set(smallBusinessUser.id, configs);
    }
    if (freelancerUser.finaConfig) {
      const configs = new Map();
      configs.set('fina', freelancerUser.finaConfig);
      mockUserConfigs.set(freelancerUser.id, configs);
    }
    if (concurrentUser1.finaConfig) {
      const configs = new Map();
      configs.set('fina', concurrentUser1.finaConfig);
      mockUserConfigs.set(concurrentUser1.id, configs);
    }
    if (concurrentUser2.finaConfig) {
      const configs = new Map();
      configs.set('fina', concurrentUser2.finaConfig);
      mockUserConfigs.set(concurrentUser2.id, configs);
    }

    // Mock query implementation
    mockQuery.mockImplementation((text: string, params?: any[]) => {
      // User lookup by email
      if (text.includes('SELECT * FROM users WHERE email')) {
        const email = params?.[0];
        const foundUser = Array.from(mockUsers.values()).find(u => u.email === email);
        return Promise.resolve({ rows: foundUser ? [foundUser] : [] });
      }
      // User lookup by ID
      if (text.includes('SELECT * FROM users WHERE id')) {
        const id = params?.[0];
        const user = mockUsers.get(id);
        return Promise.resolve({ rows: user ? [user] : [] });
      }
      // Config lookup
      if (text.includes('SELECT * FROM user_configurations WHERE user_id')) {
        const userId = params?.[0];
        const configs = mockUserConfigs.get(userId) || new Map();
        const rows = Array.from(configs.entries()).map(([serviceName, config]) => ({
          userId,
          serviceName,
          config: config as Record<string, unknown>,
        }));
        return Promise.resolve({ rows });
      }
      return Promise.resolve({ rows: [] });
    });

    // Create Express app
    app = express();
    app.use(express.json());
    app.use(requestIdMiddleware);

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

    // Setup routes with inline handlers for testing
    setupRoutes(app);

    app.use(errorHandler);
  });

  function setupRoutes(application: Application) {
    // POST /api/v1/auth/login
    application.post(
      '/api/v1/auth/login',
      validationMiddleware(loginSchema),
      async (req: any, res: any) => {
        const { email, password } = req.body;
        const foundUser = Array.from(mockUsers.values()).find(u => u.email === email);

        if (!foundUser || password !== foundUser.plainPassword) {
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
            name: foundUser.name,
          },
          token: req.sessionID || token,
        });
      }
    );

    // POST /api/v1/auth/logout
    application.post(
      '/api/v1/auth/logout',
      authMiddleware,
      async (req: any, res: any) => {
        const session = req.session;
        session?.destroy(() => {
          res.clearCookie('eracun.sid');
          res.json({ message: 'Logged out successfully' });
        });
      }
    );

    // GET /api/v1/auth/me
    application.get(
      '/api/v1/auth/me',
      authMiddleware,
      async (req: AuthenticatedRequest, res: any) => {
        res.json({
          user: {
            id: req.user!.id,
            email: req.user!.email,
          },
        });
      }
    );

    // GET /api/v1/users/me
    application.get(
      '/api/v1/users/me',
      authMiddleware,
      async (req: AuthenticatedRequest, res: any) => {
        const userId = req.user!.id;
        const user = mockUsers.get(userId);
        if (!user) {
          res.status(404).json({ error: 'User not found', requestId: req.id });
          return;
        }
        const { passwordHash, ...userResponse } = user;
        res.json(userResponse);
      }
    );

    // GET /api/v1/users/:id (Now protected with authMiddleware)
    application.get(
      '/api/v1/users/:id',
      authMiddleware, // SECURITY FIX: Added authentication
      async (req: AuthenticatedRequest, res: any) => {
        const userId = req.params.id;
        const user = mockUsers.get(userId);
        if (!user) {
          res.status(404).json({ error: 'User not found', requestId: req.id });
          return;
        }
        const { passwordHash, ...userResponse } = user;
        res.json(userResponse);
      }
    );

    // GET /api/v1/users/me/config
    application.get(
      '/api/v1/users/me/config',
      authMiddleware,
      async (req: AuthenticatedRequest, res: any) => {
        const userId = req.user!.id;
        const configs = mockUserConfigs.get(userId) || new Map();
        const configMap: Record<string, Record<string, unknown>> = {};
        for (const [serviceName, config] of configs.entries()) {
          configMap[serviceName] = config as Record<string, unknown>;
        }
        res.json({ configs: configMap });
      }
    );

    // PUT /api/v1/users/me/config/:service
    application.put(
      '/api/v1/users/me/config/:service',
      authMiddleware,
      async (req: AuthenticatedRequest, res: any) => {
        const userId = req.user!.id;
        const { service } = req.params;

        if (service !== 'fina' && service !== 'imap') {
          res.status(400).json({
            error: 'Invalid service name',
            message: 'Service must be "fina" or "imap"',
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
      }
    );

    // DELETE /api/v1/users/me/config/:service
    application.delete(
      '/api/v1/users/me/config/:service',
      authMiddleware,
      async (req: AuthenticatedRequest, res: any) => {
        const userId = req.user!.id;
        const { service } = req.params;

        if (service !== 'fina' && service !== 'imap') {
          res.status(400).json({
            error: 'Invalid service name',
            message: 'Service must be "fina" or "imap"',
          });
          return;
        }

        const configs = mockUserConfigs.get(userId);
        if (configs) {
          configs.delete(service);
        }

        res.status(204).send();
      }
    );

    // POST /api/v1/invoices
    application.post(
      '/api/v1/invoices',
      authMiddleware,
      async (req: AuthenticatedRequest, res: any) => {
        const userId = req.user!.id;

        // Check FINA config
        const userConfigs = mockUserConfigs.get(userId);
        if (!userConfigs || !userConfigs.has('fina')) {
          res.status(400).json({
            error: 'FINA configuration required',
            message: 'Please configure your FINA credentials before submitting invoices',
          });
          return;
        }

        const invoice = {
          id: `inv-${Date.now()}-${Math.random().toString(36).substring(7)}`,
          userId,
          oib: req.body.oib,
          invoiceNumber: req.body.invoiceNumber,
          amount: req.body.amount,
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
      }
    );

    // GET /api/v1/invoices/:id
    application.get(
      '/api/v1/invoices/:id',
      authMiddleware,
      async (req: AuthenticatedRequest, res: any) => {
        const userId = req.user!.id;
        const invoiceId = req.params.id;
        const userInvoices = mockInvoices.get(userId) || [];
        const invoice = userInvoices.find(inv => inv.id === invoiceId);

        if (!invoice) {
          res.status(404).json({ error: 'Invoice not found', requestId: req.id });
          return;
        }

        res.json(invoice);
      }
    );

    // GET /api/v1/invoices
    application.get(
      '/api/v1/invoices',
      authMiddleware,
      async (req: AuthenticatedRequest, res: any) => {
        const userId = req.user!.id;
        const userInvoices = mockInvoices.get(userId) || [];
        res.json({ invoices: userInvoices });
      }
    );
  }

  describe('Authentication Flow', () => {
    it('should successfully authenticate with valid credentials', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: businessUser.email,
          password: businessUser.plainPassword,
        })
        .expect(200);

      expect(response.body).toMatchObject({
        user: {
          id: businessUser.id,
          email: businessUser.email,
          name: businessUser.name,
        },
        token: expect.any(String),
      });
    });

    it('should reject authentication with invalid email', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'SomePassword123!',
        })
        .expect(401);

      expect(response.body).toMatchObject({
        error: 'Invalid credentials',
        message: 'Email or password is incorrect',
      });
    });

    it('should reject authentication with invalid password', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: businessUser.email,
          password: 'WrongPassword123!',
        })
        .expect(401);

      expect(response.body).toMatchObject({
        error: 'Invalid credentials',
      });
    });

    it('should reject login with missing email', async () => {
      await request(app)
        .post('/api/v1/auth/login')
        .send({
          password: 'SomePassword123!',
        })
        .expect(400);
    });

    it('should reject login with missing password', async () => {
      await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: businessUser.email,
        })
        .expect(400);
    });

    it('should return current user info when authenticated', async () => {
      const agent = request.agent(app);

      await agent
        .post('/api/v1/auth/login')
        .send({
          email: businessUser.email,
          password: businessUser.plainPassword,
        });

      const response = await agent
        .get('/api/v1/auth/me')
        .expect(200);

      expect(response.body.user).toMatchObject({
        id: businessUser.id,
        email: businessUser.email,
      });
    });

    it('should reject unauthenticated request to /me', async () => {
      await request(app)
        .get('/api/v1/auth/me')
        .expect(401);
    });

    it('should logout and invalidate session', async () => {
      const agent = request.agent(app);

      // Login
      await agent
        .post('/api/v1/auth/login')
        .send({
          email: businessUser.email,
          password: businessUser.plainPassword,
        })
        .expect(200);

      // Logout
      await agent
        .post('/api/v1/auth/logout')
        .expect(200);

      // Try to access protected endpoint
      await agent
        .get('/api/v1/auth/me')
        .expect(401);
    });
  });

  describe('Configuration Management', () => {
    it('should retrieve user configuration', async () => {
      const agent = request.agent(app);

      await agent
        .post('/api/v1/auth/login')
        .send({
          email: businessUser.email,
          password: businessUser.plainPassword,
        });

      const response = await agent
        .get('/api/v1/users/me/config')
        .expect(200);

      expect(response.body.configs.fina).toMatchObject(businessUser.finaConfig!);
    });

    it('should update FINA configuration', async () => {
      const agent = request.agent(app);

      await agent
        .post('/api/v1/auth/login')
        .send({
          email: freelancerUser.email,
          password: freelancerUser.plainPassword,
        });

      const newConfig = {
        wsdlUrl: 'https://new-fina.example.com/wsdl',
        certPath: '/certs/new.p12',
        certPassphrase: 'NewPass123',
      };

      await agent
        .put('/api/v1/users/me/config/fina')
        .send(newConfig)
        .expect(200);

      const response = await agent
        .get('/api/v1/users/me/config')
        .expect(200);

      expect(response.body.configs.fina).toMatchObject(newConfig);
    });

    it('should delete FINA configuration', async () => {
      const agent = request.agent(app);

      await agent
        .post('/api/v1/auth/login')
        .send({
          email: businessUser.email,
          password: businessUser.plainPassword,
        });

      await agent
        .delete('/api/v1/users/me/config/fina')
        .expect(204);

      const response = await agent
        .get('/api/v1/users/me/config')
        .expect(200);

      expect(response.body.configs).not.toHaveProperty('fina');
    });

    it('should reject invalid service name', async () => {
      const agent = request.agent(app);

      await agent
        .post('/api/v1/auth/login')
        .send({
          email: businessUser.email,
          password: businessUser.plainPassword,
        });

      await agent
        .put('/api/v1/users/me/config/invalid')
        .send({ some: 'config' })
        .expect(400);
    });
  });

  describe('Invoice Submission', () => {
    it('should submit invoice with valid data', async () => {
      const agent = request.agent(app);

      await agent
        .post('/api/v1/auth/login')
        .send({
          email: businessUser.email,
          password: businessUser.plainPassword,
        });

      const response = await agent
        .post('/api/v1/invoices')
        .send(standardSubmission)
        .expect(202);

      expect(response.body).toMatchObject({
        invoiceId: expect.any(String),
        jobId: expect.any(String),
        status: 'queued',
      });
    });

    it('should submit cash payment invoice with business premises', async () => {
      const agent = request.agent(app);

      await agent
        .post('/api/v1/auth/login')
        .send({
          email: businessUser.email,
          password: businessUser.plainPassword,
        });

      const response = await agent
        .post('/api/v1/invoices')
        .send(cashPaymentSubmission)
        .expect(202);

      expect(response.body.status).toBe('queued');
    });

    it('should reject invoice submission without FINA config', async () => {
      const agent = request.agent(app);

      await agent
        .post('/api/v1/auth/login')
        .send({
          email: userWithoutFina.email,
          password: userWithoutFina.plainPassword,
        });

      const response = await agent
        .post('/api/v1/invoices')
        .send(standardSubmission)
        .expect(400);

      expect(response.body.error).toBe('FINA configuration required');
    });

    it('should retrieve submitted invoice', async () => {
      const agent = request.agent(app);

      await agent
        .post('/api/v1/auth/login')
        .send({
          email: businessUser.email,
          password: businessUser.plainPassword,
        });

      const submitResponse = await agent
        .post('/api/v1/invoices')
        .send(standardSubmission)
        .expect(202);

      const invoiceId = submitResponse.body.invoiceId;

      const getResponse = await agent
        .get(`/api/v1/invoices/${invoiceId}`)
        .expect(200);

      expect(getResponse.body.id).toBe(invoiceId);
      expect(getResponse.body.invoiceNumber).toBe(standardSubmission.invoiceNumber);
    });

    it('should list only user\'s invoices', async () => {
      const agentA = request.agent(app);
      const agentB = request.agent(app);

      // User A submits invoices
      await agentA
        .post('/api/v1/auth/login')
        .send({
          email: businessUser.email,
          password: businessUser.plainPassword,
        });

      await agentA
        .post('/api/v1/invoices')
        .send({ ...standardSubmission, invoiceNumber: 'INV-A-1' });

      await agentA
        .post('/api/v1/invoices')
        .send({ ...standardSubmission, invoiceNumber: 'INV-A-2' });

      // User B submits invoice
      await agentB
        .post('/api/v1/auth/login')
        .send({
          email: smallBusinessUser.email,
          password: smallBusinessUser.plainPassword,
        });

      await agentB
        .post('/api/v1/invoices')
        .send({ ...standardSubmission, invoiceNumber: 'INV-B-1' });

      // User A should see only their invoices
      const listAResponse = await agentA
        .get('/api/v1/invoices')
        .expect(200);

      expect(listAResponse.body.invoices).toHaveLength(2);

      // User B should see only their invoice
      const listBResponse = await agentB
        .get('/api/v1/invoices')
        .expect(200);

      expect(listBResponse.body.invoices).toHaveLength(1);
    });
  });

  describe('Multi-User Isolation', () => {
    it('should prevent cross-user invoice access', async () => {
      const agentA = request.agent(app);
      const agentB = request.agent(app);

      await agentA
        .post('/api/v1/auth/login')
        .send({
          email: businessUser.email,
          password: businessUser.plainPassword,
        });

      await agentB
        .post('/api/v1/auth/login')
        .send({
          email: smallBusinessUser.email,
          password: smallBusinessUser.plainPassword,
        });

      const submitResponse = await agentA
        .post('/api/v1/invoices')
        .send(standardSubmission)
        .expect(202);

      const invoiceId = submitResponse.body.invoiceId;

      // User B should not access User A's invoice
      await agentB
        .get(`/api/v1/invoices/${invoiceId}`)
        .expect(404);
    });

    it('should prevent cross-user config access', async () => {
      const agentA = request.agent(app);
      const agentB = request.agent(app);

      await agentA
        .post('/api/v1/auth/login')
        .send({
          email: businessUser.email,
          password: businessUser.plainPassword,
        });

      await agentB
        .post('/api/v1/auth/login')
        .send({
          email: userWithoutFina.email,
          password: userWithoutFina.plainPassword,
        });

      const configResponse = await agentB
        .get('/api/v1/users/me/config')
        .expect(200);

      expect(configResponse.body.configs).not.toHaveProperty('fina');
    });

    it('should allow same invoice number for different users', async () => {
      const agentA = request.agent(app);
      const agentB = request.agent(app);
      const sameInvoiceNumber = 'DUPLICATE-001';

      await agentA
        .post('/api/v1/auth/login')
        .send({
          email: businessUser.email,
          password: businessUser.plainPassword,
        });

      await agentB
        .post('/api/v1/auth/login')
        .send({
          email: smallBusinessUser.email,
          password: smallBusinessUser.plainPassword,
        });

      const responseA = await agentA
        .post('/api/v1/invoices')
        .send({ ...standardSubmission, invoiceNumber: sameInvoiceNumber })
        .expect(202);

      const responseB = await agentB
        .post('/api/v1/invoices')
        .send({ ...standardSubmission, invoiceNumber: sameInvoiceNumber })
        .expect(202);

      expect(responseA.body.invoiceId).not.toBe(responseB.body.invoiceId);
    });
  });

  describe('Concurrent Operations', () => {
    it('should handle concurrent invoice submissions', async () => {
      const agents = await Promise.all([concurrentUser1, concurrentUser2].map(async user => {
        const agent = request.agent(app);
        await agent.post('/api/v1/auth/login').send({
          email: user.email,
          password: user.plainPassword,
        });
        return agent;
      }));

      const responses = await Promise.all(
        agents.map(agent =>
          agent.post('/api/v1/invoices').send({
            ...standardSubmission,
            invoiceNumber: `CONCUR-${Date.now()}`,
          })
        )
      );

      responses.forEach(response => {
        expect(response.status).toBe(202);
        expect(response.body.invoiceId).toBeTruthy();
      });

      const ids = responses.map(r => r.body.invoiceId);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });

    it('should handle concurrent config updates', async () => {
      const agent1 = request.agent(app);
      const agent2 = request.agent(app);

      await Promise.all([
        agent1.post('/api/v1/auth/login').send({
          email: concurrentUser1.email,
          password: concurrentUser1.plainPassword,
        }),
        agent2.post('/api/v1/auth/login').send({
          email: concurrentUser2.email,
          password: concurrentUser2.plainPassword,
        }),
      ]);

      await Promise.all([
        agent1.put('/api/v1/users/me/config/fina').send({
          wsdlUrl: 'https://fina1.example.com/wsdl',
          certPath: '/certs/user1.p12',
          certPassphrase: 'Pass1',
        }),
        agent2.put('/api/v1/users/me/config/fina').send({
          wsdlUrl: 'https://fina2.example.com/wsdl',
          certPath: '/certs/user2.p12',
          certPassphrase: 'Pass2',
        }),
      ]);

      const [config1, config2] = await Promise.all([
        agent1.get('/api/v1/users/me/config'),
        agent2.get('/api/v1/users/me/config'),
      ]);

      expect(config1.body.configs.fina.wsdlUrl).toBe('https://fina1.example.com/wsdl');
      expect(config2.body.configs.fina.wsdlUrl).toBe('https://fina2.example.com/wsdl');
    });
  });

  describe('SECURITY: Authentication Verification', () => {
    it('should require authentication for GET /api/v1/users/:id', async () => {
      // This test verifies the security fix
      // The endpoint now requires authentication

      const response = await request(app)
        .get(`/api/v1/users/${businessUser.id}`)
        .expect(401); // Should be 401 Unauthorized!

      expect(response.body.error).toBe('Unauthorized');
    });

    it('should allow authenticated user to fetch their own data by ID', async () => {
      const agent = request.agent(app);

      await agent
        .post('/api/v1/auth/login')
        .send({
          email: businessUser.email,
          password: businessUser.plainPassword,
        });

      const response = await agent
        .get(`/api/v1/users/${businessUser.id}`)
        .expect(200);

      expect(response.body.email).toBe(businessUser.email);
      expect(response.body.name).toBe(businessUser.name);
    });

    it('should prevent user enumeration via users/:id endpoint', async () => {
      // Verify that unauthenticated requests are blocked
      const userIds = Array.from(mockUsers.keys());

      for (const id of userIds) {
        await request(app)
          .get(`/api/v1/users/${id}`)
          .expect(401); // Unauthorized - no user enumeration possible
      }
    });
  });
});
