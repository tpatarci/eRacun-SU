import { type Request, type Response } from 'express';
import { getUserByEmail } from '../../repositories/user-repository.js';
import {
  verifyPassword,
  generateSessionToken,
  authMiddleware,
  type AuthenticatedRequest,
} from '../../shared/auth.js';
import { validationMiddleware } from '../middleware/validate.js';
import { loginSchema } from '../schemas.js';
import { logger } from '../../shared/logger.js';

/**
 * Login request body
 */
interface LoginRequestBody {
  email: string;
  password: string;
}

/**
 * Login response
 */
interface LoginResponse {
  user: {
    id: string;
    email: string;
    name?: string;
  };
  token: string;
}

// POST /api/v1/auth/login
export async function loginHandler(req: Request, res: Response): Promise<void> {
  const { email, password } = req.body as LoginRequestBody;

  try {
    // Find user by email
    const user = await getUserByEmail(email);

    if (!user) {
      logger.warn({
        email,
        requestId: req.id,
      }, 'Login failed: User not found');

      res.status(401).json({
        error: 'Invalid credentials',
        message: 'Email or password is incorrect',
        requestId: req.id,
      });
      return;
    }

    // Verify password
    const isValidPassword = await verifyPassword(password, user.passwordHash);

    if (!isValidPassword) {
      logger.warn({
        email,
        userId: user.id,
        requestId: req.id,
      }, 'Login failed: Invalid password');

      res.status(401).json({
        error: 'Invalid credentials',
        message: 'Email or password is incorrect',
        requestId: req.id,
      });
      return;
    }

    // Create session using express-session
    const authReq = req as AuthenticatedRequest;
    const token = generateSessionToken();

    // Set session data
    if (authReq.session) {
      authReq.session.userId = user.id;
      authReq.session.email = user.email;
      authReq.session.token = token;
    }

    logger.info({
      userId: user.id,
      email: user.email,
      requestId: req.id,
    }, 'User logged in successfully');

    // Return user info with session ID as token
    // For cookie-based clients, the session is automatically managed
    // For API clients, the session ID can be used with ?token=... query param
    const response: LoginResponse = {
      user: {
        id: user.id,
        email: user.email,
        name: user.name || undefined,
      },
      token: authReq.sessionID || token,
    };

    res.json(response);
  } catch (error) {
    logger.error({
      error: error instanceof Error ? error.message : String(error),
      requestId: req.id,
    }, 'Login failed due to server error');

    res.status(500).json({
      error: 'Internal server error',
      message: 'Login failed due to a server error',
      requestId: req.id,
    });
  }
}

// POST /api/v1/auth/logout
export async function logoutHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  // Destroy the session
  const session = req.session as any; // Type assertion for destroy method
  session?.destroy((err: Error | null) => {
    if (err) {
      logger.error({
        error: err,
        userId: req.user?.id,
        requestId: req.id,
      }, 'Logout failed: Error destroying session');

      res.status(500).json({
        error: 'Internal server error',
        message: 'Logout failed',
        requestId: req.id,
      });
      return;
    }

    logger.info({
      userId: req.user?.id,
      requestId: req.id,
    }, 'User logged out successfully');

    res.clearCookie('eracun.sid');
    res.json({
      message: 'Logged out successfully',
    });
  });
}

// GET /api/v1/auth/me
export async function getMeHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  // This endpoint requires authentication middleware to set req.user
  // The middleware will be added in subtask-2-3 when session storage is implemented

  if (!req.user) {
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Authentication required',
      requestId: req.id,
    });
    return;
  }

  res.json({
    user: {
      id: req.user.id,
      email: req.user.email,
    },
  });
}

// Route handlers with validation middleware
export const authRoutes = [
  {
    path: '/login',
    method: 'post' as const,
    handler: loginHandler,
    middleware: [validationMiddleware(loginSchema)],
  },
  {
    path: '/logout',
    method: 'post' as const,
    handler: logoutHandler,
    middleware: [authMiddleware], // Require authentication
  },
  {
    path: '/me',
    method: 'get' as const,
    handler: getMeHandler,
    middleware: [authMiddleware], // Require authentication
  },
];
