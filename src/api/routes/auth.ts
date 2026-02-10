import { type Request, type Response } from 'express';
import { getUserByEmail } from '../../repositories/user-repository.js';
import { verifyPassword, generateSessionToken, type AuthenticatedRequest } from '../../shared/auth.js';
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

    // Generate session token
    const token = generateSessionToken();

    logger.info({
      userId: user.id,
      email: user.email,
      requestId: req.id,
    }, 'User logged in successfully');

    // TODO: Store session in database/Redis (subtask-2-3)
    // For now, return the token which will be validated once session storage is implemented

    const response: LoginResponse = {
      user: {
        id: user.id,
        email: user.email,
        name: user.name || undefined,
      },
      token,
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
  // TODO: Invalidate session in database/Redis (subtask-2-3)
  // For now, return a success response noting that full logout will be implemented later

  logger.info({
    userId: req.user?.id,
    requestId: req.id,
  }, 'Logout requested');

  res.json({
    message: 'Logged out successfully',
    // Note: Session invalidation will be implemented in subtask-2-3
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
    // TODO: Add auth middleware in subtask-2-3
  },
  {
    path: '/me',
    method: 'get' as const,
    handler: getMeHandler,
    // TODO: Add auth middleware in subtask-2-3
  },
];
