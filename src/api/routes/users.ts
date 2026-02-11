import type { Request, Response } from 'express';
import { getUserById, createUser as createUserRecord, getUserByEmail } from '../../repositories/user-repository.js';
import { hashPassword, authMiddleware, type AuthenticatedRequest } from '../../shared/auth.js';
import { validationMiddleware } from '../middleware/validate.js';
import { userCreationSchema } from '../schemas.js';
import { logger } from '../../shared/logger.js';

// GET /api/v1/users/:id
export async function getUserByIdHandler(req: Request, res: Response): Promise<void> {
  const { id } = req.params;
  const userId = Array.isArray(id) ? id[0] : id;

  const user = await getUserById(userId);

  if (!user) {
    res.status(404).json({
      error: 'User not found',
      requestId: req.id,
    });
    return;
  }

  // Don't expose password hash in response
  const { passwordHash, ...userResponse } = user;

  res.json(userResponse);
}

// POST /api/v1/users
export async function createUserHandler(req: Request, res: Response): Promise<void> {
  const userData = req.body;

  try {
    // Check if user with this email already exists
    const existingUser = await getUserByEmail(userData.email);
    if (existingUser) {
      res.status(409).json({
        error: 'User with this email already exists',
        requestId: req.id,
      });
      return;
    }

    // Hash the password before storing
    const passwordHash = await hashPassword(userData.password);

    // Create user record
    const user = await createUserRecord({
      email: userData.email,
      passwordHash,
      name: userData.name,
    });

    logger.info({
      userId: user.id,
      email: user.email,
    }, 'User created');

    // Don't expose password hash in response
    const { passwordHash: _, ...userResponse } = user;

    res.status(201).json(userResponse);
  } catch (error) {
    logger.error({
      error: error instanceof Error ? error.message : String(error),
    }, 'Failed to create user');

    res.status(500).json({
      error: 'Failed to create user',
      requestId: req.id,
    });
  }
}

// GET /api/v1/users/me
export async function getMeHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  if (!req.user) {
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Authentication required',
      requestId: req.id,
    });
    return;
  }

  // Get full user data from database
  const user = await getUserById(req.user.id);

  if (!user) {
    res.status(404).json({
      error: 'User not found',
      requestId: req.id,
    });
    return;
  }

  // Don't expose password hash in response
  const { passwordHash, ...userResponse } = user;

  res.json(userResponse);
}

// Route handlers with validation middleware
export const userRoutes = [
  {
    path: '/me',
    method: 'get',
    handler: getMeHandler,
    middleware: [authMiddleware],
  },
  {
    path: '/:id',
    method: 'get',
    handler: getUserByIdHandler,
    middleware: [authMiddleware], // SECURITY: Added authentication to prevent user enumeration
  },
  {
    path: '/',
    method: 'post',
    handler: createUserHandler,
    middleware: [validationMiddleware(userCreationSchema)],
  },
];
