import { Router, Request, Response } from 'express';
import { authenticateJWT } from '../auth/middleware';
import { adminOnly } from '../auth/rbac';
import { AuthenticatedRequest, UserRole } from '../auth/types';
import { CreateUserRequest, UpdateUserRequest, UserResponse } from './types';
import { getUserRepository } from './repository';
import { logger, maskEmail } from '../observability';

const router = Router();

/**
 * Convert User to UserResponse (remove password hash)
 */
function toUserResponse(user: any): UserResponse {
  return {
    id: user.id,
    email: user.email,
    role: user.role,
    active: user.active,
    createdAt: user.createdAt,
    lastLogin: user.lastLogin,
  };
}

/**
 * GET /api/v1/users
 *
 * List all users (admin only)
 */
router.get('/', authenticateJWT, adminOnly, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;

  try {
    const userRepo = getUserRepository();
    const users = await userRepo.getAllUsers();

    const userResponses = users.map(toUserResponse);

    logger.info({
      request_id: authReq.requestId,
      user_id: authReq.user?.userId,
      count: userResponses.length,
      msg: 'Retrieved all users',
    });

    return res.json({ users: userResponses });
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error: error.message,
      stack: error.stack,
      msg: 'Get all users error',
    });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/v1/users
 *
 * Create new user (admin only)
 */
router.post('/', authenticateJWT, adminOnly, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const { email, password, role } = req.body;

  // Validate input
  if (!email || !password || !role) {
    return res.status(400).json({ error: 'Email, password, and role required' });
  }

  if (!Object.values(UserRole).includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }

  if (password.length < 12) {
    return res.status(400).json({ error: 'Password must be at least 12 characters' });
  }

  try {
    const userRepo = getUserRepository();

    // Check if email already exists
    const emailExists = await userRepo.emailExists(email);
    if (emailExists) {
      return res.status(409).json({ error: 'Email already exists' });
    }

    const createRequest: CreateUserRequest = { email, password, role };
    const user = await userRepo.createUser(createRequest);

    logger.info({
      request_id: authReq.requestId,
      admin_user_id: authReq.user?.userId,
      new_user_id: user.id,
      new_user_email: maskEmail(email),
      new_user_role: role,
      msg: 'User created',
    });

    return res.status(201).json({ user: toUserResponse(user) });
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error: error.message,
      stack: error.stack,
      msg: 'Create user error',
    });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/v1/users/:id
 *
 * Get user details (admin only)
 */
router.get('/:id', authenticateJWT, adminOnly, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const userId = parseInt(req.params.id, 10);

  if (isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  try {
    const userRepo = getUserRepository();
    const user = await userRepo.getUserById(userId);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    logger.info({
      request_id: authReq.requestId,
      admin_user_id: authReq.user?.userId,
      target_user_id: userId,
      msg: 'Retrieved user details',
    });

    return res.json({ user: toUserResponse(user) });
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error: error.message,
      msg: 'Get user error',
    });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * PATCH /api/v1/users/:id
 *
 * Update user (admin only)
 */
router.patch('/:id', authenticateJWT, adminOnly, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const userId = parseInt(req.params.id, 10);

  if (isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  const { role, active, password } = req.body;

  // Validate role if provided
  if (role !== undefined && !Object.values(UserRole).includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }

  // Validate password if provided
  if (password !== undefined && password.length < 12) {
    return res.status(400).json({ error: 'Password must be at least 12 characters' });
  }

  try {
    const userRepo = getUserRepository();

    // Check if user exists
    const user = await userRepo.getUserById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const updates: UpdateUserRequest = {};
    if (role !== undefined) updates.role = role;
    if (active !== undefined) updates.active = active;
    if (password !== undefined) updates.password = password;

    await userRepo.updateUser(userId, updates);

    logger.info({
      request_id: authReq.requestId,
      admin_user_id: authReq.user?.userId,
      target_user_id: userId,
      updates: Object.keys(updates),
      msg: 'User updated',
    });

    // Fetch updated user
    const updatedUser = await userRepo.getUserById(userId);
    return res.json({ user: toUserResponse(updatedUser!) });
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error: error.message,
      msg: 'Update user error',
    });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * DELETE /api/v1/users/:id
 *
 * Deactivate user (admin only)
 */
router.delete('/:id', authenticateJWT, adminOnly, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const userId = parseInt(req.params.id, 10);

  if (isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  try {
    const userRepo = getUserRepository();

    // Check if user exists
    const user = await userRepo.getUserById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Prevent self-deletion
    if (userId === authReq.user?.userId) {
      return res.status(400).json({ error: 'Cannot deactivate your own account' });
    }

    await userRepo.deactivateUser(userId);

    logger.info({
      request_id: authReq.requestId,
      admin_user_id: authReq.user?.userId,
      target_user_id: userId,
      msg: 'User deactivated',
    });

    return res.json({ message: 'User deactivated successfully' });
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error: error.message,
      msg: 'Deactivate user error',
    });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
