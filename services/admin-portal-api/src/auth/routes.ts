import { Router, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { JWTPayload, AuthenticatedRequest } from './types';
import { authenticateJWT } from './middleware';
import { logger, maskEmail, activeSessions } from '../observability';
import { getUserRepository } from '../users/repository';
import { getSessionRepository } from '../users/session-repository';

const router = Router();

/**
 * POST /api/v1/auth/login
 *
 * Login with email and password
 */
router.post('/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  try {
    const userRepo = getUserRepository();
    const user = await userRepo.getUserByEmail(email);

    if (!user) {
      logger.warn({
        request_id: (req as any).requestId,
        email: maskEmail(email),
        msg: 'Login failed - user not found',
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!user.active) {
      logger.warn({
        request_id: (req as any).requestId,
        user_id: user.id,
        email: maskEmail(email),
        msg: 'Login failed - user deactivated',
      });
      return res.status(403).json({ error: 'Account deactivated' });
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.passwordHash);

    if (!passwordMatch) {
      logger.warn({
        request_id: (req as any).requestId,
        user_id: user.id,
        email: maskEmail(email),
        msg: 'Login failed - invalid password',
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const jwtSecret = process.env.JWT_SECRET!;
    const jwtExpiry = process.env.JWT_EXPIRY || '1h';

    const payload: JWTPayload = {
      userId: user.id,
      email: user.email,
      role: user.role,
    };

    const token = jwt.sign(payload, jwtSecret, { expiresIn: jwtExpiry });

    // Create session
    const sessionRepo = getSessionRepository();
    const sessionId = uuidv4();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    await sessionRepo.createSession({
      id: sessionId,
      userId: user.id,
      token,
      expiresAt,
      createdAt: new Date(),
    });

    // Update last login
    await userRepo.updateLastLogin(user.id);

    // Update active sessions metric
    const activeCount = await sessionRepo.countActiveSessions();
    activeSessions.set(activeCount);

    logger.info({
      request_id: (req as any).requestId,
      user_id: user.id,
      email: maskEmail(email),
      role: user.role,
      msg: 'Login successful',
    });

    res.json({
      token,
      expiresIn: jwtExpiry,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: (req as any).requestId,
      error: error.message,
      stack: error.stack,
      msg: 'Login error',
    });
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/v1/auth/logout
 *
 * Logout (invalidate token)
 */
router.post('/logout', authenticateJWT, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;

  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(' ')[1];

    if (token) {
      const sessionRepo = getSessionRepository();
      await sessionRepo.deleteSessionByToken(token);

      // Update active sessions metric
      const activeCount = await sessionRepo.countActiveSessions();
      activeSessions.set(activeCount);
    }

    logger.info({
      request_id: authReq.requestId,
      user_id: authReq.user?.userId,
      msg: 'Logout successful',
    });

    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error: error.message,
      msg: 'Logout error',
    });
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/v1/auth/refresh
 *
 * Refresh JWT token
 */
router.post('/refresh', authenticateJWT, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;

  try {
    const user = authReq.user!;

    // Generate new JWT token
    const jwtSecret = process.env.JWT_SECRET!;
    const jwtExpiry = process.env.JWT_EXPIRY || '1h';

    const payload: JWTPayload = {
      userId: user.userId,
      email: user.email,
      role: user.role,
    };

    const newToken = jwt.sign(payload, jwtSecret, { expiresIn: jwtExpiry });

    // Update session
    const sessionRepo = getSessionRepository();
    const oldToken = req.headers.authorization?.split(' ')[1];
    if (oldToken) {
      await sessionRepo.updateSessionToken(oldToken, newToken);
    }

    logger.info({
      request_id: authReq.requestId,
      user_id: user.userId,
      msg: 'Token refresh successful',
    });

    res.json({
      token: newToken,
      expiresIn: jwtExpiry,
    });
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error: error.message,
      msg: 'Token refresh error',
    });
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/v1/auth/me
 *
 * Get current user info
 */
router.get('/me', authenticateJWT, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;

  try {
    const userRepo = getUserRepository();
    const user = await userRepo.getUserById(authReq.user!.userId);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      id: user.id,
      email: user.email,
      role: user.role,
      active: user.active,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin,
    });
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error: error.message,
      msg: 'Get current user error',
    });
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
