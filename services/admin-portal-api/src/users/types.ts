import { UserRole } from '../auth/types';

/**
 * User entity
 */
export interface User {
  id: number;
  email: string;
  passwordHash: string;
  role: UserRole;
  active: boolean;
  createdAt: Date;
  lastLogin: Date | null;
}

/**
 * User creation request
 */
export interface CreateUserRequest {
  email: string;
  password: string;
  role: UserRole;
}

/**
 * User update request
 */
export interface UpdateUserRequest {
  role?: UserRole;
  active?: boolean;
  password?: string;
}

/**
 * User response (without password hash)
 */
export interface UserResponse {
  id: number;
  email: string;
  role: UserRole;
  active: boolean;
  createdAt: Date;
  lastLogin: Date | null;
}
