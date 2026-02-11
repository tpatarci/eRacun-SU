/**
 * User Fixtures for E2E Testing
 *
 * Provides test user data with various roles and configurations
 * for comprehensive multi-user testing scenarios.
 */

import type { User } from '../../src/shared/types.js';

export interface TestUser extends User {
  plainPassword: string;
  finaConfig?: FinaConfig;
  imapConfig?: ImapConfig;
}

export interface FinaConfig {
  wsdlUrl: string;
  certPath: string;
  certPassphrase: string;
}

export interface ImapConfig {
  host: string;
  port: number;
  user: string;
  password: string;
  mailbox?: string;
}

/**
 * Standard business user with all configurations
 */
export const businessUser: TestUser = {
  id: '550e8400-e29b-41d4-a716-446655440001',
  email: 'business@example.com',
  plainPassword: 'SecurePass123!',
  passwordHash: '$2b$12$mockhashedpasswordfortesting',
  name: 'Business User',
  createdAt: new Date('2024-01-01T00:00:00Z'),
  updatedAt: new Date('2024-01-01T00:00:00Z'),
  finaConfig: {
    wsdlUrl: 'https://cis.porezna-uprava.hr/FiskalizacijaServiceTest/FiskalizacijaService.asmx',
    certPath: '/certs/business.p12',
    certPassphrase: 'Business_Fina_Pass_2024',
  },
  imapConfig: {
    host: 'imap.gmail.com',
    port: 993,
    user: 'business@example.com',
    password: 'app_password_here',
    mailbox: 'INVOICE',
  },
};

/**
 * Small business owner
 */
export const smallBusinessUser: TestUser = {
  id: '550e8400-e29b-41d4-a716-446655440002',
  email: 'smallbiz@example.com',
  plainPassword: 'SmallBiz123!',
  passwordHash: '$2b$12$mockhashedpasswordfortesting',
  name: 'Small Business Owner',
  createdAt: new Date('2024-01-15T00:00:00Z'),
  updatedAt: new Date('2024-01-15T00:00:00Z'),
  finaConfig: {
    wsdlUrl: 'https://cis.porezna-uprava.hr/FiskalizacijaServiceTest/FiskalizacijaService.asmx',
    certPath: '/certs/smallbiz.p12',
    certPassphrase: 'SmallBiz_Fina_456',
  },
  imapConfig: {
    host: 'imap.office365.com',
    port: 993,
    user: 'smallbiz@example.com',
    password: 'outlook_app_password',
    mailbox: 'Invoices',
  },
};

/**
 * Freelancer user
 */
export const freelancerUser: TestUser = {
  id: '550e8400-e29b-41d4-a716-446655440003',
  email: 'freelancer@example.com',
  plainPassword: 'FreeWork123!',
  passwordHash: '$2b$12$mockhashedpasswordfortesting',
  name: 'Freelancer Developer',
  createdAt: new Date('2024-02-01T00:00:00Z'),
  updatedAt: new Date('2024-02-01T00:00:00Z'),
  finaConfig: {
    wsdlUrl: 'https://cis.porezna-uprava.hr/FiskalizacijaServiceTest/FiskalizacijaService.asmx',
    certPath: '/certs/freelancer.p12',
    certPassphrase: 'Free_Fina_Pass_789',
  },
};

/**
 * User without FINA configuration (for testing errors)
 */
export const userWithoutFina: TestUser = {
  id: '550e8400-e29b-41d4-a716-446655440004',
  email: 'nofina@example.com',
  plainPassword: 'NoConfig123!',
  passwordHash: '$2b$12$mockhashedpasswordfortesting',
  name: 'User Without FINA',
  createdAt: new Date('2024-02-10T00:00:00Z'),
  updatedAt: new Date('2024-02-10T00:00:00Z'),
};

/**
 * User without IMAP configuration
 */
export const userWithoutImap: TestUser = {
  id: '550e8400-e29b-41d4-a716-446655440005',
  email: 'noimap@example.com',
  plainPassword: 'NoImap123!',
  passwordHash: '$2b$12$mockhashedpasswordfortesting',
  name: 'User Without IMAP',
  createdAt: new Date('2024-02-10T00:00:00Z'),
  updatedAt: new Date('2024-02-10T00:00:00Z'),
  finaConfig: {
    wsdlUrl: 'https://cis.porezna-uprava.hr/FiskalizacijaServiceTest/FiskalizacijaService.asmx',
    certPath: '/certs/noimap.p12',
    certPassphrase: 'NoImap_Fina_000',
  },
};

/**
 * User for concurrent operations testing
 */
export const concurrentUser1: TestUser = {
  id: '550e8400-e29b-41d4-a716-446655440006',
  email: 'concurrent1@example.com',
  plainPassword: 'Concur123!',
  passwordHash: '$2b$12$mockhashedpasswordfortesting',
  name: 'Concurrent User 1',
  createdAt: new Date('2024-02-11T00:00:00Z'),
  updatedAt: new Date('2024-02-11T00:00:00Z'),
  finaConfig: {
    wsdlUrl: 'https://fina1.example.com/wsdl',
    certPath: '/certs/concurrent1.p12',
    certPassphrase: 'Concur1_Pass_123',
  },
};

export const concurrentUser2: TestUser = {
  id: '550e8400-e29b-41d4-a716-446655440007',
  email: 'concurrent2@example.com',
  plainPassword: 'Concur456!',
  passwordHash: '$2b$12$mockhashedpasswordfortesting',
  name: 'Concurrent User 2',
  createdAt: new Date('2024-02-11T00:00:00Z'),
  updatedAt: new Date('2024-02-11T00:00:00Z'),
  finaConfig: {
    wsdlUrl: 'https://fina2.example.com/wsdl',
    certPath: '/certs/concurrent2.p12',
    certPassphrase: 'Concur2_Pass_456',
  },
};

export const concurrentUser3: TestUser = {
  id: '550e8400-e29b-41d4-a716-446655440008',
  email: 'concurrent3@example.com',
  plainPassword: 'Concur789!',
  passwordHash: '$2b$12$mockhashedpasswordfortesting',
  name: 'Concurrent User 3',
  createdAt: new Date('2024-02-11T00:00:00Z'),
  updatedAt: new Date('2024-02-11T00:00:00Z'),
  finaConfig: {
    wsdlUrl: 'https://fina3.example.com/wsdl',
    certPath: '/certs/concurrent3.p12',
    certPassphrase: 'Concur3_Pass_789',
  },
};

/**
 * FINA environment URLs for different environments
 */
export const finaEnvironments = {
  production: {
    wsdlUrl: 'https://cis.porezna-uprava.hr/FiskalizacijaService/FiskalizacijaService.asmx',
    description: 'Production FINA service',
  },
  test: {
    wsdlUrl: 'https://cis.porezna-uprava.hr/FiskalizacijaServiceTest/FiskalizacijaService.asmx',
    description: 'Test FINA service',
  },
  demo: {
    wsdlUrl: 'https://demo.fina.hr/FiskalizacijaService/FiskalizacijaService.asmx',
    description: 'Demo FINA service',
  },
};

/**
 * Common IMAP provider configurations
 */
export const imapProviders = {
  gmail: {
    host: 'imap.gmail.com',
    port: 993,
    description: 'Gmail IMAP',
  },
  outlook: {
    host: 'outlook.office365.com',
    port: 993,
    description: 'Outlook/Office365 IMAP',
  },
  yahoo: {
    host: 'imap.mail.yahoo.com',
    port: 993,
    description: 'Yahoo Mail IMAP',
  },
  icloud: {
    host: 'imap.mail.me.com',
    port: 993,
    description: 'iCloud Mail IMAP',
  },
  fastmail: {
    host: 'imap.fastmail.com',
    port: 993,
    description: 'FastMail IMAP',
  },
};

/**
 * Export all user fixtures
 */
export const userFixtures: TestUser[] = [
  businessUser,
  smallBusinessUser,
  freelancerUser,
  userWithoutFina,
  userWithoutImap,
  concurrentUser1,
  concurrentUser2,
  concurrentUser3,
];

/**
 * Helper function to get user by email
 */
export function getUserByEmail(email: string): TestUser | undefined {
  return userFixtures.find(u => u.email === email);
}

/**
 * Helper function to get user by ID
 */
export function getUserById(id: string): TestUser | undefined {
  return userFixtures.find(u => u.id === id);
}

/**
 * Helper function to get users with FINA config
 */
export function getUsersWithFinaConfig(): TestUser[] {
  return userFixtures.filter(u => u.finaConfig);
}

/**
 * Helper function to get users with IMAP config
 */
export function getUsersWithImapConfig(): TestUser[] {
  return userFixtures.filter(u => u.imapConfig);
}

/**
 * Helper to create user config for API calls
 */
export function toUserConfig(user: TestUser): Record<string, Record<string, unknown>> {
  const configs: Record<string, Record<string, unknown>> = {};

  if (user.finaConfig) {
    configs.fina = user.finaConfig;
  }

  if (user.imapConfig) {
    configs.imap = user.imapConfig;
  }

  return configs;
}
