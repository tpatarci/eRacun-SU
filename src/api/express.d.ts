import 'express';
import 'express-session';

declare module 'express' {
  export interface Request {
    /** Request ID for tracing */
    id?: string;
  }
}

declare module 'express-session' {
  export interface SessionData {
    userId?: string;
    email?: string;
    token?: string;
  }
}
