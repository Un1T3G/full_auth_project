import { GraphQLError } from 'graphql';

export enum AuthErrorCode {
  UNAUTHENTICATED = 'UNAUTHENTICATED',
  FORBIDDEN = 'FORBIDDEN',
  MFA_REQUIRED = 'MFA_REQUIRED',
  INVALID_TOKEN = 'INVALID_TOKEN',
  UNVERIFIED_EMAIL = 'UNVERIFIED_EMAIL',
  USER_ALREADY_EXISTS = 'USER_ALREADY_EXISTS',
  INVALID_CREDENTIALS = 'INVALID_CREDENTIALS',
  SESSION_EXPIRED = 'SESSION_EXPIRED',
  INVALID_MFA_CODE = 'INVALID_MFA_CODE',
  BAD_REQUEST = 'BAD_REQUEST',
}

export class CustomAuthError extends GraphQLError {
  constructor(message: string, code: AuthErrorCode, extraExtensions?: Record<string, any>) {
    super(message, {
      extensions: {
        code,
        timestamp: new Date().toISOString(),
        ...extraExtensions,
      },
    });
  }
}

export class UnauthenticatedError extends CustomAuthError {
  constructor(message = 'Authentication required to access this resource') {
    super(message, AuthErrorCode.UNAUTHENTICATED);
  }
}

export class ForbiddenError extends CustomAuthError {
  constructor(message = 'You do not have permission to perform this action') {
    super(message, AuthErrorCode.FORBIDDEN);
  }
}

export class MfaRequiredError extends CustomAuthError {
  constructor(mfaTicket: string, message = 'MFA verification required to complete login') {
    super(message, AuthErrorCode.MFA_REQUIRED, { mfaTicket });
  }
}

export class InvalidTokenError extends CustomAuthError {
  constructor(message = 'Provided token is invalid or expired') {
    super(message, AuthErrorCode.INVALID_TOKEN);
  }
}

export class UnverifiedEmailError extends CustomAuthError {
  constructor(message = 'Email verification is required before proceeding') {
    super(message, AuthErrorCode.UNVERIFIED_EMAIL);
  }
}

export class UserAlreadyExistsError extends CustomAuthError {
  constructor(message = 'User with this email already exists') {
    super(message, AuthErrorCode.USER_ALREADY_EXISTS);
  }
}

export class InvalidCredentialsError extends CustomAuthError {
  constructor(message = 'Invalid email or password') {
    super(message, AuthErrorCode.INVALID_CREDENTIALS);
  }
}
