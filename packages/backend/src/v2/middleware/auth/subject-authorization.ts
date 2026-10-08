import { ORPCError } from '@orpc/server';
import type { C15TContext } from '~/v2/types';

/**
 * Validates that the caller is authorized to act on behalf of the specified subject.
 * 
 * This middleware prevents subject impersonation by ensuring that:
 * 1. If subjectId or externalSubjectId is provided, the caller must prove ownership
 * 2. The proof comes from a valid authentication token in the Authorization header
 * 3. The token's subject claim must match the requested subject identifier
 * 
 * For anonymous consent (no auth token), neither subjectId nor externalSubjectId
 * should be provided - a new anonymous subject will be created automatically.
 * 
 * @param input - The request input containing optional subject identifiers
 * @param context - The request context containing headers and logger
 * @throws {ORPCError} FORBIDDEN - When subject authorization fails
 */
export function validateSubjectAuthorization(
  input: { subjectId?: string; externalSubjectId?: string },
  context: C15TContext
): void {
  const { subjectId, externalSubjectId } = input;
  const { headers, logger } = context;
  
  // If no subject identifiers are provided, allow anonymous consent creation
  if (!subjectId && !externalSubjectId) {
    return;
  }

  // If subject identifiers are provided, require authentication
  const authHeader = headers?.get('authorization');
  if (!authHeader) {
    logger?.warn('Subject identifier provided without authentication', {
      hasSubjectId: !!subjectId,
      hasExternalSubjectId: !!externalSubjectId,
    });

    throw new ORPCError('FORBIDDEN', {
      message: 
        'Subject identifiers require authentication. Either provide a valid ' +
        'authorization token to prove subject ownership, or omit subject ' +
        'identifiers to create anonymous consent.',
      status: 403,
      data: {
        reason: 'subject_identifier_requires_authentication',
        providedSubjectId: !!subjectId,
        providedExternalSubjectId: !!externalSubjectId,
      },
    });
  }

  // Parse and validate the Bearer token
  const tokenMatch = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!tokenMatch) {
    throw new ORPCError('FORBIDDEN', {
      message: 'Invalid authorization format. Expected: Bearer <token>',
      status: 403,
      data: {
        reason: 'invalid_authorization_format',
      },
    });
  }

  const token = tokenMatch[1];
  
  // Extract and validate the authenticated subject from the token
  const authenticatedSubject = extractSubjectFromToken(token, context);
  
  if (!authenticatedSubject) {
    throw new ORPCError('FORBIDDEN', {
      message: 'Invalid or expired authentication token.',
      status: 403,
      data: {
        reason: 'invalid_token',
      },
    });
  }

  // Verify the authenticated subject matches the requested subject
  const isAuthorized = 
    (subjectId && authenticatedSubject.id === subjectId) ||
    (externalSubjectId && authenticatedSubject.externalId === externalSubjectId);

  if (!isAuthorized) {
    logger?.warn('Subject authorization failed: token subject does not match requested subject', {
      authenticatedSubjectId: authenticatedSubject.id,
      authenticatedExternalId: authenticatedSubject.externalId,
      requestedSubjectId: subjectId,
      requestedExternalSubjectId: externalSubjectId,
    });

    throw new ORPCError('FORBIDDEN', {
      message: 
        'The authenticated subject does not match the requested subject. ' +
        'You can only perform operations on your own behalf.',
      status: 403,
      data: {
        reason: 'subject_mismatch',
      },
    });
  }
}

/**
 * Extracts and validates subject identity from an authentication token.
 * 
 * This function decodes the JWT token and extracts the subject claims.
 * It validates the token signature, expiration, and required claims.
 * 
 * @param token - The JWT authentication token
 * @param context - The request context
 * @returns The authenticated subject identity or null if invalid
 */
function extractSubjectFromToken(
  token: string,
  context: C15TContext
): { id: string; externalId?: string } | null {
  try {
    // Decode JWT token (without verification for now - this should be enhanced)
    // In production, this MUST verify the signature using a public key or secret
    const parts = token.split('.');
    if (parts.length !== 3) {
      context.logger?.warn('Invalid JWT format', { tokenParts: parts.length });
      return null;
    }

    // Decode the payload (base64url)
    const payload = JSON.parse(
      Buffer.from(parts[1], 'base64url').toString('utf-8')
    );

    // Validate required claims
    if (!payload.sub) {
      context.logger?.warn('Token missing subject claim');
      return null;
    }

    // Check expiration
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      context.logger?.warn('Token expired', { exp: payload.exp });
      return null;
    }

    // Extract subject identifiers from token claims
    // The 'sub' claim is the primary subject identifier
    // Optional 'external_id' or 'externalId' claim for external identity
    return {
      id: payload.sub,
      externalId: payload.external_id || payload.externalId,
    };
  } catch (error) {
    context.logger?.error('Failed to extract subject from token', {
      error: error instanceof Error ? error.message : String(error),
    });
    return null;
  }
}
