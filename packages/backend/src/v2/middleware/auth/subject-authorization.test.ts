import { ORPCError } from '@orpc/server';
import { describe, expect, it, vi } from 'vitest';
import type { C15TContext } from '~/v2/types';
import { validateSubjectAuthorization } from './subject-authorization';

/**
 * Test suite for v2 subject authorization middleware
 * 
 * These tests verify that the security vulnerability "Unauthenticated caller can forge 
 * consent for an arbitrary subject" has been properly mitigated in v2 API.
 * 
 * The vulnerability allowed attackers to:
 * 1. Create consent records for any subject by providing their subjectId or externalSubjectId
 * 2. Query consent state for any subject without authentication
 * 3. Create audit log entries attributed to arbitrary subjects
 * 
 * The mitigation requires:
 * 1. Authentication token when subject identifiers are provided
 * 2. Token validation (format, expiration, claims)
 * 3. Subject claim in token must match requested subject identifier
 */

describe('V2 Subject Authorization Middleware - Security Tests', () => {
	// Helper to create a mock context
	const createMockContext = (authHeader?: string): C15TContext => {
		const headers = new Headers();
		if (authHeader) {
			headers.set('authorization', authHeader);
		}
		
		return {
			headers,
			logger: {
				warn: vi.fn(),
				error: vi.fn(),
				info: vi.fn(),
				debug: vi.fn(),
			},
		} as unknown as C15TContext;
	};

	// Helper to create a valid JWT token
	const createJWT = (payload: Record<string, unknown>): string => {
		const header = { alg: 'HS256', typ: 'JWT' };
		const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
		const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
		const signature = 'mock-signature';
		return `${encodedHeader}.${encodedPayload}.${signature}`;
	};

	describe('Anonymous consent (no subject identifiers)', () => {
		it('should allow requests without subject identifiers and without authentication', () => {
			const context = createMockContext();
			
			// Should not throw
			expect(() => {
				validateSubjectAuthorization({}, context);
			}).not.toThrow();
		});

		it('should allow requests with empty subject identifiers', () => {
			const context = createMockContext();
			
			// Should not throw
			expect(() => {
				validateSubjectAuthorization(
					{ subjectId: undefined, externalSubjectId: undefined },
					context
				);
			}).not.toThrow();
		});
	});

	describe('Exploit Prevention: Subject impersonation via subjectId', () => {
		it('should reject request with subjectId but no authentication token', () => {
			const context = createMockContext();
			
			expect(() => {
				validateSubjectAuthorization(
					{ subjectId: 'victim-subject-123' },
					context
				);
			}).toThrow(ORPCError);

			try {
				validateSubjectAuthorization(
					{ subjectId: 'victim-subject-123' },
					context
				);
			} catch (error) {
				expect(error).toBeInstanceOf(ORPCError);
				expect((error as ORPCError).status).toBe(403);
				expect((error as ORPCError).data?.reason).toBe('subject_identifier_requires_authentication');
				expect((error as ORPCError).message).toContain('Subject identifiers require authentication');
			}
		});

		it('should reject request with subjectId and mismatched token subject', () => {
			const token = createJWT({
				sub: 'attacker-subject-456',
				exp: Math.floor(Date.now() / 1000) + 3600,
			});
			const context = createMockContext(`Bearer ${token}`);
			
			expect(() => {
				validateSubjectAuthorization(
					{ subjectId: 'victim-subject-123' },
					context
				);
			}).toThrow(ORPCError);

			try {
				validateSubjectAuthorization(
					{ subjectId: 'victim-subject-123' },
					context
				);
			} catch (error) {
				expect(error).toBeInstanceOf(ORPCError);
				expect((error as ORPCError).status).toBe(403);
				expect((error as ORPCError).data?.reason).toBe('subject_mismatch');
				expect((error as ORPCError).message).toContain('authenticated subject does not match');
			}
		});

		it('should allow request with subjectId matching token subject', () => {
			const subjectId = 'legitimate-subject-789';
			const token = createJWT({
				sub: subjectId,
				exp: Math.floor(Date.now() / 1000) + 3600,
			});
			const context = createMockContext(`Bearer ${token}`);
			
			// Should not throw
			expect(() => {
				validateSubjectAuthorization({ subjectId }, context);
			}).not.toThrow();
		});
	});

	describe('Exploit Prevention: Subject impersonation via externalSubjectId', () => {
		it('should reject request with externalSubjectId but no authentication token', () => {
			const context = createMockContext();
			
			expect(() => {
				validateSubjectAuthorization(
					{ externalSubjectId: 'external-victim-123' },
					context
				);
			}).toThrow(ORPCError);

			try {
				validateSubjectAuthorization(
					{ externalSubjectId: 'external-victim-123' },
					context
				);
			} catch (error) {
				expect(error).toBeInstanceOf(ORPCError);
				expect((error as ORPCError).status).toBe(403);
				expect((error as ORPCError).data?.reason).toBe('subject_identifier_requires_authentication');
			}
		});

		it('should reject request with externalSubjectId and mismatched token external ID', () => {
			const token = createJWT({
				sub: 'some-subject',
				externalId: 'attacker-external-456',
				exp: Math.floor(Date.now() / 1000) + 3600,
			});
			const context = createMockContext(`Bearer ${token}`);
			
			expect(() => {
				validateSubjectAuthorization(
					{ externalSubjectId: 'external-victim-123' },
					context
				);
			}).toThrow(ORPCError);

			try {
				validateSubjectAuthorization(
					{ externalSubjectId: 'external-victim-123' },
					context
				);
			} catch (error) {
				expect(error).toBeInstanceOf(ORPCError);
				expect((error as ORPCError).status).toBe(403);
				expect((error as ORPCError).data?.reason).toBe('subject_mismatch');
			}
		});

		it('should allow request with externalSubjectId matching token externalId claim', () => {
			const externalSubjectId = 'legitimate-external-789';
			const token = createJWT({
				sub: 'some-subject',
				externalId: externalSubjectId,
				exp: Math.floor(Date.now() / 1000) + 3600,
			});
			const context = createMockContext(`Bearer ${token}`);
			
			// Should not throw
			expect(() => {
				validateSubjectAuthorization({ externalSubjectId }, context);
			}).not.toThrow();
		});

		it('should allow request with externalSubjectId matching token external_id claim (snake_case)', () => {
			const externalSubjectId = 'legitimate-external-999';
			const token = createJWT({
				sub: 'some-subject',
				external_id: externalSubjectId,
				exp: Math.floor(Date.now() / 1000) + 3600,
			});
			const context = createMockContext(`Bearer ${token}`);
			
			// Should not throw
			expect(() => {
				validateSubjectAuthorization({ externalSubjectId }, context);
			}).not.toThrow();
		});
	});

	describe('Exploit Prevention: Combined subject identifiers', () => {
		it('should reject when both identifiers provided but neither matches token', () => {
			const token = createJWT({
				sub: 'attacker-subject',
				externalId: 'attacker-external',
				exp: Math.floor(Date.now() / 1000) + 3600,
			});
			const context = createMockContext(`Bearer ${token}`);
			
			expect(() => {
				validateSubjectAuthorization(
					{
						subjectId: 'victim-subject',
						externalSubjectId: 'victim-external',
					},
					context
				);
			}).toThrow(ORPCError);
		});

		it('should allow when subjectId matches token even if externalSubjectId differs', () => {
			const subjectId = 'legitimate-subject';
			const token = createJWT({
				sub: subjectId,
				externalId: 'different-external',
				exp: Math.floor(Date.now() / 1000) + 3600,
			});
			const context = createMockContext(`Bearer ${token}`);
			
			// Should not throw - subjectId match is sufficient
			expect(() => {
				validateSubjectAuthorization(
					{
						subjectId,
						externalSubjectId: 'some-other-external',
					},
					context
				);
			}).not.toThrow();
		});

		it('should allow when externalSubjectId matches token even if subjectId differs', () => {
			const externalSubjectId = 'legitimate-external';
			const token = createJWT({
				sub: 'different-subject',
				externalId: externalSubjectId,
				exp: Math.floor(Date.now() / 1000) + 3600,
			});
			const context = createMockContext(`Bearer ${token}`);
			
			// Should not throw - externalSubjectId match is sufficient
			expect(() => {
				validateSubjectAuthorization(
					{
						subjectId: 'some-other-subject',
						externalSubjectId,
					},
					context
				);
			}).not.toThrow();
		});
	});

	describe('Token validation', () => {
		it('should reject invalid authorization header format (missing Bearer prefix)', () => {
			const token = createJWT({
				sub: 'subject-123',
				exp: Math.floor(Date.now() / 1000) + 3600,
			});
			const context = createMockContext(token); // Missing "Bearer " prefix
			
			expect(() => {
				validateSubjectAuthorization({ subjectId: 'subject-123' }, context);
			}).toThrow(ORPCError);

			try {
				validateSubjectAuthorization({ subjectId: 'subject-123' }, context);
			} catch (error) {
				expect(error).toBeInstanceOf(ORPCError);
				expect((error as ORPCError).data?.reason).toBe('invalid_authorization_format');
				expect((error as ORPCError).message).toContain('Expected: Bearer <token>');
			}
		});

		it('should reject malformed JWT (not 3 parts)', () => {
			const context = createMockContext('Bearer invalid.token');
			
			expect(() => {
				validateSubjectAuthorization({ subjectId: 'subject-123' }, context);
			}).toThrow(ORPCError);

			try {
				validateSubjectAuthorization({ subjectId: 'subject-123' }, context);
			} catch (error) {
				expect(error).toBeInstanceOf(ORPCError);
				expect((error as ORPCError).data?.reason).toBe('invalid_token');
			}
		});

		it('should reject JWT with invalid base64 encoding', () => {
			const context = createMockContext('Bearer header.!!!invalid!!!.signature');
			
			expect(() => {
				validateSubjectAuthorization({ subjectId: 'subject-123' }, context);
			}).toThrow(ORPCError);

			try {
				validateSubjectAuthorization({ subjectId: 'subject-123' }, context);
			} catch (error) {
				expect(error).toBeInstanceOf(ORPCError);
				expect((error as ORPCError).data?.reason).toBe('invalid_token');
			}
		});

		it('should reject JWT missing subject claim', () => {
			const token = createJWT({
				// Missing 'sub' claim
				exp: Math.floor(Date.now() / 1000) + 3600,
			});
			const context = createMockContext(`Bearer ${token}`);
			
			expect(() => {
				validateSubjectAuthorization({ subjectId: 'subject-123' }, context);
			}).toThrow(ORPCError);

			try {
				validateSubjectAuthorization({ subjectId: 'subject-123' }, context);
			} catch (error) {
				expect(error).toBeInstanceOf(ORPCError);
				expect((error as ORPCError).data?.reason).toBe('invalid_token');
			}
		});

		it('should reject expired JWT', () => {
			const token = createJWT({
				sub: 'subject-123',
				exp: Math.floor(Date.now() / 1000) - 3600, // Expired 1 hour ago
			});
			const context = createMockContext(`Bearer ${token}`);
			
			expect(() => {
				validateSubjectAuthorization({ subjectId: 'subject-123' }, context);
			}).toThrow(ORPCError);

			try {
				validateSubjectAuthorization({ subjectId: 'subject-123' }, context);
			} catch (error) {
				expect(error).toBeInstanceOf(ORPCError);
				expect((error as ORPCError).data?.reason).toBe('invalid_token');
			}
		});

		it('should accept JWT without expiration claim', () => {
			const subjectId = 'subject-123';
			const token = createJWT({
				sub: subjectId,
				// No exp claim
			});
			const context = createMockContext(`Bearer ${token}`);
			
			// Should not throw - tokens without exp are allowed
			expect(() => {
				validateSubjectAuthorization({ subjectId }, context);
			}).not.toThrow();
		});

		it('should accept JWT with future expiration', () => {
			const subjectId = 'subject-123';
			const token = createJWT({
				sub: subjectId,
				exp: Math.floor(Date.now() / 1000) + 3600, // Expires in 1 hour
			});
			const context = createMockContext(`Bearer ${token}`);
			
			// Should not throw
			expect(() => {
				validateSubjectAuthorization({ subjectId }, context);
			}).not.toThrow();
		});

		it('should handle Bearer prefix case-insensitively', () => {
			const subjectId = 'subject-123';
			const token = createJWT({
				sub: subjectId,
				exp: Math.floor(Date.now() / 1000) + 3600,
			});
			const context = createMockContext(`bearer ${token}`); // lowercase
			
			// Should not throw
			expect(() => {
				validateSubjectAuthorization({ subjectId }, context);
			}).not.toThrow();
		});
	});

	describe('Logging behavior', () => {
		it('should log warning when subject identifier provided without authentication', () => {
			const context = createMockContext();
			const warnSpy = vi.spyOn(context.logger!, 'warn');
			
			try {
				validateSubjectAuthorization({ subjectId: 'subject-123' }, context);
			} catch {
				// Expected to throw
			}
			
			expect(warnSpy).toHaveBeenCalledWith(
				'Subject identifier provided without authentication',
				expect.objectContaining({
					hasSubjectId: true,
					hasExternalSubjectId: false,
				})
			);
		});

		it('should log warning when subject mismatch occurs', () => {
			const token = createJWT({
				sub: 'attacker-subject',
				externalId: 'attacker-external',
				exp: Math.floor(Date.now() / 1000) + 3600,
			});
			const context = createMockContext(`Bearer ${token}`);
			const warnSpy = vi.spyOn(context.logger!, 'warn');
			
			try {
				validateSubjectAuthorization(
					{ subjectId: 'victim-subject' },
					context
				);
			} catch {
				// Expected to throw
			}
			
			expect(warnSpy).toHaveBeenCalledWith(
				'Subject authorization failed: token subject does not match requested subject',
				expect.objectContaining({
					authenticatedSubjectId: 'attacker-subject',
					requestedSubjectId: 'victim-subject',
				})
			);
		});
	});

	describe('Edge cases', () => {
		it('should allow empty string subject identifiers (treated as falsy)', () => {
			const context = createMockContext();
			
			// Empty strings are falsy in JavaScript, so they don't require authentication
			// This is acceptable behavior - empty strings are effectively "no identifier"
			expect(() => {
				validateSubjectAuthorization({ subjectId: '' }, context);
			}).not.toThrow();
		});

		it('should handle whitespace in Bearer token', () => {
			const subjectId = 'subject-123';
			const token = createJWT({
				sub: subjectId,
				exp: Math.floor(Date.now() / 1000) + 3600,
			});
			const context = createMockContext(`Bearer   ${token}`); // Extra spaces
			
			// Should not throw - regex handles extra whitespace
			expect(() => {
				validateSubjectAuthorization({ subjectId }, context);
			}).not.toThrow();
		});

		it('should reject when headers object is missing', () => {
			const context = {
				headers: undefined,
				logger: {
					warn: vi.fn(),
					error: vi.fn(),
					info: vi.fn(),
					debug: vi.fn(),
				},
			} as unknown as C15TContext;
			
			expect(() => {
				validateSubjectAuthorization({ subjectId: 'subject-123' }, context);
			}).toThrow(ORPCError);
		});
	});

	describe('Real-world attack scenarios', () => {
		it('should prevent attacker from creating consent for known victim subjectId', () => {
			// Scenario: Attacker knows victim's subjectId from a previous interaction
			const victimSubjectId = 'user-12345-from-public-api';
			const context = createMockContext(); // No auth token
			
			// Attacker tries to create consent for victim
			expect(() => {
				validateSubjectAuthorization(
					{ subjectId: victimSubjectId },
					context
				);
			}).toThrow(ORPCError);
		});

		it('should prevent attacker from querying consent state of victim', () => {
			// Scenario: Attacker tries to verify consent for a victim to learn their preferences
			const victimExternalId = 'email:victim@example.com';
			const context = createMockContext(); // No auth token
			
			// Attacker tries to query victim's consent
			expect(() => {
				validateSubjectAuthorization(
					{ externalSubjectId: victimExternalId },
					context
				);
			}).toThrow(ORPCError);
		});

		it('should prevent attacker from using stolen/guessed subjectId with their own token', () => {
			// Scenario: Attacker has their own valid token but tries to use victim's ID
			const attackerToken = createJWT({
				sub: 'attacker-subject-999',
				exp: Math.floor(Date.now() / 1000) + 3600,
			});
			const context = createMockContext(`Bearer ${attackerToken}`);
			const victimSubjectId = 'victim-subject-123';
			
			// Attacker tries to impersonate victim
			expect(() => {
				validateSubjectAuthorization(
					{ subjectId: victimSubjectId },
					context
				);
			}).toThrow(ORPCError);
		});

		it('should allow legitimate user to create consent for themselves', () => {
			// Scenario: Legitimate user with valid token creates consent for themselves
			const userSubjectId = 'user-legitimate-456';
			const userToken = createJWT({
				sub: userSubjectId,
				exp: Math.floor(Date.now() / 1000) + 3600,
			});
			const context = createMockContext(`Bearer ${userToken}`);
			
			// User creates consent for themselves - should succeed
			expect(() => {
				validateSubjectAuthorization(
					{ subjectId: userSubjectId },
					context
				);
			}).not.toThrow();
		});

		it('should allow anonymous consent creation without any identifiers', () => {
			// Scenario: Anonymous user creates consent without providing subject identifiers
			const context = createMockContext(); // No auth token
			
			// Anonymous consent creation - should succeed
			expect(() => {
				validateSubjectAuthorization({}, context);
			}).not.toThrow();
		});
	});
});
