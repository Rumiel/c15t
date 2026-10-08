/**
 * Security tests for setup-docs.ts environment sanitization
 *
 * These tests verify that the mitigation for the pentest finding
 * "Fetched documentation project scripts execute with CI secrets" is effective.
 *
 * The vulnerability allowed malicious code in the fetched documentation repository
 * to access CI secrets (INPUT_* variables, tokens, private keys) during execution.
 *
 * The mitigation sanitizes the environment before spawning child processes that
 * execute untrusted code from the fetched repository.
 */

import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

// Mock @actions/core
const mockCore = {
	info: vi.fn(),
	error: vi.fn(),
	setFailed: vi.fn(),
};

vi.mock('@actions/core', () => mockCore);

// Mock @actions/github with mutable context
const mockGithubContext = {
	payload: {},
	repo: {
		owner: 'test-owner',
		repo: 'test-repo',
	},
};

vi.mock('@actions/github', () => ({
	context: mockGithubContext,
}));

// Mock child_process.spawnSync
const mockSpawnSync = vi.fn();
vi.mock('node:child_process', () => ({
	spawnSync: mockSpawnSync,
}));

describe('setup-docs environment sanitization', () => {
	let originalEnv: NodeJS.ProcessEnv;

	beforeEach(() => {
		// Save original environment
		originalEnv = { ...process.env };

		// Clear all mocks
		vi.clearAllMocks();

		// Reset github context
		mockGithubContext.payload = {};
		mockGithubContext.repo = {
			owner: 'test-owner',
			repo: 'test-repo',
		};

		// Setup mock spawnSync to succeed by default
		mockSpawnSync.mockReturnValue({
			status: 0,
			signal: null,
			output: [],
			pid: 12345,
			stdout: null,
			stderr: null,
		});
	});

	afterEach(() => {
		// Restore original environment
		process.env = originalEnv;
		vi.resetModules();
	});

	test('should remove INPUT_GITHUB_APP_PRIVATE_KEY from environment', async () => {
		// Setup: Add sensitive INPUT_* variables that should be removed
		process.env.INPUT_GITHUB_APP_PRIVATE_KEY = 'secret-private-key-12345';
		process.env.INPUT_GITHUB_TOKEN = 'ghp_secret_token_67890';
		process.env.INPUT_VERCEL_TOKEN = 'vercel_secret_token_abcde';
		process.env.CONSENT_GIT_TOKEN = 'consent_token_xyz';

		// Import and execute the function
		const { setupDocsWithScript } = await import(
			'../src/steps/setup-docs.ts'
		);
		setupDocsWithScript('test-token');

		// Verify spawnSync was called
		expect(mockSpawnSync).toHaveBeenCalledTimes(1);

		// Get the environment passed to spawnSync
		const spawnCall = mockSpawnSync.mock.calls[0];
		const spawnOptions = spawnCall[2];
		const sanitizedEnv = spawnOptions?.env;

		// Assert: INPUT_* variables should be removed
		expect(sanitizedEnv).toBeDefined();
		expect(sanitizedEnv?.INPUT_GITHUB_APP_PRIVATE_KEY).toBeUndefined();
		expect(sanitizedEnv?.INPUT_GITHUB_TOKEN).toBeUndefined();
		expect(sanitizedEnv?.INPUT_VERCEL_TOKEN).toBeUndefined();

		// Assert: CONSENT_GIT_TOKEN should be present (needed for authentication)
		expect(sanitizedEnv?.CONSENT_GIT_TOKEN).toBe('test-token');
	});

	test('should remove all INPUT_* variables from environment', async () => {
		// Setup: Add multiple INPUT_* variables
		process.env.INPUT_GITHUB_APP_PRIVATE_KEY = 'secret-key';
		process.env.INPUT_GITHUB_TOKEN = 'secret-token';
		process.env.INPUT_VERCEL_TOKEN = 'vercel-token';
		process.env.INPUT_CUSTOM_SECRET = 'custom-secret';
		process.env.INPUT_API_KEY = 'api-key';

		const { setupDocsWithScript } = await import(
			'../src/steps/setup-docs.ts'
		);
		setupDocsWithScript('test-token');

		const spawnCall = mockSpawnSync.mock.calls[0];
		const sanitizedEnv = spawnCall[2]?.env;

		// Assert: All INPUT_* variables should be removed
		expect(sanitizedEnv).toBeDefined();
		const inputKeys = Object.keys(sanitizedEnv || {}).filter((key) =>
			key.startsWith('INPUT_')
		);
		expect(inputKeys).toHaveLength(0);
	});

	test('should remove TOKEN, SECRET, KEY, PASSWORD, CREDENTIAL patterns', async () => {
		// Setup: Add various secret patterns
		process.env.GITHUB_TOKEN = 'github-token';
		process.env.API_SECRET = 'api-secret';
		process.env.PRIVATE_KEY = 'private-key';
		process.env.DB_PASSWORD = 'db-password';
		process.env.AWS_CREDENTIAL = 'aws-credential';
		process.env.SOME_TOKEN = 'some-token';

		const { setupDocsWithScript } = await import(
			'../src/steps/setup-docs.ts'
		);
		setupDocsWithScript('test-token');

		const spawnCall = mockSpawnSync.mock.calls[0];
		const sanitizedEnv = spawnCall[2]?.env;

		// Assert: Secret patterns should be removed
		expect(sanitizedEnv).toBeDefined();
		expect(sanitizedEnv?.GITHUB_TOKEN).toBeUndefined();
		expect(sanitizedEnv?.API_SECRET).toBeUndefined();
		expect(sanitizedEnv?.PRIVATE_KEY).toBeUndefined();
		expect(sanitizedEnv?.DB_PASSWORD).toBeUndefined();
		expect(sanitizedEnv?.AWS_CREDENTIAL).toBeUndefined();
		expect(sanitizedEnv?.SOME_TOKEN).toBeUndefined();
	});

	test('should preserve safe environment variables', async () => {
		// Setup: Add safe variables that should be preserved
		process.env.PATH = '/usr/bin:/bin';
		process.env.HOME = '/home/user';
		process.env.USER = 'testuser';
		process.env.SHELL = '/bin/bash';
		process.env.NODE_ENV = 'test';
		process.env.CI = 'true';

		const { setupDocsWithScript } = await import(
			'../src/steps/setup-docs.ts'
		);
		setupDocsWithScript('test-token');

		const spawnCall = mockSpawnSync.mock.calls[0];
		const sanitizedEnv = spawnCall[2]?.env;

		// Assert: Safe variables should be preserved
		expect(sanitizedEnv).toBeDefined();
		expect(sanitizedEnv?.PATH).toBe('/usr/bin:/bin');
		expect(sanitizedEnv?.HOME).toBe('/home/user');
		expect(sanitizedEnv?.USER).toBe('testuser');
		expect(sanitizedEnv?.SHELL).toBe('/bin/bash');
		expect(sanitizedEnv?.NODE_ENV).toBe('test');
		expect(sanitizedEnv?.CI).toBe('true');
	});

	test('should preserve NODE_AUTH_TOKEN for npm registry access', async () => {
		// Setup: NODE_AUTH_TOKEN is needed for npm registry authentication
		process.env.NODE_AUTH_TOKEN = 'npm-registry-token';
		process.env.OTHER_TOKEN = 'should-be-removed';

		const { setupDocsWithScript } = await import(
			'../src/steps/setup-docs.ts'
		);
		setupDocsWithScript('test-token');

		const spawnCall = mockSpawnSync.mock.calls[0];
		const sanitizedEnv = spawnCall[2]?.env;

		// Assert: NODE_AUTH_TOKEN should be preserved (allowlisted)
		expect(sanitizedEnv).toBeDefined();
		expect(sanitizedEnv?.NODE_AUTH_TOKEN).toBe('npm-registry-token');
		// But other tokens should be removed
		expect(sanitizedEnv?.OTHER_TOKEN).toBeUndefined();
	});

	test('should add CONSENT_GIT_TOKEN to sanitized environment', async () => {
		// Setup: Clean environment
		delete process.env.CONSENT_GIT_TOKEN;

		const { setupDocsWithScript } = await import(
			'../src/steps/setup-docs.ts'
		);
		setupDocsWithScript('provided-token');

		const spawnCall = mockSpawnSync.mock.calls[0];
		const sanitizedEnv = spawnCall[2]?.env;

		// Assert: CONSENT_GIT_TOKEN should be set from parameter
		expect(sanitizedEnv).toBeDefined();
		expect(sanitizedEnv?.CONSENT_GIT_TOKEN).toBe('provided-token');
	});

	test('should use environment CONSENT_GIT_TOKEN if parameter not provided', async () => {
		// Setup: Set CONSENT_GIT_TOKEN in environment
		process.env.CONSENT_GIT_TOKEN = 'env-token';

		const { setupDocsWithScript } = await import(
			'../src/steps/setup-docs.ts'
		);
		setupDocsWithScript(); // No parameter

		const spawnCall = mockSpawnSync.mock.calls[0];
		const sanitizedEnv = spawnCall[2]?.env;

		// Assert: CONSENT_GIT_TOKEN should be set from environment
		expect(sanitizedEnv).toBeDefined();
		expect(sanitizedEnv?.CONSENT_GIT_TOKEN).toBe('env-token');
	});

	test('should prevent exploit scenario: malicious code cannot access INPUT_GITHUB_APP_PRIVATE_KEY', async () => {
		// Reproduce the exploit scenario from the pentest
		// Step 2: The composite action exposes the GitHub App private key
		process.env.INPUT_GITHUB_APP_PRIVATE_KEY = 'malicious-target-key';
		process.env.INPUT_GITHUB_TOKEN = 'malicious-target-token';
		process.env.INPUT_VERCEL_TOKEN = 'malicious-target-vercel';

		const { setupDocsWithScript } = await import(
			'../src/steps/setup-docs.ts'
		);
		setupDocsWithScript('consent-token');

		const spawnCall = mockSpawnSync.mock.calls[0];
		const sanitizedEnv = spawnCall[2]?.env;

		// Assert: The exploit is mitigated - INPUT_* variables are not accessible
		expect(sanitizedEnv).toBeDefined();
		expect(sanitizedEnv?.INPUT_GITHUB_APP_PRIVATE_KEY).toBeUndefined();
		expect(sanitizedEnv?.INPUT_GITHUB_TOKEN).toBeUndefined();
		expect(sanitizedEnv?.INPUT_VERCEL_TOKEN).toBeUndefined();

		// Verify that the environment is actually sanitized (not just process.env)
		expect(sanitizedEnv).not.toBe(process.env);
		expect(Object.keys(sanitizedEnv || {}).length).toBeLessThan(
			Object.keys(process.env).length
		);
	});

	test('should skip docs setup for fork pull requests', async () => {
		// Setup: Mock a fork PR scenario
		mockGithubContext.payload = {
			pull_request: {
				head: {
					repo: {
						full_name: 'fork-owner/fork-repo',
					},
				},
			},
		};

		const { setupDocsWithScript } = await import(
			'../src/steps/setup-docs.ts'
		);
		setupDocsWithScript('test-token');

		// Assert: spawnSync should not be called for fork PRs
		expect(mockSpawnSync).not.toHaveBeenCalled();
	});

	test('should execute setup script for non-fork scenarios', async () => {
		// Setup: Mock a non-fork scenario
		mockGithubContext.payload = {
			pull_request: {
				head: {
					repo: {
						full_name: 'test-owner/test-repo',
					},
				},
			},
		};

		const { setupDocsWithScript } = await import(
			'../src/steps/setup-docs.ts'
		);
		setupDocsWithScript('test-token');

		// Assert: spawnSync should be called for non-fork PRs
		expect(mockSpawnSync).toHaveBeenCalledTimes(1);
		expect(mockSpawnSync).toHaveBeenCalledWith(
			'pnpm',
			['tsx', 'scripts/setup-docs.ts', '--vercel'],
			expect.objectContaining({
				stdio: 'inherit',
				env: expect.any(Object),
			})
		);
	});

	test('should handle empty environment gracefully', async () => {
		// Setup: Clear most environment variables
		process.env = {
			PATH: '/usr/bin',
		};

		const { setupDocsWithScript } = await import(
			'../src/steps/setup-docs.ts'
		);
		setupDocsWithScript('test-token');

		const spawnCall = mockSpawnSync.mock.calls[0];
		const sanitizedEnv = spawnCall[2]?.env;

		// Assert: Should still work with minimal environment
		expect(sanitizedEnv).toBeDefined();
		expect(sanitizedEnv?.CONSENT_GIT_TOKEN).toBe('test-token');
		expect(sanitizedEnv?.PATH).toBe('/usr/bin');
	});

	test('should not leak secrets through environment inheritance', async () => {
		// Setup: Add secrets that should not be inherited
		process.env.INPUT_SECRET_1 = 'secret1';
		process.env.INPUT_SECRET_2 = 'secret2';
		process.env.GITHUB_TOKEN = 'github-secret';
		process.env.SAFE_VAR = 'safe-value';

		const { setupDocsWithScript } = await import(
			'../src/steps/setup-docs.ts'
		);
		setupDocsWithScript('test-token');

		const spawnCall = mockSpawnSync.mock.calls[0];
		const sanitizedEnv = spawnCall[2]?.env;

		// Assert: Verify the environment is a new object, not a reference
		expect(sanitizedEnv).toBeDefined();
		expect(sanitizedEnv).not.toBe(process.env);

		// Assert: Secrets should not be present
		const allKeys = Object.keys(sanitizedEnv || {});
		const secretKeys = allKeys.filter(
			(key) =>
				key.startsWith('INPUT_') ||
				(key.includes('SECRET') && key !== 'SAFE_VAR')
		);
		expect(secretKeys).toHaveLength(0);

		// Assert: Safe variables should be present
		expect(sanitizedEnv?.SAFE_VAR).toBe('safe-value');
	});
});
