import { spawnSync } from 'node:child_process';
import * as core from '@actions/core';
import * as github from '@actions/github';

function isForkPullRequest(): boolean {
	const pr = (
		github.context?.payload as unknown as {
			pull_request?: { head?: { repo?: { full_name?: string } } };
		}
	)?.pull_request;
	if (!pr) {
		return false;
	}
	const headRepo = pr.head?.repo?.full_name || '';
	const thisRepo = `${github.context.repo.owner}/${github.context.repo.repo}`;
	return headRepo.toLowerCase() !== thisRepo.toLowerCase();
}

/**
 * Sanitizes the environment by removing INPUT_* variables and other CI secrets
 * before spawning the setup-docs script.
 *
 * This prevents the fetched documentation repository and its dependencies from
 * accessing GitHub Action inputs (tokens, private keys) during execution.
 *
 * @param consentGitToken - The token needed for repository authentication
 * @returns A sanitized environment with only CONSENT_GIT_TOKEN and safe variables
 */
function sanitizeEnvironmentForSetup(
	consentGitToken?: string
): NodeJS.ProcessEnv {
	const sanitized: NodeJS.ProcessEnv = {};

	// Copy all environment variables except sensitive ones
	for (const [key, value] of Object.entries(process.env)) {
		// Remove GitHub Actions input variables (INPUT_*)
		// These contain all action inputs including tokens and private keys
		if (key.startsWith('INPUT_')) {
			continue;
		}

		// Remove other common CI secret patterns
		if (
			key.includes('TOKEN') ||
			key.includes('SECRET') ||
			key.includes('KEY') ||
			key.includes('PASSWORD') ||
			key.includes('CREDENTIAL')
		) {
			// Allow known safe variables
			if (
				key === 'NODE_AUTH_TOKEN' || // May be needed for npm registry
				key === 'PATH' ||
				key === 'HOME' ||
				key === 'USER' ||
				key === 'SHELL'
			) {
				sanitized[key] = value;
			}
			continue;
		}

		// Copy safe environment variables
		sanitized[key] = value;
	}

	// Add only the required authentication token
	sanitized.CONSENT_GIT_TOKEN =
		consentGitToken || process.env.CONSENT_GIT_TOKEN || '';

	return sanitized;
}

export function setupDocsWithScript(consentGitToken?: string): void {
	const isPrFromFork = isForkPullRequest();
	if (isPrFromFork) {
		core.info('PR from fork detected: skipping docs setup');
		return;
	}
	const env = sanitizeEnvironmentForSetup(consentGitToken);
	core.info('Running docs setup script via pnpm tsx scripts/setup-docs.ts');
	const result = spawnSync(
		'pnpm',
		['tsx', 'scripts/setup-docs.ts', '--vercel'],
		{ stdio: 'inherit', env }
	);
	if (result.error) {
		throw result.error;
	}
	if (typeof result.status === 'number' && result.status !== 0) {
		throw new Error(`setup-docs script failed with exit code ${result.status}`);
	}
}
