import type {
	ActivityPayload,
	AdminSession,
	AdminUser,
	AlertsPayload,
	ApiErrorPayload,
	CachePreview,
	CapturedPackage,
	ConfigPatch,
	ConfigPayload,
	ConfigPreview,
	ConfigProposal,
	JobsPage,
	MetricsHistory,
	Mirror,
	OperationJob,
	OverviewPayload,
	PackageFilters,
	PackagesPage,
	Permission,
	SessionState,
	StoragePayload,
	SyncTarget,
	TimeRange
} from '$lib/types/admin';

const isErrorPayload = (value: unknown): value is ApiErrorPayload =>
	typeof value === 'object' &&
	value !== null &&
	'error' in value &&
	typeof value.error === 'string';

/** Structured HTTP error returned by the Ferrum admin API. */
export class AdminApiError extends Error {
	constructor(
		message: string,
		readonly status: number,
		readonly code: string,
		readonly retryAfter: string | null
	) {
		super(message);
		this.name = 'AdminApiError';
	}
}

const extractError = async (response: Response): Promise<AdminApiError> => {
	const payload: unknown = await response.json().catch(() => null);
	return new AdminApiError(
		isErrorPayload(payload) ? payload.error : `Request failed (${response.status})`,
		response.status,
		isErrorPayload(payload) && typeof payload.code === 'string' ? payload.code : 'request_failed',
		response.headers.get('retry-after')
	);
};

const requestJson = async <T>(
	path: string,
	options: RequestInit = {},
	csrfToken: string | null = null
): Promise<T> => {
	const headers = new Headers(options.headers);
	if (options.body !== undefined) headers.set('content-type', 'application/json');
	if (csrfToken !== null) headers.set('x-ferrum-csrf', csrfToken);
	const response = await fetch(path, {
		...options,
		credentials: 'same-origin',
		cache: 'no-store',
		headers
	});
	if (response.ok === false) throw await extractError(response);
	if (response.status === 204) return undefined as T;
	return (await response.json()) as T;
};

const buildQuery = (values: object): string => {
	const params = new URLSearchParams();
	for (const [key, value] of Object.entries(values))
		if (value !== undefined && value !== null && value !== '')
			params.set(key, String(value));
	return params.size > 0 ? `?${params}` : '';
};

const postJson = <T>(
	path: string,
	csrfToken: string | null,
	body: object,
	signal?: AbortSignal
): Promise<T> =>
	requestJson<T>(
		`/api/admin/${path}`,
		{
			method: 'POST',
			body: JSON.stringify(body),
			signal
		},
		csrfToken
	);

/**
 * Fetches the current admin session and first-time setup status.
 * @param signal - Optional abort signal.
 * @returns Current session state.
 */
export const fetchSession = (signal?: AbortSignal): Promise<SessionState> =>
	requestJson<SessionState>('/api/admin/session', { signal });

/**
 * Completes first-time administrator setup and starts an authenticated session.
 * @param username - Initial administrator username.
 * @param displayName - Initial display name.
 * @param password - Initial administrator password.
 * @param bootstrapToken - One-time local bootstrap token.
 * @param signal - Optional abort signal.
 * @returns Updated session state.
 */
export const submitInitialSetup = (
	username: string,
	displayName: string,
	password: string,
	bootstrapToken: string,
	signal?: AbortSignal
): Promise<SessionState> =>
	requestJson<SessionState>('/api/admin/setup', {
		method: 'POST',
		body: JSON.stringify({ username, displayName, password, bootstrapToken }),
		signal
	});

/**
 * Authenticates an admin user with username and password.
 * @param username - Account username.
 * @param password - Account password.
 * @param signal - Optional abort signal.
 * @returns Authenticated session state.
 */
export const loginAdmin = (
	username: string,
	password: string,
	signal?: AbortSignal
): Promise<SessionState> =>
	requestJson<SessionState>('/api/admin/login', {
		method: 'POST',
		body: JSON.stringify({ username, password }),
		signal
	});

/**
 * Signs out the current admin session.
 * @param csrfToken - Active session CSRF token.
 * @param signal - Optional abort signal.
 */
export const logoutAdmin = (
	csrfToken: string | null,
	signal?: AbortSignal
): Promise<void> =>
	requestJson<void>('/api/admin/logout', { method: 'POST', signal }, csrfToken);

/**
 * Fetches the live mirror status, storage usage, and traffic statistics.
 * @param signal - Optional abort signal.
 * @returns Complete gateway overview payload.
 */
export const fetchOverview = (signal?: AbortSignal): Promise<OverviewPayload> =>
	requestJson<OverviewPayload>('/api/admin/overview', { signal });

/**
 * Updates the currently authenticated user's own account profile or password.
 * @param csrfToken - Active session CSRF token.
 * @param payload - Account fields to update.
 * @param signal - Optional abort signal.
 * @returns Updated user profile.
 */
export const updateOwnAccount = async (
	csrfToken: string | null,
	payload: {
		username?: string;
		displayName?: string;
		currentPassword?: string;
		newPassword?: string;
	},
	signal?: AbortSignal
): Promise<AdminUser> => {
	const result = await requestJson<{ user: AdminUser }>(
		'/api/admin/account',
		{
			method: 'PUT',
			body: JSON.stringify(payload),
			signal
		},
		csrfToken
	);
	return result.user;
};

/**
 * Lists all configured admin dashboard users.
 * @param signal - Optional abort signal.
 * @returns Array of admin users.
 */
export const fetchUsers = async (signal?: AbortSignal): Promise<AdminUser[]> => {
	const result = await requestJson<{ users: AdminUser[] }>('/api/admin/users', { signal });
	return result.users;
};

/**
 * Creates a new admin dashboard user with the specified permissions.
 * @param csrfToken - Active session CSRF token.
 * @param payload - New user credentials and permissions.
 * @param signal - Optional abort signal.
 * @returns Created user profile.
 */
export const createAdminUser = async (
	csrfToken: string | null,
	payload: {
		username: string;
		displayName: string;
		password: string;
		permissions: Permission[];
	},
	signal?: AbortSignal
): Promise<AdminUser> => {
	const result = await requestJson<{ user: AdminUser }>(
		'/api/admin/users',
		{
			method: 'POST',
			body: JSON.stringify(payload),
			signal
		},
		csrfToken
	);
	return result.user;
};

/**
 * Updates an existing user's display name, permissions, password, or disabled state.
 * @param csrfToken - Active session CSRF token.
 * @param userId - Target user ID.
 * @param payload - Updated fields.
 * @param signal - Optional abort signal.
 * @returns Updated user profile.
 */
export const updateAdminUser = async (
	csrfToken: string | null,
	userId: string,
	payload: {
		displayName?: string;
		password?: string;
		permissions: Permission[];
		disabled?: boolean;
	},
	signal?: AbortSignal
): Promise<AdminUser> => {
	const result = await requestJson<{ user: AdminUser }>(
		`/api/admin/users/${encodeURIComponent(userId)}`,
		{
			method: 'PUT',
			body: JSON.stringify(payload),
			signal
		},
		csrfToken
	);
	return result.user;
};

/**
 * Deletes an admin user account by ID.
 * @param csrfToken - Active session CSRF token.
 * @param userId - Target user ID to remove.
 * @param signal - Optional abort signal.
 */
export const deleteAdminUser = (
	csrfToken: string | null,
	userId: string,
	signal?: AbortSignal
): Promise<void> =>
	requestJson<void>(
		`/api/admin/users/${encodeURIComponent(userId)}`,
		{ method: 'DELETE', signal },
		csrfToken
	);

/**
 * Lists the current user's active sessions without exposing credentials.
 * @param signal - Optional abort signal.
 * @returns Active sessions for the caller.
 */
export const fetchOwnSessions = async (signal?: AbortSignal): Promise<AdminSession[]> => {
	const result = await requestJson<{ sessions: AdminSession[] }>(
		'/api/admin/sessions',
		{ signal }
	);
	return result.sessions;
};

/**
 * Revokes one of the current user's sessions.
 * @param csrfToken - Active session CSRF token.
 * @param sessionId - Session ID to revoke.
 * @param signal - Optional abort signal.
 */
export const revokeOwnSession = (
	csrfToken: string | null,
	sessionId: string,
	signal?: AbortSignal
): Promise<void> =>
	requestJson<void>(
		`/api/admin/sessions/${encodeURIComponent(sessionId)}`,
		{ method: 'DELETE', signal },
		csrfToken
	);

/**
 * Lists active sessions for a specific user (requires `manage_users`).
 * @param userId - Target user ID.
 * @param signal - Optional abort signal.
 * @returns Active sessions for the target user.
 */
export const fetchUserSessions = async (
	userId: string,
	signal?: AbortSignal
): Promise<AdminSession[]> => {
	const result = await requestJson<{ sessions: AdminSession[] }>(
		`/api/admin/users/${encodeURIComponent(userId)}/sessions`,
		{ signal }
	);
	return result.sessions;
};

/**
 * Revokes a specific session belonging to another user (requires `manage_users`).
 * @param csrfToken - Active session CSRF token.
 * @param userId - Target user ID.
 * @param sessionId - Target session ID.
 * @param signal - Optional abort signal.
 */
export const revokeUserSession = (
	csrfToken: string | null,
	userId: string,
	sessionId: string,
	signal?: AbortSignal
): Promise<void> =>
	requestJson<void>(
		`/api/admin/users/${encodeURIComponent(userId)}/sessions/${encodeURIComponent(sessionId)}`,
		{ method: 'DELETE', signal },
		csrfToken
	);

/**
 * Lists all compiled repository suite candidates and configured mirror health.
 * @param signal - Optional abort signal.
 * @returns Mirrors list and snapshot timestamp.
 */
export const fetchMirrors = (
	signal?: AbortSignal
): Promise<{ mirrors: Mirror[]; sampledAt: number }> =>
	requestJson<{ mirrors: Mirror[]; sampledAt: number }>('/api/admin/mirrors', { signal });

/**
 * Fetches detailed status for a single repository suite candidate.
 * @param repository - Repository name.
 * @param suite - Suite name.
 * @param signal - Optional abort signal.
 * @returns Mirror detail payload.
 */
export const fetchMirrorDetail = (
	repository: string,
	suite: string,
	signal?: AbortSignal
): Promise<{ mirror: Mirror; sampledAt: number }> =>
	requestJson<{ mirror: Mirror; sampledAt: number }>(
		`/api/admin/mirrors/${encodeURIComponent(repository)}/${encodeURIComponent(suite)}`,
		{ signal }
	);

/**
 * Schedules an authenticated metadata synchronization job for the specified targets.
 * @param csrfToken - Active session CSRF token.
 * @param body - Targets, idempotency key, and operator reason.
 * @param signal - Optional abort signal.
 * @returns Created or replayed operation job receipt.
 */
export const triggerSync = (
	csrfToken: string | null,
	body: { targets: SyncTarget[]; idempotencyKey: string; reason: string },
	signal?: AbortSignal
): Promise<{ job: OperationJob; triggered: string[] }> =>
	postJson<{ job: OperationJob; triggered: string[] }>('sync', csrfToken, body, signal);

/**
 * Lists recent operation jobs and live per-suite synchronizer phases.
 * @param filters - Optional pagination and state filters.
 * @param signal - Optional abort signal.
 * @returns Paginated jobs and active suite states.
 */
export const fetchJobs = (
	filters: { limit?: number; cursor?: string; kind?: string; state?: string } = {},
	signal?: AbortSignal
): Promise<JobsPage> =>
	requestJson<JobsPage>(`/api/admin/jobs${buildQuery(filters)}`, { signal });

/**
 * Fetches detailed per-target status for one operation job.
 * @param jobId - Operation job ID.
 * @param signal - Optional abort signal.
 * @returns Operation job detail.
 */
export const fetchJobDetail = (
	jobId: string,
	signal?: AbortSignal
): Promise<{ job: OperationJob }> =>
	requestJson<{ job: OperationJob }>(
		`/api/admin/jobs/${encodeURIComponent(jobId)}`,
		{ signal }
	);

/**
 * Cancels any still-queued targets on a synchronization job.
 * @param csrfToken - Active session CSRF token.
 * @param jobId - Operation job ID.
 * @param signal - Optional abort signal.
 * @returns Updated operation job.
 */
export const cancelJob = (
	csrfToken: string | null,
	jobId: string,
	signal?: AbortSignal
): Promise<{ job: OperationJob }> =>
	postJson<{ job: OperationJob }>(
		`jobs/${encodeURIComponent(jobId)}/cancel`,
		csrfToken,
		{},
		signal
	);

/**
 * Queries the local SQLite catalog for Ferrum-owned captured packages.
 * @param filters - Optional repository, suite, prefix, residency, and cursor filters.
 * @param signal - Optional abort signal.
 * @returns Paginated package inventory and deduplicated summary.
 */
export const fetchPackages = (
	filters: PackageFilters = {},
	signal?: AbortSignal
): Promise<PackagesPage> =>
	requestJson<PackagesPage>(`/api/admin/packages${buildQuery(filters)}`, { signal });

/**
 * Fetches recorded catalog evidence for a single captured package.
 * @param packageId - Opaque package identifier.
 * @param signal - Optional abort signal.
 * @returns Captured package detail.
 */
export const fetchPackageDetail = (
	packageId: string,
	signal?: AbortSignal
): Promise<{ package: CapturedPackage; sampledAt: number }> =>
	requestJson<{ package: CapturedPackage; sampledAt: number }>(
		`/api/admin/packages/${encodeURIComponent(packageId)}`,
		{ signal }
	);

/**
 * Fetches local NVMe spool partitions, capture outbox, and S3 allowance diagnostics.
 * @param signal - Optional abort signal.
 * @returns Storage diagnostics payload.
 */
export const fetchStorage = (signal?: AbortSignal): Promise<StoragePayload> =>
	requestJson<StoragePayload>('/api/admin/storage', { signal });

/**
 * Computes a dry-run preview of evictable local package cache objects and protected categories.
 * @param csrfToken - Active session CSRF token.
 * @param signal - Optional abort signal.
 * @returns Cache eviction preview.
 */
export const previewCacheClear = (
	csrfToken: string | null,
	signal?: AbortSignal
): Promise<CachePreview> =>
	postJson<CachePreview>('cache/preview', csrfToken, {}, signal);

/**
 * Executes bounded local package cache reclamation and records an operation job.
 * @param csrfToken - Active session CSRF token.
 * @param body - Optional target bytes to reclaim, operator reason, and idempotency key.
 * @param signal - Optional abort signal.
 * @returns Completed cache reclamation job and reclaimed totals.
 */
export const clearCache = (
	csrfToken: string | null,
	body: { targetBytes?: string; reason: string; idempotencyKey: string },
	signal?: AbortSignal
): Promise<{ job: OperationJob; evictedObjects: string; freedBytes: string }> =>
	postJson<{ job: OperationJob; evictedObjects: string; freedBytes: string }>(
		'cache/clear',
		csrfToken,
		body,
		signal
	);

/**
 * Fetches 5-second ring samples or 1-minute rollup history for the requested time window.
 * @param range - Time range (`15m`, `1h`, `24h`, `7d`).
 * @param signal - Optional abort signal.
 * @returns Telemetry sample series.
 */
export const fetchMetricsHistory = (
	range: TimeRange,
	signal?: AbortSignal
): Promise<MetricsHistory> =>
	requestJson<MetricsHistory>(
		`/api/admin/metrics/history${buildQuery({ range })}`,
		{ signal }
	);

/**
 * Fetches active/resolved alerts and recent operator acknowledgments.
 * @param signal - Optional abort signal.
 * @returns Alerts and acknowledgments payload.
 */
export const fetchAlerts = (signal?: AbortSignal): Promise<AlertsPayload> =>
	requestJson<AlertsPayload>('/api/admin/alerts', { signal });

/**
 * Records an audited operator note acknowledging an alert condition.
 * @param csrfToken - Active session CSRF token.
 * @param conditionId - Alert condition ID.
 * @param note - Operator note text.
 * @param signal - Optional abort signal.
 */
export const acknowledgeAlert = (
	csrfToken: string | null,
	conditionId: string,
	note: string,
	signal?: AbortSignal
): Promise<void> =>
	postJson<void>(
		`alerts/${encodeURIComponent(conditionId)}/acknowledge`,
		csrfToken,
		{ note },
		signal
	);

/**
 * Fetches recent audit events and operation summaries.
 * @param signal - Optional abort signal.
 * @returns Activity payload.
 */
export const fetchActivity = (signal?: AbortSignal): Promise<ActivityPayload> =>
	requestJson<ActivityPayload>('/api/admin/activity', { signal });

/**
 * Fetches the redacted running configuration, field capabilities, and recent proposals.
 * @param signal - Optional abort signal.
 * @returns Redacted configuration payload.
 */
export const fetchConfig = (signal?: AbortSignal): Promise<ConfigPayload> =>
	requestJson<ConfigPayload>('/api/admin/config', { signal });

/**
 * Validates a candidate configuration patch in memory and returns structured diffs.
 * @param csrfToken - Active session CSRF token.
 * @param expectedRevision - Expected base configuration revision hash.
 * @param patch - Candidate settings patch.
 * @param signal - Optional abort signal.
 * @returns Validation preview and TOML diff.
 */
export const previewConfigPatch = (
	csrfToken: string | null,
	expectedRevision: string,
	patch: ConfigPatch,
	signal?: AbortSignal
): Promise<ConfigPreview> =>
	postJson<ConfigPreview>(
		'config/preview',
		csrfToken,
		{ expectedRevision, patch },
		signal
	);

/**
 * Records a validated configuration proposal in the admin store.
 * @param csrfToken - Active session CSRF token.
 * @param expectedRevision - Expected base configuration revision hash.
 * @param patch - Validated settings patch.
 * @param reason - Operator reason for the change.
 * @param signal - Optional abort signal.
 * @returns Created configuration proposal.
 */
export const createConfigProposal = (
	csrfToken: string | null,
	expectedRevision: string,
	patch: ConfigPatch,
	reason: string,
	signal?: AbortSignal
): Promise<{ proposal: ConfigProposal }> =>
	postJson<{ proposal: ConfigProposal }>(
		'config/proposals',
		csrfToken,
		{ expectedRevision, patch, reason },
		signal
	);

/**
 * Atomically saves a configuration proposal to the host's opted-in managed configuration file.
 * @param csrfToken - Active session CSRF token.
 * @param proposalId - Proposal ID to save.
 * @param signal - Optional abort signal.
 * @returns Updated proposal marked for service restart.
 */
export const saveConfigProposal = (
	csrfToken: string | null,
	proposalId: string,
	signal?: AbortSignal
): Promise<{ proposal: ConfigProposal }> =>
	postJson<{ proposal: ConfigProposal }>(
		`config/proposals/${encodeURIComponent(proposalId)}/save`,
		csrfToken,
		{},
		signal
	);
