import type { Snippet } from 'svelte';
import type { ClassValue } from 'svelte/elements';

/** Granular RBAC permissions granted to an admin user. */
export type Permission =
	| 'view_status'
	| 'trigger_sync'
	| 'manage_cache'
	| 'manage_users'
	| 'view_inventory'
	| 'view_audit'
	| 'manage_config'
	| 'acknowledge_alerts';

/** Dashboard navigation tab identifier. */
export type DashboardTab =
	| 'overview'
	| 'mirrors'
	| 'packages'
	| 'storage'
	| 'activity'
	| 'settings'
	| 'account'
	| 'users'
	| 'docs';

/** Unsigned 64-bit integer serialized as a decimal string. */
export type UnsignedInteger = string;

/** Supported telemetry history windows. */
export type TimeRange = '15m' | '1h' | '24h' | '7d';

/** Supported telemetry refresh modes. */
export type RefreshMode = 'live' | '5s' | '15s' | '30s' | '60s' | 'manual';

/** Recursive JSON value type for structured diagnostics. */
export type JsonValue =
	| string
	| number
	| boolean
	| null
	| JsonValue[]
	| { [key: string]: JsonValue };

/** Authenticated admin account representation. */
export interface AdminUser {
	/** Unique user identifier. */
	id: string;
	/** Lowercase login username. */
	username: string;
	/** Human-readable display name. */
	displayName: string;
	/** Granted RBAC permissions. */
	permissions: Permission[];
	/** Account creation timestamp in Unix seconds. */
	createdAt: number;
	/** Last login timestamp in Unix seconds. */
	lastLoginAt: number | null;
	/** Disabled accounts cannot authenticate and have no active sessions. */
	disabled: boolean;
}

/** Token-free metadata for an active user session. */
export interface AdminSession {
	/** Unique session identifier. */
	id: string;
	/** Session creation timestamp in Unix seconds. */
	createdAt: number;
	/** Last recorded activity timestamp in Unix seconds. */
	lastSeenAt: number;
	/** Absolute expiration timestamp in Unix seconds. */
	expiresAt: number;
	/** True when this record represents the caller's current session. */
	current: boolean;
}

/** Session state returned by `/api/admin/session`. */
export interface SessionState {
	/** True when no admin account has been initialized yet. */
	setupRequired: boolean;
	/** Currently authenticated user, or null when unauthenticated. */
	user: AdminUser | null;
	/** Active CSRF token for state-changing requests. */
	csrfToken: string | null;
}

/** Per-suite mirror publication and health status. */
export interface SuiteOverview {
	/** Repository identifier (for example `debian` or `ubuntu`). */
	repository: string;
	/** Suite name (for example `trixie` or `noble`). */
	suite: string;
	/** Whether the suite is currently fresh and servable. */
	ready: boolean;
	/** Active SHA-256 generation digest. */
	generationId: string | null;
	/** Lease expiration timestamp in Unix seconds. */
	leaseDeadline: number | null;
	/** Remaining lease validity in seconds. */
	leaseRemainingSeconds: number | null;
	/** Seconds since last origin observation. */
	observedAgeSeconds: number | null;
	/** Seconds since last origin confirmation. */
	confirmedAgeSeconds: number | null;
	/** Publication lag in seconds. */
	publicationLagSeconds: number | null;
	/** Durable checkpoint sequence number. */
	checkpointSequence: number | null;
	/** Checkpoint status label (`active`, `pending`, `blocked`, `missing`, `unavailable`). */
	checkpointStatus: string;
	/** Alert severity (`ok`, `warn`, `page`). */
	alertState: string;
	/** Most recent synchronization error summary, if any. */
	lastError: string | null;
}

/** Local NVMe spool storage and reservation metrics. */
export interface SpoolOverview {
	/** Verified bytes currently installed in the spool. */
	installedBytes: number;
	/** Bytes currently reserved by active writers. */
	reservedBytes: number;
	/** Configured managed spool ceiling in bytes. */
	managedCeilingBytes: number;
	/** SQLite catalog bytes on disk. */
	catalogBytes: number;
	/** Total managed bytes against the ceiling. */
	managedBytes: number;
	/** Available bytes on the underlying filesystem. */
	filesystemAvailableBytes: number;
	/** Number of resident objects in the spool. */
	residentEntries: number;
	/** Number of active write reservations. */
	activeReservations: number;
	/** Whether new spool admissions are open. */
	admissionOpen: boolean;
}

/** Remote S3 storage, transfer budget, and capture outbox metrics. */
export interface RemoteOverview {
	/** Accounted remote storage bytes. */
	storageBytes: number;
	/** Monthly download bytes charged. */
	downloadBytes: number;
	/** Monthly package download bytes charged. */
	packageDownloadBytes: number;
	/** Whether remote budget accounting is certain. */
	certain: boolean;
	/** Queued capture outbox object count. */
	outboxEntries: number;
	/** Queued capture outbox byte total. */
	outboxBytes: number;
	/** Whether startup capture reconciliation is complete. */
	coverageReady: boolean;
}

/** Traffic counters for one HTTP request class. */
export interface ClassTraffic {
	/** Request class name (`metadata`, `by_hash`, `package`, `other`). */
	class: string;
	/** Count of 2xx responses. */
	ok2xx: number;
	/** Count of 3xx responses. */
	redirect3xx: number;
	/** Count of 4xx responses. */
	client4xx: number;
	/** Count of 5xx responses. */
	server5xx: number;
	/** Cumulative time-to-first-byte in nanoseconds. */
	ttfbNanos: number;
	/** Cumulative response body bytes served. */
	responseBytes: number;
	/** Cumulative body transfer duration in nanoseconds. */
	bodyDurationNanos: number;
}

/** Upstream fill outcome counter. */
export interface FillStat {
	/** Outcome label. */
	outcome: string;
	/** Total occurrences. */
	count: number;
}

/** Synchronizer outcome counter. */
export interface SyncStat {
	/** Outcome label (`published`, `renewed`, `rejected`, `error`). */
	outcome: string;
	/** Total occurrences. */
	count: number;
}

/** Live traffic, fill, and synchronization statistics. */
export interface StatsOverview {
	/** Per-class HTTP traffic counters. */
	requests: ClassTraffic[];
	/** Completed response body transfers. */
	completedTransfers: number;
	/** Aborted response body transfers. */
	abortedTransfers: number;
	/** Upstream fill counters by outcome. */
	fills: FillStat[];
	/** Currently waiting cold-fill clients. */
	fillWaiters: number;
	/** Total cold-fill waiter timeouts. */
	waiterTimeouts: number;
	/** Synchronizer pass counters by outcome. */
	syncOutcomes: SyncStat[];
}

/** Alert condition reported by the telemetry sampler. */
export interface Alert {
	/** Stable condition identifier. */
	conditionId: string;
	/** Severity level (`warning` or `critical`). */
	severity: string;
	/** Human-readable alert summary. */
	message: string;
	/** True while the underlying condition remains active. */
	active: boolean;
	/** First observation timestamp in Unix seconds. */
	firstSeenAt: number;
	/** Most recent transition timestamp in Unix seconds. */
	changedAt: number;
}

/** Admission semaphore and flight utilization snapshot. */
export interface AdmissionSnapshot {
	/** Available public request slot permits. */
	availableRequestSlots: number | null;
	/** Available active body streaming permits. */
	availableBodySlots: number | null;
	/** Available cold-fill producer permits. */
	availableFillSlots: number | null;
	/** Configured maximum cold-fill producer permits. */
	maxFillSlots: number | null;
	/** Currently executing single-flight producers. */
	activeFlights: number | null;
	/** Currently waiting single-flight followers. */
	fillWaiters: UnsignedInteger;
}

/** Per-repository traffic delta within a telemetry interval. */
export interface RepositoryTrafficSample {
	/** Repository profile name. */
	repository: string;
	/** Count of 2xx and 3xx responses. */
	successfulRequests: UnsignedInteger;
	/** Count of 4xx and 5xx responses. */
	errorRequests: UnsignedInteger;
	/** Total response bytes streamed. */
	responseBytes: UnsignedInteger;
}

/** Five-second or one-minute telemetry sample. */
export interface TelemetrySample {
	/** Process boot identifier for gap detection. */
	bootId: string;
	/** Sample timestamp in Unix seconds. */
	sampleAt: number;
	/** Sample resolution in seconds (`5` or `60`). */
	resolutionSeconds: number;
	/** True when a restart or missing-sample gap preceded this point. */
	gap: boolean;
	/** Total requests in the sample window. */
	requests: UnsignedInteger;
	/** Total delivered body bytes in the sample window. */
	responseBytes: UnsignedInteger;
	/** Measured request rate in requests per second. */
	requestsPerSecond: number | null;
	/** Measured throughput in bytes per second. */
	bytesPerSecond: number | null;
	/** Request resolutions by cache tier. */
	cacheSources: Record<string, UnsignedInteger>;
	/** TTFB histogram bucket counts. */
	latencyBuckets: UnsignedInteger[];
	/** Producer fill duration histogram bucket counts. */
	fillDurationBuckets: UnsignedInteger[];
	/** Estimated 95th percentile TTFB in seconds. */
	latencyP95Seconds: number | null;
	/** Estimated 95th percentile fill duration in seconds. */
	fillP95Seconds: number | null;
	/** Gateway process resident set size in bytes. */
	rssBytes: UnsignedInteger | null;
	/** Gateway process CPU usage in core equivalents. */
	cpuCoreEquivalents: number | null;
	/** Explanation of process measurement scope. */
	processMeasurementNote: string;
	/** Local spool installed bytes. */
	installedBytes: UnsignedInteger | null;
	/** Filesystem available bytes. */
	filesystemAvailableBytes: UnsignedInteger | null;
	/** Capture outbox entry count. */
	outboxEntries: UnsignedInteger | null;
	/** Whether the S3 forbidden circuit breaker is open. */
	circuitOpen: boolean | null;
	/** Accounted S3 storage bytes. */
	remoteStorageBytes: UnsignedInteger | null;
	/** Accounted monthly S3 download bytes. */
	remoteDownloadBytes: UnsignedInteger | null;
	/** Active S3 download reservation bytes. */
	remoteReservedDownloadBytes: UnsignedInteger | null;
	/** Active UTC civil month period integer. */
	remoteLedgerPeriod: number | null;
	/** Whether remote allowance accounting is certain. */
	remoteUsageCertain: boolean | null;
	/** Per-repository traffic breakdown for 5s ring samples. */
	repositoryTraffic: RepositoryTrafficSample[] | null;
	/** Producer completions by source tier. */
	producerSources: Record<string, UnsignedInteger>;
	/** Live admission and flight gauges. */
	admission: AdmissionSnapshot;
	/** Active and retained resolved alerts. */
	alerts: Alert[];
}

/** Complete gateway overview returned by `/api/admin/overview`. */
export interface OverviewPayload {
	/** Process boot identifier. */
	bootId: string;
	/** Latest telemetry sample timestamp in Unix seconds. */
	sampleAt: number | null;
	/** True when the latest telemetry sample is older than 10 seconds. */
	stale: boolean;
	/** Lifetime cache source resolution totals. */
	cacheSources: Record<string, UnsignedInteger>;
	/** Latest latency summary. */
	latency: JsonValue;
	/** Latest alert conditions. */
	alerts: Alert[] | null;
	/** Latest admission gauges. */
	admission: AdmissionSnapshot | null;
	/** Aggregate gateway readiness. */
	ready: boolean;
	/** Whether the host clock is synchronized and valid. */
	clockValid: boolean;
	/** Gateway operating mode (`fixture` or `durable`). */
	mode: string;
	/** Isolated signature verifier version string. */
	verifierVersion: string;
	/** Global catalog error, if any. */
	lastError: string | null;
	/** Configured mirror suites. */
	suites: SuiteOverview[];
	/** Local spool usage snapshot. */
	spool: SpoolOverview;
	/** Remote S3 usage snapshot, when durable storage is active. */
	remote: RemoteOverview | null;
	/** Live traffic and fill statistics. */
	stats: StatsOverview;
}

/** Historical telemetry response returned by `/api/admin/metrics/history`. */
export interface MetricsHistory {
	/** Ordered telemetry samples for the requested window. */
	samples: TelemetrySample[];
	/** Sample resolution in seconds. */
	resolutionSeconds: number;
	/** Latest sample timestamp in Unix seconds. */
	sampleAt: number | null;
	/** Server response timestamp in Unix seconds. */
	requestedAt: number;
	/** True when sampling is stale. */
	stale: boolean;
	/** Requested time range identifier. */
	range: TimeRange;
}

/** Mirror health projection with stringified checkpoint sequence. */
export interface MirrorHealth extends Omit<SuiteOverview, 'repository' | 'suite' | 'checkpointSequence'> {
	/** Durable checkpoint sequence as a decimal string. */
	checkpointSequence: UnsignedInteger | null;
}

/** Compiled repository suite candidate or configured mirror. */
export interface Mirror {
	/** Repository profile name. */
	repository: string;
	/** Suite name. */
	suite: string;
	/** Fixed upstream origin URL. */
	origin: string;
	/** Package ecosystem (`apt`, `pacman`, `rpm`). */
	ecosystem: 'apt' | 'pacman' | 'rpm';
	/** Supported architectures for this profile. */
	architectures: string[];
	/** True when enabled in the running gateway configuration. */
	configured: boolean;
	/** True when a retained checkpoint prevents removing this suite. */
	retainedLocked: boolean | null;
	/** True when initial bootstrap is authorized. */
	bootstrapAuthorized: boolean | null;
	/** True when a keyring path is configured. */
	keyringConfigured: boolean;
	/** True when the configured keyring file exists on disk. */
	keyringExists: boolean;
	/** High-level mirror status (`ready`, `configured_not_ready`, `candidate_unconfigured`). */
	status: string;
	/** Qualification disclaimer. */
	qualification: string;
	/** Live health when configured. */
	health: MirrorHealth | null;
}

/** Repository and suite coordinate pair. */
export interface SyncTarget {
	/** Repository name. */
	repository: string;
	/** Suite name. */
	suite: string;
}

/** Per-target status inside a synchronization job. */
export interface JobTarget extends SyncTarget {
	/** Target lifecycle state. */
	state: string;
	/** Queue disposition (`queued` or `queued_recheck`). */
	disposition: string;
	/** Current synchronizer phase. */
	phase: string;
	/** Candidate or published generation digest. */
	generationId: string | null;
	/** Completed metadata artifact count during staging. */
	completedArtifacts: number | null;
	/** Total metadata artifact count during staging. */
	totalArtifacts: number | null;
	/** Metadata path currently being staged. */
	currentPath: string | null;
	/** Sanitized failure summary, if any. */
	error: string | null;
	/** Whether this target can still be cancelled. */
	cancellable?: boolean;
	/** Attached synchronizer pass identifier. */
	passId: string | null;
	/** Generations superseded before cutover. */
	supersededGenerationIds: string[];
}

/** Durable synchronization or cache maintenance job. */
export interface OperationJob {
	/** Unique operation job identifier. */
	id: string;
	/** Operation kind (`sync` or `cache_clear`). */
	kind: string;
	/** Aggregate state (`queued`, `running`, `succeeded`, `partial`, `failed`, `cancelled`, `interrupted`). */
	state: string;
	/** Principal that requested the operation. */
	actor: string;
	/** Creation timestamp in Unix seconds. */
	createdAt: number;
	/** Last transition timestamp in Unix seconds. */
	updatedAt: number;
	/** Operator-supplied reason. */
	reason: string;
	/** Per-suite target states for sync jobs. */
	targets: JobTarget[];
	/** True when admin DB persistence lagged behind live execution. */
	recordingIncomplete?: boolean;
	/** Evicted object count for cache clear jobs. */
	evictedObjects?: UnsignedInteger;
	/** Reclaimed byte count for cache clear jobs. */
	freedBytes?: UnsignedInteger;
	/** Whether any target in the job is currently cancellable. */
	cancellable?: boolean;
	/** Top-level error summary, if any. */
	error?: string | null;
}

/** Live per-suite state reported by the synchronizer actor. */
export interface SuiteJobState extends SyncTarget {
	/** Current actor phase (`idle`, `recovering`, `observing`, `verifying_metadata`, `staging`, `publishing`). */
	phase: string;
	/** Active candidate generation digest. */
	generationId: string | null;
	/** Completed metadata artifacts in current candidate. */
	completedArtifacts: number | null;
	/** Total metadata artifacts in current candidate. */
	totalArtifacts: number | null;
	/** Current artifact path being staged. */
	currentPath: string | null;
	/** Active pass identifier. */
	activePassId: string | null;
	/** Queued recheck pass identifier. */
	queuedPassId: string | null;
	/** True when a follow-up observation is scheduled after the current pass. */
	recheckAfterCurrent: boolean;
	/** Most recent terminal outcome (`published`, `renewed`, `rejected`, `failed`). */
	lastOutcome: string | null;
	/** Most recent error summary. */
	lastError: string | null;
	/** True when durable job recording encountered a write error. */
	recordingIncomplete: boolean;
}

/** Paginated job list response from `/api/admin/jobs`. */
export interface JobsPage {
	/** Ordered operation jobs. */
	jobs: OperationJob[];
	/** Keyset continuation cursor. */
	nextCursor: string | null;
	/** True when additional pages exist. */
	hasMore: boolean;
	/** Live synchronizer state across configured suites. */
	activeSuites: SuiteJobState[];
}

/** Query filter parameters for `/api/admin/packages`. */
export interface PackageFilters {
	/** Exact repository name filter. */
	repository?: string;
	/** Recorded suite filter. */
	suite?: string;
	/** Lowercase hex SHA-256 prefix filter. */
	digestPrefix?: string;
	/** Repository-relative path prefix filter. */
	pathPrefix?: string;
	/** Local spool residency filter. */
	cacheStatus?: string;
	/** Recorded remote S3 state filter. */
	remoteStatus?: string;
	/** Keyset continuation cursor. */
	cursor?: string;
	/** Page size (`1` to `100`). */
	limit?: number;
}

/** Catalog-backed captured package record. */
export interface CapturedPackage {
	/** Opaque package lookup identifier. */
	id: string;
	/** Filename extracted from the repository path. */
	displayName: string;
	/** Honesty marker indicating coordinates come from the path only. */
	metadataStatus: 'path_only';
	/** Owning repository profile. */
	repository: string;
	/** Full repository-relative package path. */
	path: string;
	/** SHA-256 digest of the path. */
	pathHash: string;
	/** Package content SHA-256 digest. */
	digest: string;
	/** Verified package size in bytes as a decimal string. */
	size: UnsignedInteger;
	/** Associated proof generation identifier. */
	generation: string;
	/** True when the S3 capture receipt has been verified. */
	receiptVerified: boolean;
	/** True when referenced by an active public generation. */
	referenced: boolean;
	/** Retention floor timestamp in Unix seconds. */
	retainUntil: number;
	/** First capture timestamp in Unix seconds. */
	firstCapture: number;
	/** Suite recorded on the capture proof manifest. */
	recordedSuite: string | null;
	/** True when the capture proof manifest is durable in S3. */
	proofDurable: boolean;
	/** True when resident as a derived artifact. */
	derivedResidency: boolean;
	/** Local spool residency status. */
	cacheStatus: string;
	/** Recorded remote S3 status. */
	remoteStatus: string;
	/** Ferrum-owned S3 object key. */
	objectKey: string | null;
	/** Evidence disclaimer. */
	remoteEvidence: string;
}

/** Paginated package inventory response from `/api/admin/packages`. */
export interface PackagesPage {
	/** Page of captured package rows. */
	items: CapturedPackage[];
	/** Keyset cursor for the next page. */
	nextCursor: string | null;
	/** True when more rows follow this page. */
	hasMore: boolean;
	/** Deduplicated global capture summary counters. */
	summary: Record<string, UnsignedInteger> | null;
	/** Page query timestamp in Unix seconds. */
	sampledAt: number | null;
	/** Summary snapshot timestamp in Unix seconds. */
	summarySampledAt?: number | null;
	/** True when the cached summary snapshot is stale. */
	summaryStale?: boolean;
	/** Warning message if the summary query was busy. */
	summaryError?: string;
	/** Gateway operating mode (`durable` or `fixture`). */
	mode: string;
	/** Explanation when durable inventory is unavailable in fixture mode. */
	unavailable?: string;
}

/** Object count and byte total pair for cache previews. */
export interface CacheProtectionCount {
	/** Number of objects in this category. */
	objects: UnsignedInteger;
	/** Total bytes in this category. */
	bytes: UnsignedInteger;
}

/** Dry-run local cache eviction preview from `/api/admin/cache/preview`. */
export interface CachePreview {
	/** Currently evictable package cache objects and bytes. */
	eligible: CacheProtectionCount;
	/** Protected non-evictable objects grouped by protection reason. */
	protected: Record<string, CacheProtectionCount>;
	/** Preview snapshot timestamp in Unix seconds. */
	sampledAt: number;
	/** True because execution re-verifies eligibility on each batch. */
	executionRechecksEligibility: boolean;
	/** Scope description (`local_package_cache_only`). */
	scope: string;
}

/** Detailed local spool and S3 allowance diagnostics from `/api/admin/storage`. */
export interface StoragePayload {
	/** Operating mode (`durable` or `fixture`). */
	mode: string;
	/** Snapshot timestamp in Unix seconds. */
	sampledAt: number;
	/** Local NVMe spool partitions and watermarks. */
	local: Record<string, JsonValue>;
	/** Recorded S3 allowance ledger and provider binding. */
	remote: Record<string, JsonValue> | null;
	/** Capture outbox and reconciliation coverage state. */
	capture: Record<string, JsonValue> | null;
	/** Error message if remote diagnostics are unavailable. */
	remoteError: string | null;
	/** Error message if capture diagnostics are unavailable. */
	captureError: string | null;
	/** Whether the S3 forbidden circuit breaker is open. */
	circuitOpen: boolean | null;
}

/** Operator acknowledgment record for an alert condition. */
export interface AlertAcknowledgment {
	/** Acknowledged alert condition ID. */
	conditionId: string;
	/** Operator user ID. */
	actor: string;
	/** Operator note text. */
	note: string;
	/** Acknowledgment timestamp in Unix seconds. */
	createdAt: number;
}

/** Alerts and acknowledgments payload from `/api/admin/alerts`. */
export interface AlertsPayload {
	/** Active and retained resolved alerts. */
	alerts: Alert[] | null;
	/** Recent operator acknowledgments. */
	acknowledgments: AlertAcknowledgment[];
	/** Snapshot timestamp in Unix seconds. */
	sampleAt: number;
}

/** Local audit log entry. */
export interface AuditEvent {
	/** Monotonic audit event ID. */
	id: number;
	/** Actor user ID or machine principal. */
	actor: string;
	/** Audited action name. */
	action: string;
	/** Target identifier. */
	target: string;
	/** Recorded outcome. */
	outcome: string;
	/** Operator or system reason. */
	reason: string;
	/** Event timestamp in Unix seconds. */
	createdAt: number;
}

/** Activity payload from `/api/admin/activity`. */
export interface ActivityPayload {
	/** Recent audit events when the caller holds `view_audit`. */
	auditEvents: AuditEvent[] | null;
	/** Recent operation request summaries. */
	operations: { id: string; state: string; createdAt: number }[];
	/** Snapshot timestamp in Unix seconds. */
	sampleAt: number;
}

/** Structured patch for allowlisted restart-required settings. */
export interface ConfigPatch {
	/** Updated `[limits]` fields. */
	limits?: Record<string, number | UnsignedInteger>;
	/** Updated `[verifier].timeout_seconds` value. */
	verifierTimeoutSeconds?: number;
}

/** Single field diff entry in a configuration preview. */
export interface ConfigDiff {
	/** Dotted configuration field path. */
	field: string;
	/** Previous running or base value. */
	before: JsonValue;
	/** Proposed new value. */
	after: JsonValue;
	/** True when a gateway restart is required to apply. */
	restartRequired: boolean;
}

/** Dry-run configuration validation response from `/api/admin/config/preview`. */
export interface ConfigPreview {
	/** True when the candidate configuration passed full validation. */
	valid: boolean;
	/** Base configuration revision hash. */
	baseRevision: string;
	/** Resulting configuration revision hash. */
	proposedRevision: string;
	/** Changed field diffs. */
	diffs: ConfigDiff[];
	/** Generated TOML snippet preview. */
	tomlPreview: string;
	/** Whether managed disk save is enabled on this host. */
	managedConfigEnabled: boolean;
}

/** Persisted configuration change proposal. */
export interface ConfigProposal {
	/** Unique proposal identifier. */
	id: string;
	/** Authoring user ID. */
	actor: string;
	/** Persistence state (`proposed`, `saved`, `applied`, `conflict`). */
	state: string;
	/** Display status including restart guidance. */
	status: string;
	/** Base revision hash the proposal was built against. */
	baseRevision: string;
	/** Proposed revision hash. */
	proposedRevision: string;
	/** Creation timestamp in Unix seconds. */
	createdAt: number;
	/** Allowlisted patch body. */
	patch: ConfigPatch;
	/** Field-by-field diff list. */
	diffs: ConfigDiff[];
	/** Operator reason for the change. */
	reason: string;
}

/** Field capability metadata in `/api/admin/config`. */
export interface ConfigFieldCapability {
	/** Dotted field name. */
	field: string;
	/** Current running value. */
	value: JsonValue;
	/** True when editable through the web proposal workflow. */
	editable: boolean;
	/** True when changing this field requires a service restart. */
	restartRequired: boolean;
	/** Minimum allowed value for numeric fields. */
	min?: number;
	/** Maximum allowed value for numeric fields. */
	max?: number;
	/** Explanation of editability and authority boundaries. */
	reason: string;
}

/** Redacted configuration projection returned by `/api/admin/config`. */
export interface ConfigPayload {
	/** Redacted running configuration sections. */
	running: Record<string, JsonValue>;
	/** SHA-256 revision of the running configuration projection. */
	runningRevision: string;
	/** SHA-256 revision of the saved configuration file on disk. */
	savedRevision: string | null;
	/** Status comparing saved file vs running process. */
	savedRevisionStatus: string;
	/** True when a saved change is awaiting service restart. */
	restartRequired: boolean;
	/** True when the disk file was modified outside the dashboard. */
	externalChangeDetected: boolean;
	/** True when the host opted into a writable managed config file. */
	managedConfigEnabled: boolean;
	/** Field-level capability descriptors. */
	fields: ConfigFieldCapability[];
	/** Recent configuration proposals. */
	proposals: ConfigProposal[];
}

/** Editable numeric setting specification for the Settings page. */
export interface EditableSettingSpec {
	/** Wire key under `limits` or `verifierTimeoutSeconds`. */
	key: string;
	/** Human-readable setting label. */
	label: string;
	/** Unit description (`slots`, `bytes`, `seconds`, `attempts`, `entries`). */
	unit: string;
	/** Minimum allowed integer value. */
	min: number;
	/** Maximum allowed integer value. */
	max: number;
	/** Category grouping (`cache` or `timeouts`). */
	group: 'cache' | 'timeouts';
	/** Short operational explanation. */
	description: string;
}

/** Props for the StatusBadge component. */
export interface StatusBadgeProps {
	/** Visual tone of the badge. */
	tone: 'ok' | 'warn' | 'danger' | 'neutral';
	/** Badge label text. */
	label: string;
	/** Optional extra classes. */
	class?: ClassValue;
}

/** Props for the StatCard component. */
export interface StatCardProps {
	/** Sentence-case metric heading. */
	title: string;
	/** Primary metric value. */
	value: string;
	/** Secondary caption text. */
	subtitle?: string;
	/** Optional extra classes. */
	class?: ClassValue;
}

/** Props for the Modal dialog component. */
export interface ModalProps {
	/** Dialog heading text. */
	title: string;
	/** Callback invoked when the dialog closes. */
	onclose: () => void;
	/** Dialog body content. */
	children: Snippet;
}

/** Props for the EvidenceTable component. */
export interface EvidenceTableProps {
	/** Key-value object to render. */
	values: object;
	/** Accessible table caption. */
	caption?: string;
}

/** Props for the MetricChart component. */
export interface MetricChartProps {
	/** Ordered telemetry samples. */
	samples: TelemetrySample[];
	/** Numeric sample property to plot. */
	metric: 'requestsPerSecond' | 'bytesPerSecond' | 'latencyP95Seconds';
	/** Chart title. */
	title: string;
	/** Measurement unit label. */
	unit: string;
	/** Active time range label. */
	range: string;
	/** Sample resolution in seconds. */
	resolution: number;
}

/** Props for the JobDetail modal component. */
export interface JobDetailProps {
	/** Job identifier to inspect. */
	id: string;
	/** Active session CSRF token. */
	csrf: string | null;
	/** Whether the caller has permission to cancel queued sync targets. */
	canCancel: boolean;
	/** Callback invoked when the modal closes. */
	onclose: () => void;
	/** Error handler callback. */
	onerror: (error: unknown) => void;
}

/** Props for the top-right Google Admin style TaskTray component. */
export interface TaskTrayProps {
	/** Active session CSRF token. */
	csrf: string | null;
	/** Whether the user can cancel queued sync targets. */
	canCancel: boolean;
	/** Incrementing trigger counter that opens and refreshes the tray when a task starts. */
	pulseSignal: number;
	/** Callback to open a full job detail modal. */
	onselectjob: (jobId: string) => void;
	/** Error handler callback. */
	onerror: (error: unknown) => void;
}

/** Props for the OverviewPage component. */
export interface OverviewPageProps {
	/** True when Overview is the currently visible tab. */
	active: boolean;
	/** Active session CSRF token. */
	csrf: string | null;
	/** True when the user can trigger or cancel synchronization. */
	canSync: boolean;
	/** Callback to navigate to another dashboard tab. */
	onnavigate: (tab: DashboardTab) => void;
	/** Callback to inspect a specific mirror on the Mirrors tab. */
	oninspectmirror: (repository: string, suite: string) => void;
	/** Error handler callback. */
	onerror: (error: unknown) => void;
}

/** Props for the MirrorsPage component. */
export interface MirrorsPageProps {
	/** Active session CSRF token. */
	csrf: string | null;
	/** True when the user can trigger synchronization. */
	canSync: boolean;
	/** Optional deep-linked `repository/suite` target. */
	initialTarget?: string;
	/** Callback fired when a sync job is created so the top-right task tray opens. */
	ontaskcreated: (job: OperationJob) => void;
	/** Error handler callback. */
	onerror: (error: unknown) => void;
}

/** Props for the PackagesPage component. */
export interface PackagesPageProps {
	/** Error handler callback. */
	onerror: (error: unknown) => void;
}

/** Props for the StoragePage component. */
export interface StoragePageProps {
	/** Active session CSRF token. */
	csrf: string | null;
	/** True when the user holds `manage_cache`. */
	canManage: boolean;
	/** Callback fired when a cache reclamation job is created. */
	ontaskcreated: (job: OperationJob) => void;
	/** Error handler callback. */
	onerror: (error: unknown) => void;
}

/** Props for the ActivityPage component. */
export interface ActivityPageProps {
	/** Active session CSRF token. */
	csrf: string | null;
	/** Authenticated admin user. */
	user: AdminUser;
	/** Error handler callback. */
	onerror: (error: unknown) => void;
}

/** Props for the SettingsPage component. */
export interface SettingsPageProps {
	/** Active session CSRF token. */
	csrf: string | null;
	/** True when the user holds `manage_config`. */
	canManage: boolean;
	/** Error handler callback. */
	onerror: (error: unknown) => void;
}

/** Props for the AccountUsersPage component. */
export interface AccountUsersPageProps {
	/** Authenticated admin user. */
	user: AdminUser;
	/** Active session CSRF token. */
	csrf: string | null;
	/** Whether to render self-service account settings or user administration. */
	mode: 'account' | 'users';
	/** Error handler callback. */
	onerror: (error: unknown) => void;
	/** Callback invoked when credentials change and reauthentication is required. */
	onreauth: () => void;
}

/** Error payload returned by admin API endpoints. */
export interface ApiErrorPayload {
	/** Stable server error classification. */
	code: string;
	/** Human-readable error message. */
	error: string;
}

/** Props for the root layout component. */
export interface LayoutProps {
	/** Child route content snippet. */
	children: Snippet;
}

/** Parsed Markdown documentation entry loaded from `src/lib/docs/*.md`. */
export interface DocEntry {
	/** Slug derived from the Markdown filename. */
	slug: string;
	/** Title extracted from the top-level `# Heading` in the Markdown file. */
	title: string;
	/** Raw Markdown source text. */
	raw: string;
	/** Pre-rendered HTML string from `marked`. */
	html: string;
}
