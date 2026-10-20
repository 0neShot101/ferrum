<script lang="ts">
	import { onMount } from 'svelte';
	import {
		fetchJobs,
		fetchMetricsHistory,
		fetchMirrors,
		fetchOverview
	} from '$lib/services/api';
	import type {
		MetricsHistory,
		Mirror,
		OperationJob,
		OverviewPageProps,
		OverviewPayload,
		RefreshMode,
		SuiteJobState,
		TelemetrySample,
		TimeRange
	} from '$lib/types/admin';
	import {
		decimalU64,
		formatBytes,
		formatCounter,
		formatDuration,
		formatPercent,
		formatTimestamp
	} from '$lib/utils/format';
	import JobDetail from './JobDetail.svelte';
	import MetricChart from './MetricChart.svelte';
	import StatCard from './StatCard.svelte';
	import StatusBadge from './StatusBadge.svelte';

	let {
		active,
		csrf,
		canSync,
		onnavigate,
		oninspectmirror,
		onerror
	}: OverviewPageProps = $props();

	let range = $state<TimeRange>('15m');
	let refreshMode = $state<RefreshMode>('live');
	let overview = $state<OverviewPayload | null>(null);
	let history = $state<MetricsHistory | null>(null);
	let latest = $state<TelemetrySample | null>(null);
	let jobs = $state<OperationJob[]>([]);
	let activeSuites = $state<SuiteJobState[]>([]);
	let mirrors = $state<Mirror[]>([]);
	let connection = $state('Connecting');
	let visible = $state(true);
	let selectedJobId = $state<string | null>(null);
	let loading = false;
	const controller = new AbortController();

	const configuredMirrors = $derived(mirrors.filter((mirror) => mirror.configured));
	const readySuitesCount = $derived(
		overview?.suites.filter((suite) => suite.ready).length ?? 0
	);
	const totalSuitesCount = $derived(overview?.suites.length ?? 0);

	const activeAlerts = $derived(
		(latest?.alerts ?? overview?.alerts ?? []).filter((alert) => alert.active)
	);

	const cacheHitSummary = $derived.by(() => {
		const sources = overview?.cacheSources ?? latest?.cacheSources;
		if (sources === undefined) return { ratioText: '0%', subtitle: 'No package requests yet' };
		const localHits = decimalU64(sources.local_hit) ?? 0n;
		const conditional304 = decimalU64(sources.conditional_304) ?? 0n;
		const s3Hits = decimalU64(sources.s3_rehydrated) ?? 0n;
		const originFills = decimalU64(sources.origin_fill) ?? 0n;
		const derivedHits = decimalU64(sources.derived_expanded) ?? 0n;
		const warmTotal = localHits + conditional304 + derivedHits;
		const total = warmTotal + s3Hits + originFills;
		if (total === 0n) return { ratioText: '100%', subtitle: '0 requests served' };
		const pct = Number((warmTotal * 1000n) / total) / 10;
		return {
			ratioText: `${pct.toFixed(1)}%`,
			subtitle: `${formatCounter(localHits)} NVMe hits · ${formatCounter(s3Hits)} S3 · ${formatCounter(originFills)} origin`
		};
	});

	const loadOverview = async (): Promise<void> => {
		if (loading || controller.signal.aborted || document.hidden || active === false) return;
		loading = true;
		const requestedRange = range;
		try {
			const [overviewResult, historyResult, jobsResult, mirrorsResult] =
				await Promise.all([
					fetchOverview(controller.signal),
					fetchMetricsHistory(requestedRange, controller.signal),
					fetchJobs({ limit: 25 }, controller.signal),
					fetchMirrors(controller.signal)
				]);

			if (
				controller.signal.aborted === false &&
				requestedRange === range &&
				active
			) {
				overview = overviewResult;
				history = historyResult;
				latest = historyResult.samples.at(-1) ?? null;
				jobs = jobsResult.jobs.filter(
					(job) => job.state === 'queued' || job.state === 'running'
				);
				activeSuites = jobsResult.activeSuites.filter(
					(suite) =>
						suite.phase !== 'idle' &&
						suite.phase !== 'published' &&
						suite.phase !== 'renewed'
				);
				mirrors = mirrorsResult.mirrors;
			}
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		} finally {
			loading = false;
			if (requestedRange !== range) void loadOverview();
		}
	};

	const badgeTone = (ready: boolean, alertState?: string): 'ok' | 'warn' | 'danger' => {
		if (ready && alertState !== 'warn' && alertState !== 'page') return 'ok';
		if (alertState === 'warn') return 'warn';
		return 'danger';
	};

	onMount(() => {
		visible = document.hidden === false;
		const handleVisibility = (): void => {
			visible = document.hidden === false;
		};
		document.addEventListener('visibilitychange', handleVisibility);
		return () => {
			controller.abort();
			document.removeEventListener('visibilitychange', handleVisibility);
		};
	});

	$effect(() => {
		const currentRange = range;
		const currentMode = refreshMode;
		if (visible === false || active === false || typeof window === 'undefined') {
			connection = 'Paused while tab is hidden';
			return;
		}
		void currentRange;
		void loadOverview();

		let eventSource: EventSource | null = null;
		let stopped = false;
		let fallback = false;
		let tickCount = 0;

		const connectStream = (): void => {
			if (stopped || currentMode !== 'live') return;
			eventSource?.close();
			eventSource = new EventSource('/api/admin/events');
			connection = 'Connecting';

			eventSource.addEventListener('telemetry', (event) => {
				if (stopped) return;
				try {
					const sample = JSON.parse(
						(event as MessageEvent<string>).data
					) as TelemetrySample;
					latest = sample;
					connection = 'Live (5s sampler)';
					fallback = false;
					if (
						history !== null &&
						(currentRange === '15m' || currentRange === '1h')
					) {
						const previous = history.samples.at(-1);
						const hasGap =
							sample.gap ||
							(previous !== undefined &&
								(sample.bootId !== previous.bootId ||
									sample.sampleAt - previous.sampleAt >
										sample.resolutionSeconds * 1.5));
						const windowSeconds = currentRange === '15m' ? 900 : 3600;
						history = {
							...history,
							sampleAt: sample.sampleAt,
							stale: false,
							samples: [
								...history.samples.filter(
									(item) =>
										item.sampleAt >= sample.sampleAt - windowSeconds &&
										item.sampleAt !== sample.sampleAt
								),
								{ ...sample, gap: hasGap }
							]
						};
					}
				} catch {
					fallback = true;
				}
			});

			eventSource.addEventListener('waiting', () => {
				connection = 'Waiting for first 5s sample';
			});

			eventSource.onerror = () => {
				if (stopped) return;
				eventSource?.close();
				fallback = true;
				connection = 'Polling every 5s';
			};
		};

		if (currentMode === 'live') connectStream();
		else
			connection =
				currentMode === 'manual'
					? 'Manual refresh'
					: `Polling every ${currentMode}`;

		const intervalMs =
			currentMode === 'live'
				? 5000
				: currentMode === 'manual'
					? 0
					: Number.parseInt(currentMode, 10) * 1000;

		const timer =
			intervalMs > 0
				? setInterval(() => {
						tickCount += 1;
						if (currentMode !== 'live' || fallback || tickCount % 3 === 0)
							void loadOverview();
						if (currentMode === 'live' && fallback && tickCount % 6 === 0)
							connectStream();
					}, intervalMs)
				: undefined;

		return () => {
			stopped = true;
			eventSource?.close();
			if (timer !== undefined) clearInterval(timer);
		};
	});
</script>

<div class="toolbar spaced-panel">
	<label class="field-inline">
		<span>Time window</span>
		<select class="input" bind:value={range}>
			{#each ['15m', '1h', '24h', '7d'] as windowOption (windowOption)}
				<option value={windowOption}>{windowOption}</option>
			{/each}
		</select>
	</label>

	<label class="field-inline">
		<span>Refresh</span>
		<select class="input" bind:value={refreshMode}>
			{#each ['live', '5s', '15s', '30s', '60s', 'manual'] as modeOption (modeOption)}
				<option value={modeOption}>{modeOption}</option>
			{/each}
		</select>
	</label>

	<button class="button" type="button" onclick={loadOverview}>
		Refresh now
	</button>

	<span class="muted" role="status">
		{connection} · Observed {formatTimestamp(latest?.sampleAt ?? overview?.sampleAt ?? null)}
	</span>
</div>

<div class="grid-cards spaced-panel">
	<StatCard
		title="Gateway readiness"
		value={overview !== null ? (overview.ready ? 'Ready' : 'Syncing / recovering') : 'Loading'}
		subtitle={`${readySuitesCount} of ${totalSuitesCount} suites ready · Clock ${overview?.clockValid ? 'valid' : 'invalid'} · ${overview?.mode ?? 'durable'}`}
	/>

	<StatCard
		title="Request & delivery rate"
		value={latest?.requestsPerSecond !== null && latest?.requestsPerSecond !== undefined
			? `${latest.requestsPerSecond.toFixed(1)} req/s`
			: '0.0 req/s'}
		subtitle={latest?.bytesPerSecond !== null && latest?.bytesPerSecond !== undefined
			? `${formatBytes(Math.round(latest.bytesPerSecond))}/s delivered`
			: '0 B/s delivered'}
	/>

	<StatCard
		title="Cache hit ratio"
		value={cacheHitSummary.ratioText}
		subtitle={cacheHitSummary.subtitle}
	/>

	<StatCard
		title="Local NVMe cache"
		value={overview !== null
			? `${formatBytes(overview.spool.installedBytes)} / ${formatBytes(overview.spool.managedCeilingBytes)}`
			: 'Unavailable'}
		subtitle={overview !== null
			? `${overview.spool.residentEntries.toLocaleString()} objects (${formatPercent(overview.spool.installedBytes, overview.spool.managedCeilingBytes)}% of ceiling)`
			: 'Local spool usage'}
	/>

	<StatCard
		title="S3 storage & monthly egress"
		value={overview?.remote !== null && overview?.remote !== undefined
			? formatBytes(overview.remote.storageBytes)
			: 'Fixture mode'}
		subtitle={overview?.remote !== null && overview?.remote !== undefined
			? `${formatBytes(overview.remote.downloadBytes)} monthly egress · Coverage ${overview.remote.coverageReady ? 'ready' : 'reconciling'}`
			: 'No durable S3 store configured'}
	/>

	<StatCard
		title="Active tasks & alerts"
		value={`${jobs.length + activeSuites.length} tasks · ${activeAlerts.length} alerts`}
		subtitle={`Verifier ${overview?.verifierVersion ?? 'unavailable'} · RSS ${formatBytes(latest?.rssBytes)}`}
	/>
</div>

<div class="chart-grid spaced-panel">
	<section class="card">
		<MetricChart
			samples={history?.samples ?? []}
			metric="requestsPerSecond"
			title="Measured request rate"
			unit="requests/s"
			{range}
			resolution={history?.resolutionSeconds ?? 5}
		/>
	</section>

	<section class="card">
		<MetricChart
			samples={history?.samples ?? []}
			metric="bytesPerSecond"
			title="Delivered body throughput"
			unit="bytes/s"
			{range}
			resolution={history?.resolutionSeconds ?? 5}
		/>
	</section>

	<section class="card">
		<MetricChart
			samples={history?.samples ?? []}
			metric="latencyP95Seconds"
			title="Server response TTFB p95"
			unit="seconds"
			{range}
			resolution={history?.resolutionSeconds ?? 5}
		/>
	</section>

	<section class="card">
		<div class="row-between">
			<h2>Cache & source tier breakdown</h2>
			<button
				type="button"
				class="button"
				onclick={() => onnavigate('storage')}
			>
				Manage cache
			</button>
		</div>
		<p class="muted">
			Lifetime request resolutions by storage tier since process start.
		</p>
		<div class="source-tier-grid">
			<div class="stat-block">
				<p class="stat-title">Local NVMe hits</p>
				<p class="stat-value">
					{formatCounter(overview?.cacheSources.local_hit ?? '0')}
				</p>
			</div>
			<div class="stat-block">
				<p class="stat-title">Conditional 304</p>
				<p class="stat-value">
					{formatCounter(overview?.cacheSources.conditional_304 ?? '0')}
				</p>
			</div>
			<div class="stat-block">
				<p class="stat-title">S3 rehydrations</p>
				<p class="stat-value">
					{formatCounter(overview?.cacheSources.s3_rehydrated ?? '0')}
				</p>
			</div>
			<div class="stat-block">
				<p class="stat-title">Origin cold fills</p>
				<p class="stat-value">
					{formatCounter(overview?.cacheSources.origin_fill ?? '0')}
				</p>
			</div>
		</div>
	</section>
</div>

{#if activeAlerts.length > 0}
	<section class="card spaced-panel">
		<div class="row-between">
			<h2>Active alerts ({activeAlerts.length})</h2>
			<button
				type="button"
				class="button"
				onclick={() => onnavigate('activity')}
			>
				View activity & alerts
			</button>
		</div>
		{#each activeAlerts.slice(0, 6) as alert (alert.conditionId)}
			<div class="alert-row">
				<div>
					<StatusBadge
						tone={alert.severity === 'critical' ? 'danger' : 'warn'}
						label={alert.severity}
					/>
					<strong> {alert.conditionId}</strong>
					<p>{alert.message}</p>
				</div>
				<small class="muted">{formatTimestamp(alert.changedAt)}</small>
			</div>
		{/each}
	</section>
{/if}

<section class="card table-panel">
	<div class="table-toolbar">
		<h2>Configured mirrors ({configuredMirrors.length})</h2>
		<button
			type="button"
			class="button"
			onclick={() => onnavigate('mirrors')}
		>
			Open mirror operations
		</button>
	</div>

	<div class="table-wrap">
		<table>
			<thead>
				<tr>
					<th>Mirror</th>
					<th>Ecosystem</th>
					<th>Status</th>
					<th>Checkpoint</th>
					<th>Lease remaining</th>
					<th>Last observed</th>
				</tr>
			</thead>
			<tbody>
				{#each configuredMirrors.slice(0, 15) as mirror (`${mirror.repository}/${mirror.suite}`)}
					<tr>
						<td>
							<button
								type="button"
								class="text-button"
								onclick={() => oninspectmirror(mirror.repository, mirror.suite)}
							>
								{mirror.repository}/{mirror.suite}
							</button>
						</td>
						<td>{mirror.ecosystem.toUpperCase()}</td>
						<td>
							<StatusBadge
								tone={badgeTone(
									mirror.health?.ready ?? false,
									mirror.health?.alertState
								)}
								label={mirror.health?.ready ? 'Ready' : mirror.health?.checkpointStatus ?? 'Recovering'}
							/>
							{#if mirror.health?.lastError !== null && mirror.health?.lastError !== undefined}
								<div class="muted">{mirror.health.lastError}</div>
							{/if}
						</td>
						<td>
							{mirror.health?.checkpointSequence ?? 'None'}
						</td>
						<td>
							{formatDuration(mirror.health?.leaseRemainingSeconds ?? null)}
						</td>
						<td>
							{formatDuration(mirror.health?.observedAgeSeconds ?? null)}
						</td>
					</tr>
				{:else}
					<tr>
						<td colspan="6" class="empty-state">Loading configured mirrors...</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>

	{#if configuredMirrors.length > 15}
		<div class="table-footer">
			<span>Showing 15 of {configuredMirrors.length} configured mirrors.</span>
			<button
				type="button"
				class="button"
				onclick={() => onnavigate('mirrors')}
			>
				View all {configuredMirrors.length} mirrors
			</button>
		</div>
	{/if}
</section>

{#if selectedJobId !== null}
	<JobDetail
		id={selectedJobId}
		{csrf}
		canCancel={canSync}
		onclose={() => {
			selectedJobId = null;
		}}
		{onerror}
	/>
{/if}
