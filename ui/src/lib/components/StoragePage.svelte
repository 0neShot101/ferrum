<script lang="ts">
	import { onMount } from 'svelte';
	import {
		clearCache,
		fetchOverview,
		fetchStorage,
		previewCacheClear
	} from '$lib/services/api';
	import type {
		CachePreview,
		OverviewPayload,
		StoragePageProps,
		StoragePayload
	} from '$lib/types/admin';
	import {
		decimalU64,
		formatBytes,
		formatCounter,
		formatPercent,
		formatTimestamp
	} from '$lib/utils/format';
	import EvidenceTable from './EvidenceTable.svelte';
	import JobDetail from './JobDetail.svelte';
	import Modal from './Modal.svelte';
	import StatCard from './StatCard.svelte';
	import StatusBadge from './StatusBadge.svelte';

	let { csrf, canManage, ontaskcreated, onerror }: StoragePageProps = $props();

	let storage = $state<StoragePayload | null>(null);
	let overview = $state<OverviewPayload | null>(null);
	let loading = $state(true);
	let preview = $state<CachePreview | null>(null);
	let targetMegabytes = $state('');
	let reason = $state('Reclaim evictable local package cache');
	let confirmed = $state(false);
	let busy = $state(false);
	let jobId = $state<string | null>(null);
	let message = $state('');
	let requestKey = '';
	let requestSignature = '';
	const controller = new AbortController();

	const localUsagePercent = $derived(
		storage !== null
			? formatPercent(
					String(storage.local.managedBytes ?? '0'),
					String(storage.local.managedCeilingBytes ?? '1')
				)
			: 0
	);

	const packageCacheBytes = $derived.by(() => {
		if (storage === null) return 0n;
		const installed = decimalU64(String(storage.local.installedBytes ?? '0')) ?? 0n;
		const metadata = decimalU64(String(storage.local.metadataInstalledBytes ?? '0')) ?? 0n;
		return installed > metadata ? installed - metadata : 0n;
	});

	const loadStorage = async (): Promise<void> => {
		loading = true;
		try {
			const [storageResult, overviewResult] = await Promise.all([
				fetchStorage(controller.signal),
				fetchOverview(controller.signal)
			]);
			if (controller.signal.aborted === false) {
				storage = storageResult;
				overview = overviewResult;
			}
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		} finally {
			loading = false;
		}
	};

	const inspectEvictableCache = async (): Promise<void> => {
		if (busy) return;
		busy = true;
		message = '';
		try {
			const result = await previewCacheClear(csrf, controller.signal);
			if (controller.signal.aborted === false) {
				preview = result;
				confirmed = false;
			}
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		} finally {
			busy = false;
		}
	};

	const executeCacheClear = async (): Promise<void> => {
		if (confirmed === false || busy) return;
		const trimmedMb = targetMegabytes.trim();
		const targetBytes =
			trimmedMb !== '' && /^\d+$/.test(trimmedMb)
				? (BigInt(trimmedMb) * 1048576n).toString()
				: undefined;
		const finalReason =
			reason.trim() === '' ? 'Reclaim evictable local package cache' : reason.trim();
		const signature = JSON.stringify({ targetBytes, finalReason });
		if (signature !== requestSignature) {
			requestKey = crypto.randomUUID();
			requestSignature = signature;
		}
		busy = true;
		try {
			const result = await clearCache(
				csrf,
				{
					targetBytes,
					reason: finalReason,
					idempotencyKey: requestKey
				},
				controller.signal
			);
			if (controller.signal.aborted === false) {
				preview = null;
				requestSignature = '';
				message = `Reclaimed ${formatBytes(result.freedBytes)} across ${formatCounter(result.evictedObjects)} local package objects.`;
				ontaskcreated(result.job);
				await loadStorage();
			}
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		} finally {
			busy = false;
		}
	};

	onMount(() => {
		void loadStorage();
		return () => {
			controller.abort();
		};
	});
</script>

<div class="toolbar spaced-panel">
	<p class="page-description">
		Local NVMe package cache, CLOCK eviction watermarks, and S3 transfer allowance ledger.
	</p>
	<button class="button" type="button" onclick={loadStorage}>
		Refresh cache & storage
	</button>
</div>

{#if message !== ''}
	<p class="notice" role="status">{message}</p>
{/if}

{#if storage !== null}
	<div class="grid-cards spaced-panel">
		<StatCard
			title="Local package cache"
			value={formatBytes(packageCacheBytes)}
			subtitle={`${formatCounter(String(storage.local.residentEntries ?? '0'))} total resident objects`}
		/>

		<StatCard
			title="Pinned metadata cache"
			value={formatBytes(String(storage.local.metadataInstalledBytes ?? '0'))}
			subtitle={`SQLite catalog: ${formatBytes(String(storage.local.catalogBytes ?? '0'))}`}
		/>

		<StatCard
			title="Managed spool usage"
			value={`${formatBytes(String(storage.local.managedBytes ?? '0'))} / ${formatBytes(String(storage.local.managedCeilingBytes ?? '0'))}`}
			subtitle={`${localUsagePercent}% of ceiling · ${formatBytes(String(storage.local.filesystemAvailableBytes ?? '0'))} free on disk`}
		/>

		<StatCard
			title="Capture outbox & S3 circuit"
			value={storage.capture !== null
				? `${formatCounter(String(storage.capture.outboxEntries ?? '0'))} queued (${formatBytes(String(storage.capture.outboxBytes ?? '0'))})`
				: 'Fixture mode'}
			subtitle={`Coverage ${storage.capture?.coverageReady === true ? 'ready' : 'pending'} · Circuit ${storage.circuitOpen === true ? 'OPEN' : 'closed'}`}
		/>
	</div>

	<section class="card spaced-panel">
		<div class="row-between">
			<div>
				<h2>Local NVMe cache & eviction controls</h2>
				<p class="muted">
					CLOCK eviction automatically reclaims verified package cache at the 90% high
					watermark down to 80%. Active metadata, pinned fills, live HTTP readers, and
					unuploaded outbox objects are never evicted.
				</p>
			</div>
			<StatusBadge
				tone={storage.local.admissionOpen === true ? 'ok' : 'danger'}
				label={storage.local.admissionOpen === true ? 'Admission open' : 'Admission closed'}
			/>
		</div>

		<progress
			class="cache-usage-bar"
			max="100"
			value={localUsagePercent}
		></progress>

		{#if overview !== null}
			<div class="source-tier-grid spaced-panel">
				<div class="stat-block">
					<p class="stat-title">Local NVMe hits</p>
					<p class="stat-value">
						{formatCounter(overview.cacheSources.local_hit ?? '0')}
					</p>
				</div>
				<div class="stat-block">
					<p class="stat-title">304 Not Modified</p>
					<p class="stat-value">
						{formatCounter(overview.cacheSources.conditional_304 ?? '0')}
					</p>
				</div>
				<div class="stat-block">
					<p class="stat-title">S3 rehydrations</p>
					<p class="stat-value">
						{formatCounter(overview.cacheSources.s3_rehydrated ?? '0')}
					</p>
				</div>
				<div class="stat-block">
					<p class="stat-title">Origin cold fills</p>
					<p class="stat-value">
						{formatCounter(overview.cacheSources.origin_fill ?? '0')}
					</p>
				</div>
				<div class="stat-block">
					<p class="stat-title">Derived expansions</p>
					<p class="stat-value">
						{formatCounter(overview.cacheSources.derived_expanded ?? '0')}
					</p>
				</div>
			</div>
		{/if}

		{#if canManage}
			<div class="toolbar">
				<button
					class="button is-primary"
					type="button"
					disabled={busy}
					onclick={inspectEvictableCache}
				>
					Preview & clear local package cache
				</button>
			</div>
		{/if}
	</section>

	<div class="grid-cards spaced-panel">
		<section class="card">
			<h2>Local spool partitions & watermarks</h2>
			<EvidenceTable
				values={storage.local}
				caption="Local NVMe capacity and enforced watermarks"
			/>
		</section>

		<section class="card">
			<h2>S3 allowance ledger</h2>
			<p class="muted">
				Recorded S3 storage and monthly UTC download ledger. Evicting local NVMe cache
				never deletes S3 objects or resets S3 allowances.
			</p>
			{#if storage.remote !== null}
				<EvidenceTable
					values={storage.remote}
					caption="Recorded S3 budget and provider binding"
				/>
			{:else}
				<p>{storage.remoteError ?? 'Remote S3 diagnostics unavailable in fixture mode.'}</p>
			{/if}
		</section>
	</div>
{:else}
	<p role="status">
		{loading ? 'Loading cache and storage diagnostics...' : 'Storage diagnostics unavailable.'}
	</p>
{/if}

{#if preview !== null}
	<Modal
		title="Reclaim local NVMe package cache"
		onclose={() => {
			preview = null;
		}}
	>
		<p>
			Currently eligible for eviction:
			<strong>{formatCounter(preview.eligible.objects)}</strong> package objects
			(<strong>{formatBytes(preview.eligible.bytes)}</strong>).
		</p>

		<EvidenceTable
			values={preview.protected}
			caption="Protected local objects (never removed)"
		/>

		<form
			onsubmit={(event) => {
				event.preventDefault();
				void executeCacheClear();
			}}
		>
			<label class="field">
				<span>Target MiB to reclaim (optional; leave blank to clear all evictable cache)</span>
				<input
					class="input"
					bind:value={targetMegabytes}
					pattern="[0-9]*"
					inputmode="numeric"
					maxlength="12"
					placeholder="All evictable package cache"
				/>
			</label>

			<label class="field">
				<span>Operator reason</span>
				<textarea bind:value={reason} required maxlength="1024"></textarea>
			</label>

			<label class="checkbox-item">
				<input type="checkbox" bind:checked={confirmed} required />
				<span>
					Confirm local package cache eviction (S3 objects and metadata remain untouched)
				</span>
			</label>

			<button
				class="button is-primary"
				type="submit"
				disabled={busy || confirmed === false}
			>
				Reclaim local cache
			</button>
		</form>
	</Modal>
{/if}

{#if jobId !== null}
	<JobDetail
		id={jobId}
		{csrf}
		canCancel={false}
		onclose={() => {
			jobId = null;
		}}
		{onerror}
	/>
{/if}
