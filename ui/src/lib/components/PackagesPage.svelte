<script lang="ts">
	import { onMount } from 'svelte';
	import { fetchPackageDetail, fetchPackages } from '$lib/services/api';
	import type {
		CapturedPackage,
		PackageFilters,
		PackagesPage,
		PackagesPageProps
	} from '$lib/types/admin';
	import { formatBytes, formatCounter, formatTimestamp } from '$lib/utils/format';
	import EvidenceTable from './EvidenceTable.svelte';
	import Modal from './Modal.svelte';
	import StatCard from './StatCard.svelte';
	import StatusBadge from './StatusBadge.svelte';

	let { onerror }: PackagesPageProps = $props();

	let filters = $state<PackageFilters>({
		repository: '',
		suite: '',
		digestPrefix: '',
		pathPrefix: '',
		cacheStatus: '',
		remoteStatus: ''
	});
	let appliedFilters: PackageFilters = {};
	let page = $state<PackagesPage | null>(null);
	let detail = $state<CapturedPackage | null>(null);
	let busy = $state(false);
	let copiedMessage = $state('');
	let controller = new AbortController();

	const loadPackages = async (useNextCursor = false): Promise<void> => {
		controller.abort();
		controller = new AbortController();
		const signal = controller.signal;
		busy = true;
		if (useNextCursor === false) appliedFilters = { ...filters };
		try {
			const result = await fetchPackages(
				{
					...appliedFilters,
					cursor: useNextCursor ? (page?.nextCursor ?? undefined) : undefined,
					limit: 50
				},
				signal
			);
			if (signal.aborted === false) page = result;
		} catch (error) {
			if (signal.aborted === false) onerror(error);
		} finally {
			if (signal.aborted === false) busy = false;
		}
	};

	const showPackageDetail = async (packageId: string): Promise<void> => {
		const signal = controller.signal;
		try {
			const result = await fetchPackageDetail(packageId, signal);
			if (signal.aborted === false) detail = result.package;
		} catch (error) {
			if (signal.aborted === false) onerror(error);
		}
	};

	const copyText = async (text: string): Promise<void> => {
		try {
			await navigator.clipboard.writeText(text);
			copiedMessage = 'Copied to clipboard.';
		} catch (error) {
			onerror(error);
		}
	};

	const cacheTone = (cacheStatus: string): 'ok' | 'warn' | 'neutral' => {
		if (cacheStatus === 'resident_cached' || cacheStatus === 'resident_pinned')
			return 'ok';
		if (cacheStatus === 'resident_staged' || cacheStatus === 'evicting') return 'warn';
		return 'neutral';
	};

	const remoteTone = (remoteStatus: string): 'ok' | 'warn' | 'danger' | 'neutral' => {
		if (remoteStatus === 'verified_durable') return 'ok';
		if (remoteStatus === 'quarantined') return 'danger';
		if (remoteStatus.startsWith('outbox_') || remoteStatus === 'admitted_filling')
			return 'warn';
		return 'neutral';
	};

	onMount(() => {
		void loadPackages(false);
		return () => {
			controller.abort();
		};
	});
</script>

<p class="page-description">
	Catalog explorer of packages captured by Ferrum into local NVMe and S3. Browsing queries
	local SQLite records with zero S3 requests and zero allowance changes.
</p>

<form
	class="card filter-grid spaced-panel"
	onsubmit={(event) => {
		event.preventDefault();
		void loadPackages(false);
	}}
>
	<label class="field">
		<span>Repository</span>
		<input
			class="input"
			bind:value={filters.repository}
			maxlength="64"
			placeholder="debian, ubuntu..."
		/>
	</label>

	<label class="field">
		<span>Suite</span>
		<input
			class="input"
			bind:value={filters.suite}
			maxlength="128"
			placeholder="trixie, noble..."
		/>
	</label>

	<label class="field">
		<span>SHA-256 prefix</span>
		<input
			class="input"
			bind:value={filters.digestPrefix}
			maxlength="64"
			placeholder="Hex digest prefix"
		/>
	</label>

	<label class="field">
		<span>Path prefix</span>
		<input
			class="input"
			bind:value={filters.pathPrefix}
			maxlength="1024"
			placeholder="pool/main/..."
		/>
	</label>

	<label class="field">
		<span>Local NVMe cache</span>
		<select class="input" bind:value={filters.cacheStatus}>
			<option value="">All</option>
			<option value="resident_cached">Resident (evictable cache)</option>
			<option value="resident_pinned">Resident (pinned)</option>
			<option value="resident_staged">Resident (staged for S3 upload)</option>
			<option value="evicting">Evicting</option>
			<option value="remote_only">Evicted locally (S3 only)</option>
		</select>
	</label>

	<label class="field">
		<span>S3 durability state</span>
		<select class="input" bind:value={filters.remoteStatus}>
			<option value="">All</option>
			<option value="verified_durable">Verified durable in S3</option>
			<option value="outbox_queued">Outbox queued</option>
			<option value="outbox_uploading">Outbox uploading</option>
			<option value="outbox_backoff">Outbox backoff</option>
			<option value="admitted_filling">Filling from origin</option>
			<option value="pending_verification">Pending verification</option>
			<option value="quarantined">Quarantined</option>
		</select>
	</label>

	<div class="toolbar">
		<button class="button is-primary" disabled={busy} type="submit">
			Apply filters
		</button>
	</div>
</form>

{#if busy}
	<p role="status">Loading captured package catalog...</p>
{/if}

{#if page === null && busy === false}
	<p class="notice" role="status">
		Captured package inventory is temporarily busy. Narrow your prefix filter and retry.
	</p>
{/if}

{#if page !== null}
	{#if page.unavailable !== undefined}
		<p class="notice">{page.unavailable}</p>
	{/if}

	{#if page.summary !== null}
		<div class="grid-cards spaced-panel">
			<StatCard
				title="Captured package paths"
				value={formatCounter(page.summary.paths)}
				subtitle="Repository path mappings"
			/>
			<StatCard
				title="Deduplicated blobs"
				value={formatCounter(page.summary.blobs)}
				subtitle={formatBytes(page.summary.blobBytes)}
			/>
			<StatCard
				title="Resident in local NVMe"
				value={formatCounter(page.summary.residentBlobs)}
				subtitle={formatBytes(page.summary.residentBytes)}
			/>
			<StatCard
				title="Verified durable in S3"
				value={formatCounter(page.summary.verifiedBlobs)}
				subtitle={formatBytes(page.summary.verifiedBytes)}
			/>
		</div>
	{/if}

	<section class="card table-panel">
		<div class="table-wrap">
			<table>
				<thead>
					<tr>
						<th>Captured package path</th>
						<th>Suite</th>
						<th>Size</th>
						<th>Local cache</th>
						<th>S3 status</th>
						<th>SHA-256</th>
						<th>Retained until</th>
					</tr>
				</thead>
				<tbody>
					{#each page.items as item (item.id)}
						<tr>
							<td class="break-word">
								<button
									type="button"
									class="text-button"
									onclick={() => showPackageDetail(item.id)}
								>
									{item.repository}/{item.path}
								</button>
							</td>
							<td>{item.recordedSuite ?? 'Unrecorded'}</td>
							<td>
								<span title={`${item.size} bytes`}>{formatBytes(item.size)}</span>
							</td>
							<td>
								<StatusBadge
									tone={cacheTone(item.cacheStatus)}
									label={item.cacheStatus}
								/>
							</td>
							<td>
								<StatusBadge
									tone={remoteTone(item.remoteStatus)}
									label={item.remoteStatus}
								/>
							</td>
							<td class="mono">{item.digest.slice(0, 14)}...</td>
							<td>{formatTimestamp(item.retainUntil)}</td>
						</tr>
					{:else}
						<tr>
							<td colspan="7" class="empty-state">
								No captured packages match these filters.
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>

		<div class="table-footer">
			<span>
				Observed {formatTimestamp(page.sampledAt)} · 50 rows per page · Ordered by
				repository and path
			</span>
			<button
				class="button"
				type="button"
				disabled={busy || page.hasMore === false || page.nextCursor === null}
				onclick={() => loadPackages(true)}
			>
				Next page
			</button>
		</div>
	</section>
{/if}

{#if detail !== null}
	<Modal
		title={detail.displayName}
		onclose={() => {
			detail = null;
			copiedMessage = '';
		}}
	>
		<p class="notice">
			Recorded in local SQLite catalog (not a live S3 network check).
		</p>
		<div class="toolbar">
			<button
				class="button"
				type="button"
				onclick={() => {
					if (detail !== null) void copyText(detail.path);
				}}
			>
				Copy path
			</button>
			<button
				class="button"
				type="button"
				onclick={() => {
					if (detail !== null) void copyText(detail.digest);
				}}
			>
				Copy SHA-256
			</button>
			{#if detail.objectKey !== null}
				<button
					class="button"
					type="button"
					onclick={() => {
						if (detail !== null && detail.objectKey !== null)
							void copyText(detail.objectKey);
					}}
				>
					Copy S3 key
				</button>
			{/if}
		</div>
		{#if copiedMessage !== ''}
			<p class="muted" role="status">{copiedMessage}</p>
		{/if}
		<EvidenceTable
			values={detail}
			caption="Captured path, proof generation, local residency, and S3 object key"
		/>
	</Modal>
{/if}
