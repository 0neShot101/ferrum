<script lang="ts">
	import { onMount } from 'svelte';
	import {
		createConfigProposal,
		fetchConfig,
		previewConfigPatch,
		saveConfigProposal
	} from '$lib/services/api';
	import type {
		ConfigPatch,
		ConfigPayload,
		ConfigPreview,
		EditableSettingSpec,
		SettingsPageProps
	} from '$lib/types/admin';
	import { formatBytes } from '$lib/utils/format';
	import EvidenceTable from './EvidenceTable.svelte';
	import StatCard from './StatCard.svelte';
	import StatusBadge from './StatusBadge.svelte';

	let { csrf, canManage, onerror }: SettingsPageProps = $props();

	let config = $state<ConfigPayload | null>(null);
	let preview = $state<ConfigPreview | null>(null);
	let edits = $state<Record<string, string>>({});
	let reason = $state('Tune cache and cold-fill concurrency settings');
	let busy = $state(false);
	let message = $state('');
	let loading = $state(true);
	let refreshing = false;
	const controller = new AbortController();

	const settingSpecs: EditableSettingSpec[] = [
		{
			key: 'concurrentFills',
			label: 'Concurrent upstream fills',
			unit: 'producers',
			min: 1,
			max: 64,
			group: 'cache',
			description: 'Max simultaneous cold-miss package/index downloads (raise to 32-64 for fast cold starts).'
		},
		{
			key: 'waitersPerObject',
			label: 'Waiters per single-flight object',
			unit: 'clients',
			min: 1,
			max: 64,
			group: 'cache',
			description: 'Max concurrent callers sharing one in-flight package download.'
		},
		{
			key: 'activeBodies',
			label: 'Active response body streams',
			unit: 'streams',
			min: 1,
			max: 256,
			group: 'cache',
			description: 'Max concurrent package/metadata bodies streaming from local NVMe.'
		},
		{
			key: 'requestSlots',
			label: 'Public request admission slots',
			unit: 'requests',
			min: 1,
			max: 1024,
			group: 'cache',
			description: 'Max concurrent public HTTP requests admitted into the pipeline.'
		},
		{
			key: 'readerBufferBytes',
			label: 'NVMe reader chunk buffer',
			unit: 'bytes',
			min: 4096,
			max: 262144,
			group: 'cache',
			description: 'Per-stream read chunk size (up to 262,144 bytes = 256 KiB).'
		},
		{
			key: 'failureMapEntries',
			label: 'Negative failure cache entries',
			unit: 'entries',
			min: 1,
			max: 10000,
			group: 'cache',
			description: 'Bounded in-memory backoff map size for failed upstream objects.'
		},
		{
			key: 'sourceAttempts',
			label: 'Upstream retry attempts',
			unit: 'attempts',
			min: 1,
			max: 2,
			group: 'cache',
			description: 'Attempts per cold fill before returning an error.'
		},
		{
			key: 'admissionWaitSeconds',
			label: 'Admission queue wait',
			unit: 'seconds',
			min: 1,
			max: 2,
			group: 'timeouts',
			description: 'Max wait for a request or fill slot before returning 503.'
		},
		{
			key: 'waiterTimeoutSeconds',
			label: 'Single-flight waiter timeout',
			unit: 'seconds',
			min: 1,
			max: 30,
			group: 'timeouts',
			description: 'Max time a follower waits on an in-flight fill (producer continues).'
		},
		{
			key: 'producerDeadlineSeconds',
			label: 'Producer fill deadline',
			unit: 'seconds',
			min: 1,
			max: 600,
			group: 'timeouts',
			description: 'Max total duration for one cold package or metadata fill.'
		},
		{
			key: 'connectTimeoutSeconds',
			label: 'Upstream connect timeout',
			unit: 'seconds',
			min: 1,
			max: 3,
			group: 'timeouts',
			description: 'TCP/TLS connection timeout to upstream origins.'
		},
		{
			key: 'responseHeaderTimeoutSeconds',
			label: 'Upstream header timeout',
			unit: 'seconds',
			min: 1,
			max: 10,
			group: 'timeouts',
			description: 'Timeout waiting for upstream HTTP response headers.'
		},
		{
			key: 'readIdleTimeoutSeconds',
			label: 'Upstream read idle timeout',
			unit: 'seconds',
			min: 1,
			max: 30,
			group: 'timeouts',
			description: 'Max idle gap between upstream body chunks.'
		},
		{
			key: 'failureBackoffSeconds',
			label: 'Failed fill backoff window',
			unit: 'seconds',
			min: 1,
			max: 30,
			group: 'timeouts',
			description: 'How long a failed object stays in negative cache backoff.'
		},
		{
			key: 'bodyWriteIdleSeconds',
			label: 'Client socket write idle timeout',
			unit: 'seconds',
			min: 1,
			max: 30,
			group: 'timeouts',
			description: 'Drops stalled client downloads that stop reading.'
		},
		{
			key: 'bodyLifetimeSeconds',
			label: 'Max response body lifetime',
			unit: 'seconds',
			min: 1,
			max: 900,
			group: 'timeouts',
			description: 'Maximum duration of a single response stream.'
		},
		{
			key: 'verifierTimeoutSeconds',
			label: 'PGP verifier timeout',
			unit: 'seconds',
			min: 1,
			max: 30,
			group: 'timeouts',
			description: 'Subprocess timeout for ferrum-verifier (sqv).'
		}
	];

	const cacheSpecs = $derived(settingSpecs.filter((spec) => spec.group === 'cache'));
	const timeoutSpecs = $derived(settingSpecs.filter((spec) => spec.group === 'timeouts'));

	const hasPendingEdits = $derived(
		Object.values(edits).some((value) => value.trim() !== '')
	);

	const runningLimits = $derived(
		(config?.running.limits as Record<string, unknown> | undefined) ?? {}
	);

	const runningVerifier = $derived(
		(config?.running.verifier as Record<string, unknown> | undefined) ?? {}
	);

	const currentRunningValue = (key: string): string => {
		if (key === 'verifierTimeoutSeconds')
			return String(runningVerifier.timeoutSeconds ?? '');
		return String(runningLimits[key] ?? '');
	};

	const loadConfig = async (): Promise<void> => {
		if (refreshing) return;
		refreshing = true;
		loading = true;
		try {
			const result = await fetchConfig(controller.signal);
			if (controller.signal.aborted === false) config = result;
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		} finally {
			refreshing = false;
			loading = false;
		}
	};

	const buildPatch = (): ConfigPatch => {
		const limits: Record<string, number | string> = {};
		let verifierTimeoutSeconds: number | undefined = undefined;
		for (const [name, value] of Object.entries(edits)) {
			const trimmed = value.trim();
			if (trimmed === '') continue;
			if (name === 'verifierTimeoutSeconds')
				verifierTimeoutSeconds = Number(trimmed);
			else
				limits[name] =
					name === 'readerBufferBytes' ? trimmed : Number(trimmed);
		}
		return {
			limits,
			...(verifierTimeoutSeconds !== undefined ? { verifierTimeoutSeconds } : {})
		};
	};

	const handlePreview = async (): Promise<void> => {
		if (config === null || busy) return;
		busy = true;
		try {
			const result = await previewConfigPatch(
				csrf,
				config.savedRevision ?? config.runningRevision,
				buildPatch(),
				controller.signal
			);
			if (controller.signal.aborted === false) preview = result;
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		} finally {
			busy = false;
		}
	};

	const handlePropose = async (): Promise<void> => {
		if (preview === null || busy) return;
		busy = true;
		try {
			const result = await createConfigProposal(
				csrf,
				preview.baseRevision,
				buildPatch(),
				reason,
				controller.signal
			);
			if (controller.signal.aborted === false) {
				message = `Created proposal ${result.proposal.id.slice(0, 12)}. Click Save to managed config below to write it to disk.`;
				await loadConfig();
			}
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		} finally {
			busy = false;
		}
	};

	const handleSaveProposal = async (proposalId: string): Promise<void> => {
		if (busy) return;
		busy = true;
		try {
			await saveConfigProposal(csrf, proposalId, controller.signal);
			if (controller.signal.aborted === false) {
				message =
					'Saved to managed configuration file. Restart ferrum.service to apply new limits.';
				await loadConfig();
			}
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		} finally {
			busy = false;
		}
	};

	onMount(() => {
		void loadConfig();
		return () => {
			controller.abort();
		};
	});
</script>

<div class="toolbar spaced-panel">
	<p class="page-description">
		Cache sizing, cold-fill concurrency, and request timeout settings.
	</p>
	<button class="button" type="button" onclick={loadConfig}>
		Refresh settings
	</button>
</div>

{#if message !== ''}
	<p class="notice" role="status">{message}</p>
{/if}

{#if config !== null}
	<div class="grid-cards spaced-panel">
		<StatCard
			title="Managed NVMe cache ceiling"
			value={formatBytes(String(runningLimits.managedCeilingBytes ?? '0'))}
			subtitle={`Max single object: ${formatBytes(String(runningLimits.maxObjectBytes ?? '0'))}`}
		/>

		<StatCard
			title="Concurrent cold fills"
			value={`${String(runningLimits.concurrentFills ?? '8')} producers`}
			subtitle={`${String(runningLimits.waitersPerObject ?? '64')} waiters/object · ${String(runningLimits.activeBodies ?? '256')} body streams`}
		/>

		<StatCard
			title="Reader buffer & slots"
			value={formatBytes(String(runningLimits.readerBufferBytes ?? '262144'))}
			subtitle={`${String(runningLimits.requestSlots ?? '1024')} request slots · ${String(runningLimits.failureMapEntries ?? '10000')} negative cache entries`}
		/>

		<StatCard
			title="Configuration status"
			value={config.restartRequired ? 'Restart required' : 'In sync'}
			subtitle={config.managedConfigEnabled
				? 'Managed config save enabled'
				: 'Read-only config file'}
		/>
	</div>

	{#if canManage}
		<form
			onsubmit={(event) => {
				event.preventDefault();
				void handlePreview();
			}}
		>
			<section class="card spaced-panel">
				<div class="row-between">
					<div>
						<h2>Cache & fill concurrency settings</h2>
						<p class="muted">
							Leave a field blank to keep its current value ({currentRunningValue(
								'concurrentFills'
							)} concurrent fills currently active).
						</p>
					</div>
					<StatusBadge
						tone={config.managedConfigEnabled ? 'ok' : 'warn'}
						label={config.managedConfigEnabled ? 'Managed config writable' : 'Proposal only'}
					/>
				</div>

				<div class="filter-grid">
					{#each cacheSpecs as spec (spec.key)}
						<label class="field">
							<span>
								{spec.label} ({spec.min} to {spec.max} {spec.unit})
							</span>
							<input
								class="input"
								type="number"
								min={spec.min}
								max={spec.max}
								step="1"
								placeholder={`Current: ${currentRunningValue(spec.key)}`}
								value={edits[spec.key] ?? ''}
								disabled={busy}
								oninput={(event) => {
									edits[spec.key] = event.currentTarget.value;
									preview = null;
								}}
							/>
							<small class="muted">{spec.description}</small>
						</label>
					{/each}
				</div>
			</section>

			<section class="card spaced-panel">
				<h2>Transfer & verifier timeouts</h2>
				<div class="filter-grid">
					{#each timeoutSpecs as spec (spec.key)}
						<label class="field">
							<span>
								{spec.label} ({spec.min} to {spec.max} {spec.unit})
							</span>
							<input
								class="input"
								type="number"
								min={spec.min}
								max={spec.max}
								step="1"
								placeholder={`Current: ${currentRunningValue(spec.key)}`}
								value={edits[spec.key] ?? ''}
								disabled={busy}
								oninput={(event) => {
									edits[spec.key] = event.currentTarget.value;
									preview = null;
								}}
							/>
							<small class="muted">{spec.description}</small>
						</label>
					{/each}
				</div>

				<div class="toolbar">
					<button
						class="button is-primary"
						type="submit"
						disabled={busy || hasPendingEdits === false}
					>
						Preview changes
					</button>
					{#if hasPendingEdits}
						<button
							class="button"
							type="button"
							disabled={busy}
							onclick={() => {
								edits = {};
								preview = null;
							}}
						>
							Reset inputs
						</button>
					{/if}
				</div>
			</section>
		</form>

		{#if preview !== null}
			<section class="card spaced-panel">
				<h2>Validated configuration diff</h2>
				<div class="table-wrap">
					<table>
						<thead>
							<tr>
								<th>Setting</th>
								<th>Current value</th>
								<th>Proposed value</th>
								<th>Restart</th>
							</tr>
						</thead>
						<tbody>
							{#each preview.diffs as diff (diff.field)}
								<tr>
									<td><strong>{diff.field}</strong></td>
									<td>{JSON.stringify(diff.before)}</td>
									<td>{JSON.stringify(diff.after)}</td>
									<td>Required</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>

				<pre>{preview.tomlPreview}</pre>

				<form
					onsubmit={(event) => {
						event.preventDefault();
						void handlePropose();
					}}
				>
					<label class="field">
						<span>Operator reason</span>
						<textarea bind:value={reason} maxlength="1024" required></textarea>
					</label>
					<button class="button is-primary" type="submit" disabled={busy}>
						Create proposal
					</button>
				</form>
			</section>
		{/if}
	{/if}

	<section class="card spaced-panel">
		<h2>Saved proposals ({config.proposals.length})</h2>
		{#each config.proposals as proposal (proposal.id)}
			<article class="alert-row">
				<div>
					<StatusBadge
						tone={proposal.state === 'saved' ? 'ok' : 'warn'}
						label={proposal.status}
					/>
					<code class="mono"> {proposal.id.slice(0, 14)}...</code>
					<p>{proposal.reason}</p>
					<small class="muted">
						{proposal.diffs
							.map(
								(diff) =>
									`${diff.field}: ${JSON.stringify(diff.before)} -> ${JSON.stringify(diff.after)}`
							)
							.join(', ')}
					</small>
				</div>

				{#if canManage && config.managedConfigEnabled && proposal.state === 'proposed'}
					<button
						class="button is-primary"
						type="button"
						disabled={busy}
						onclick={() => handleSaveProposal(proposal.id)}
					>
						Save to managed config
					</button>
				{/if}
			</article>
		{:else}
			<p class="muted">No configuration proposals recorded yet.</p>
		{/each}
	</section>

	<section class="card">
		<h2>Effective running configuration (redacted)</h2>
		<EvidenceTable values={config.running} caption="Running gateway configuration" />
	</section>
{:else}
	<p role="status">
		{loading ? 'Loading configuration...' : 'Configuration unavailable.'}
	</p>
{/if}
