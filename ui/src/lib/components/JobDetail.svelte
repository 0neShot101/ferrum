<script lang="ts">
	import { onMount } from 'svelte';
	import { cancelJob, fetchJobDetail } from '$lib/services/api';
	import type { JobDetailProps, JobTarget, OperationJob } from '$lib/types/admin';
	import { formatBytes, formatCounter, formatTimestamp } from '$lib/utils/format';
	import Modal from './Modal.svelte';
	import StatusBadge from './StatusBadge.svelte';

	let { id, csrf, canCancel, onclose, onerror }: JobDetailProps = $props();

	let job = $state<OperationJob | null>(null);
	let busy = $state(false);
	let failed = $state(false);
	let loading = false;
	const controller = new AbortController();

	const loadJob = async (): Promise<void> => {
		if (loading || document.hidden) return;
		loading = true;
		failed = false;
		try {
			const result = await fetchJobDetail(id, controller.signal);
			if (controller.signal.aborted === false) job = result.job;
		} catch (error) {
			if (controller.signal.aborted === false) {
				failed = true;
				onerror(error);
			}
		} finally {
			loading = false;
		}
	};

	const handleCancel = async (): Promise<void> => {
		if (busy) return;
		busy = true;
		try {
			const result = await cancelJob(csrf, id, controller.signal);
			if (controller.signal.aborted === false) job = result.job;
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		} finally {
			busy = false;
		}
	};

	const badgeTone = (state: string): 'ok' | 'warn' | 'danger' | 'neutral' => {
		if (
			state === 'succeeded' || state === 'published' || state === 'renewed' ||
			state === 'filled' || state === 'cache_hit'
		) return 'ok';
		if (state === 'running' || state === 'queued' || state === 'partial') return 'warn';
		if (state === 'failed' || state === 'rejected' || state === 'interrupted') return 'danger';
		return 'neutral';
	};

	const formatTargetProgress = (target: JobTarget): string => {
		if (target.totalArtifacts !== null && target.totalArtifacts !== undefined)
			return `${target.completedArtifacts ?? 0} / ${target.totalArtifacts} artifacts`;
		if (target.state === 'renewed') return 'Up to date (InRelease unchanged)';
		if (target.state === 'published') return 'Published';
		if (target.state === 'failed' || target.state === 'rejected') return 'Failed';
		if (target.state === 'cancelled') return 'Cancelled';
		return 'Pending observation';
	};

	onMount(() => {
		void loadJob();
		const timer = setInterval(() => {
			if (job?.state === 'running' || job?.state === 'queued') void loadJob();
		}, 3000);
		return () => {
			clearInterval(timer);
			controller.abort();
		};
	});
</script>

<Modal title="Task details" {onclose}>
	{#if job !== null}
		<div class="job-detail-header">
			<div>
				<p class="mono break-word">{job.id}</p>
				<p class="muted">Updated {formatTimestamp(job.updatedAt)} · Actor: {job.actor}</p>
			</div>
			<StatusBadge tone={badgeTone(job.state)} label={`${job.kind}: ${job.state}`} />
		</div>

		{#if job.reason !== ''}
			<p><strong>Reason:</strong> {job.reason}</p>
		{/if}

		{#if job.recordingIncomplete === true}
			<p class="notice error">
				Durable recording is incomplete. The live outcome shown below may not be retained.
			</p>
		{/if}

		{#if job.error !== undefined && job.error !== null && job.error !== ''}
			<p class="notice error">{job.error}</p>
		{/if}

		{#if job.kind === 'cache_clear' && job.freedBytes !== undefined && job.freedBytes !== null}
			<p class="notice">
				Reclaimed <strong>{formatBytes(job.freedBytes)}</strong> across
				<strong>{formatCounter(job.evictedObjects)}</strong> local package objects.
			</p>
		{/if}

		{#if job.prewarm !== undefined && job.prewarm !== null}
			<p class="notice">
				{job.prewarm.filled} filled, {job.prewarm.cacheHits} cache hits,
				{job.prewarm.failed} failed.
				Charged {formatBytes(job.prewarm.chargedBytes)} of
				{formatBytes(job.prewarm.plannedBytes)} planned admission bytes across
				{job.prewarm.plannedObjects} package/signature objects.
			</p>
			<p class="muted">
				{job.prewarm.byteScope}. Cancellation stops background admission and unshared
				transfers; a fill joined by a foreground client may finish.
			</p>
			<div class="table-wrap">
				<table>
					<thead>
						<tr>
							<th>Package path</th>
							<th>State</th>
							<th>Admission bytes</th>
							<th>Details</th>
						</tr>
					</thead>
					<tbody>
						{#each job.prewarm.items as item (item.path)}
							<tr>
								<td class="mono break-word">{item.path}</td>
								<td><StatusBadge tone={badgeTone(item.state)} label={item.state} /></td>
								<td>{formatBytes(item.bytes)}</td>
								<td class="break-word">{item.error ?? ''}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}

		{#if job.targets.length > 0}
			<div class="table-wrap">
				<table>
					<thead>
						<tr>
							<th>Target</th>
							<th>Phase</th>
							<th>State</th>
							<th>Metadata progress</th>
							<th>Details</th>
						</tr>
					</thead>
					<tbody>
						{#each job.targets as target (`${target.repository}/${target.suite}`)}
							<tr>
								<td>
									<strong>{target.repository}/{target.suite}</strong>
									<div class="muted">{target.disposition}</div>
								</td>
								<td>
									{target.phase}
									<div class="muted">
										{target.cancellable === true ? 'Cancellable while queued' : 'Active or finished'}
									</div>
								</td>
								<td>
									<StatusBadge tone={badgeTone(target.state)} label={target.state} />
								</td>
								<td>
									{formatTargetProgress(target)}
								</td>
								<td class="break-word">
									{#if target.error !== null}
										<span class="danger-text">{target.error}</span>
									{:else if target.currentPath !== null}
										<span class="mono">{target.currentPath}</span>
									{:else if target.generationId !== null}
										<span class="mono">{target.generationId.slice(0, 16)}...</span>
									{:else}
										Waiting for pass
									{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}

		{#if canCancel && job.cancellable === true}
			<div class="toolbar">
				<button
					class="button is-danger"
					type="button"
					disabled={busy}
					onclick={handleCancel}
				>
					{job.kind === 'prewarm' ? 'Cancel prewarm' : 'Cancel queued targets'}
				</button>
			</div>
		{/if}
	{:else}
		<p role="status">
			{failed ? 'Task detail is unavailable.' : 'Loading task details...'}
		</p>
	{/if}

	{#if failed}
		<button class="button" type="button" onclick={loadJob}>Retry</button>
	{/if}
</Modal>
