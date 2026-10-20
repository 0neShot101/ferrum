<script lang="ts">
	import { onMount } from 'svelte';
	import { cancelJob, fetchJobs } from '$lib/services/api';
	import type { OperationJob, SuiteJobState, TaskTrayProps } from '$lib/types/admin';
	import { formatBytes, formatTimestamp } from '$lib/utils/format';
	import StatusBadge from './StatusBadge.svelte';

	let { csrf, canCancel, pulseSignal, onselectjob, onerror }: TaskTrayProps = $props();

	let open = $state(false);
	let jobs = $state<OperationJob[]>([]);
	let activeSuites = $state<SuiteJobState[]>([]);
	let busyId = $state<string | null>(null);
	let lastPulse = 0;
	let loading = false;
	const controller = new AbortController();

	const runningJobs = $derived(
		jobs.filter((job) => job.state === 'queued' || job.state === 'running')
	);

	const runningSuites = $derived(
		activeSuites.filter(
			(suite) =>
				suite.phase !== 'idle' &&
				suite.phase !== 'published' &&
				suite.phase !== 'renewed' &&
				suite.phase !== 'failed' &&
				suite.phase !== 'rejected'
		)
	);

	const activeCount = $derived(runningJobs.length + runningSuites.length);

	const recentJobs = $derived(jobs.slice(0, 8));

	const loadTasks = async (): Promise<void> => {
		if (loading || document.hidden) return;
		loading = true;
		try {
			const response = await fetchJobs({ limit: 12 }, controller.signal);
			if (controller.signal.aborted === false) {
				jobs = response.jobs;
				activeSuites = response.activeSuites;
			}
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		} finally {
			loading = false;
		}
	};

	const toggleTray = (): void => {
		open = open === false;
		if (open) void loadTasks();
	};

	const closeTray = (): void => {
		open = false;
	};

	const handleCancel = async (jobId: string): Promise<void> => {
		if (busyId !== null) return;
		busyId = jobId;
		try {
			await cancelJob(csrf, jobId, controller.signal);
			await loadTasks();
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		} finally {
			busyId = null;
		}
	};

	const progressPercent = (completed: number | null, total: number | null): number => {
		if (completed === null || total === null || total <= 0) return 25;
		return Math.min(100, Math.max(8, Math.round((completed / total) * 100)));
	};

	const jobProgressPercent = (job: OperationJob): number => {
		if (job.state === 'succeeded') return 100;
		if (job.targets.length === 0) return job.state === 'running' ? 50 : 15;
		const finished = job.targets.filter(
			(target) =>
				target.state === 'published' ||
				target.state === 'renewed' ||
				target.state === 'failed' ||
				target.state === 'rejected' ||
				target.state === 'cancelled'
		).length;
		return Math.min(100, Math.max(10, Math.round((finished / job.targets.length) * 100)));
	};

	const badgeTone = (state: string): 'ok' | 'warn' | 'danger' | 'neutral' => {
		if (state === 'succeeded' || state === 'published' || state === 'renewed') return 'ok';
		if (state === 'running' || state === 'queued' || state === 'staging' || state === 'observing')
			return 'warn';
		if (state === 'failed' || state === 'rejected' || state === 'interrupted') return 'danger';
		return 'neutral';
	};

	onMount(() => {
		void loadTasks();
		const timer = setInterval(() => {
			if (document.hidden === false && (open || activeCount > 0)) void loadTasks();
		}, 3000);
		return () => {
			clearInterval(timer);
			controller.abort();
		};
	});

	$effect(() => {
		if (pulseSignal > lastPulse) {
			lastPulse = pulseSignal;
			open = true;
			void loadTasks();
		}
	});
</script>

<div class="task-tray-anchor">
	<button
		type="button"
		class={['task-pill', activeCount > 0 && 'is-active']}
		aria-expanded={open}
		aria-label="Background tasks"
		onclick={toggleTray}
	>
		{#if activeCount > 0}
			<span class="task-spinner" aria-hidden="true"></span>
			<span>
				{activeCount} {activeCount === 1 ? 'task running' : 'tasks running'}
			</span>
		{:else}
			<svg
				viewBox="0 0 24 24"
				width="15"
				height="15"
				fill="none"
				stroke="currentColor"
				stroke-width="1.8"
				stroke-linecap="round"
				stroke-linejoin="round"
				aria-hidden="true"
			>
				<path d="M12 6v6l4 2" />
				<circle cx="12" cy="12" r="9" />
			</svg>
			<span>Tasks</span>
			{#if recentJobs.length > 0}
				<span class="task-count-badge">{recentJobs.length}</span>
			{/if}
		{/if}
	</button>

	{#if open}
		<section class="task-popover card" aria-label="Running and recent tasks">
			<header class="task-popover-header">
				<div>
					<h2>Tasks & sync progress</h2>
					<p class="muted">
						{activeCount > 0
							? `${activeCount} active in background`
							: 'All background tasks idle'}
					</p>
				</div>
				<div class="toolbar">
					<button class="button" type="button" onclick={loadTasks}>Refresh</button>
					<button
						class="button"
						type="button"
						onclick={closeTray}
						aria-label="Close tasks panel"
					>
						Close
					</button>
				</div>
			</header>

			<div class="task-popover-body">
				{#if runningSuites.length > 0}
					<div class="task-group">
						<p class="section-label">Active suite sync passes ({runningSuites.length})</p>
						{#each runningSuites as suite (`${suite.repository}/${suite.suite}`)}
							<div class="task-item">
								<div class="row-between">
									<strong>{suite.repository}/{suite.suite}</strong>
									<StatusBadge tone={badgeTone(suite.phase)} label={suite.phase} />
								</div>
								<progress
									class="task-progress-bar"
									max="100"
									value={progressPercent(suite.completedArtifacts, suite.totalArtifacts)}
								></progress>
								<p class="muted break-word">
									{#if suite.totalArtifacts !== null}
										Staging {suite.completedArtifacts ?? 0} of {suite.totalArtifacts} metadata files
									{:else}
										Phase: {suite.phase}
									{/if}
									{#if suite.currentPath !== null}
										· {suite.currentPath}
									{/if}
								</p>
							</div>
						{/each}
					</div>
				{/if}

				<div class="task-group">
					<p class="section-label">Recent jobs ({recentJobs.length})</p>
					{#each recentJobs as job (job.id)}
						<div class="task-item">
							<div class="row-between">
								<button
									type="button"
									class="text-button"
									onclick={() => {
										onselectjob(job.id);
										closeTray();
									}}
								>
									{job.kind === 'cache_clear' ? 'Local cache clear' : 'Mirror sync'} ·
									{job.targets.length > 0
										? `${job.targets.length} ${job.targets.length === 1 ? 'suite' : 'suites'}`
										: job.id.slice(0, 10)}
								</button>
								<StatusBadge tone={badgeTone(job.state)} label={job.state} />
							</div>

							{#if job.state === 'running' || job.state === 'queued'}
								<progress
									class="task-progress-bar"
									max="100"
									value={jobProgressPercent(job)}
								></progress>
							{/if}

							{#if job.kind === 'cache_clear' && job.freedBytes !== undefined && job.freedBytes !== null}
								<p class="muted">Reclaimed {formatBytes(job.freedBytes)}</p>
							{:else if job.targets.length > 0}
								<p class="muted break-word">
									{job.targets
										.slice(0, 3)
										.map((target) => `${target.repository}/${target.suite} (${target.phase})`)
										.join(', ')}
									{#if job.targets.length > 3}
										+{job.targets.length - 3} more
									{/if}
								</p>
							{/if}

							<div class="row-between task-item-footer">
								<small class="muted">{formatTimestamp(job.updatedAt)}</small>
								<div class="toolbar">
									{#if canCancel && job.targets.some((target) => target.state === 'queued')}
										<button
											type="button"
											class="button is-danger"
											disabled={busyId === job.id}
											onclick={() => handleCancel(job.id)}
										>
											Cancel queued
										</button>
									{/if}
									<button
										type="button"
										class="button"
										onclick={() => {
											onselectjob(job.id);
											closeTray();
										}}
									>
										Details
									</button>
								</div>
							</div>
						</div>
					{:else}
						<p class="muted">No sync or cache jobs triggered in this session yet.</p>
					{/each}
				</div>
			</div>
		</section>
	{/if}
</div>
