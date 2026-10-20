<script lang="ts">
	import { onMount } from 'svelte';
	import {
		fetchJobs,
		fetchMirrorDetail,
		fetchMirrors,
		triggerSync
	} from '$lib/services/api';
	import type {
		Mirror,
		MirrorsPageProps,
		OperationJob,
		SuiteJobState,
		SyncTarget
	} from '$lib/types/admin';
	import { formatDuration, formatTimestamp } from '$lib/utils/format';
	import EvidenceTable from './EvidenceTable.svelte';
	import JobDetail from './JobDetail.svelte';
	import Modal from './Modal.svelte';
	import StatusBadge from './StatusBadge.svelte';

	let {
		csrf,
		canSync,
		initialTarget = '',
		ontaskcreated,
		onerror
	}: MirrorsPageProps = $props();

	let mirrors = $state<Mirror[]>([]);
	let sampledAt = $state<number | null>(null);
	let configuredOnly = $state(true);
	let search = $state('');
	let ecosystem = $state('all');
	let status = $state('all');
	let repositoryFilter = $state('');
	let suiteFilter = $state('');
	let jobs = $state<OperationJob[]>([]);
	let suiteJobs = $state<SuiteJobState[]>([]);
	let selected = $state<string[]>([]);
	let detail = $state<Mirror | null>(null);
	let pendingTargets = $state<SyncTarget[] | null>(null);
	let reason = $state('Manual metadata sync from dashboard');
	let busy = $state(false);
	let loading = $state(true);
	let jobId = $state<string | null>(null);
	let requestKey = '';
	let lastSignature = '';
	let refreshing = false;
	const controller = new AbortController();

	const visibleMirrors = $derived.by(() => {
		const filtered = mirrors.filter(
			(mirror) =>
				(configuredOnly === false || mirror.configured) &&
				(repositoryFilter === '' || mirror.repository === repositoryFilter) &&
				(suiteFilter === '' || mirror.suite === suiteFilter) &&
				(ecosystem === 'all' || mirror.ecosystem === ecosystem) &&
				(status === 'all' || mirror.status === status) &&
				`${mirror.repository}/${mirror.suite}`
					.toLowerCase()
					.includes(search.trim().toLowerCase())
		);

		return filtered.sort(
			(left, right) =>
				left.repository.localeCompare(right.repository) ||
				left.suite.localeCompare(right.suite)
		);
	});

	const loadMirrors = async (): Promise<void> => {
		if (refreshing) return;
		refreshing = true;
		try {
			const [mirrorsResponse, jobsResponse] = await Promise.all([
				fetchMirrors(controller.signal),
				fetchJobs({ limit: 50 }, controller.signal)
			]);
			if (controller.signal.aborted === false) {
				mirrors = mirrorsResponse.mirrors;
				sampledAt = mirrorsResponse.sampledAt;
				jobs = jobsResponse.jobs;
				suiteJobs = jobsResponse.activeSuites;
			}
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		} finally {
			refreshing = false;
			loading = false;
		}
	};

	const showDetail = async (repository: string, suite: string): Promise<void> => {
		try {
			const result = await fetchMirrorDetail(repository, suite, controller.signal);
			if (controller.signal.aborted === false) detail = result.mirror;
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		}
	};

	const submitSync = async (targets: SyncTarget[], syncReason: string): Promise<void> => {
		if (targets.length === 0 || targets.length > 128 || busy) return;
		const finalReason =
			syncReason.trim() === ''
				? 'Manual metadata sync from dashboard'
				: syncReason.trim();
		const signature = JSON.stringify({ targets, finalReason });
		if (signature !== lastSignature) {
			lastSignature = signature;
			requestKey = crypto.randomUUID();
		}
		busy = true;
		try {
			const result = await triggerSync(
				csrf,
				{
					targets,
					reason: finalReason,
					idempotencyKey: requestKey
				},
				controller.signal
			);
			if (controller.signal.aborted === false) {
				pendingTargets = null;
				lastSignature = '';
				ontaskcreated(result.job);
				await loadMirrors();
			}
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		} finally {
			busy = false;
		}
	};

	const toggleSelection = (key: string): void => {
		selected = selected.includes(key)
			? selected.filter((value) => value !== key)
			: [...selected, key];
	};

	const badgeTone = (mirror: Mirror): 'ok' | 'warn' | 'danger' | 'neutral' => {
		if (mirror.configured === false) return 'neutral';
		if (mirror.health?.ready === true) return 'ok';
		if (mirror.health?.alertState === 'warn') return 'warn';
		return 'danger';
	};

	onMount(() => {
		void loadMirrors();
		const timer = setInterval(() => {
			if (document.hidden === false) void loadMirrors();
		}, 5000);
		return () => {
			clearInterval(timer);
			controller.abort();
		};
	});

	$effect(() => {
		if (initialTarget !== '') {
			const [repository, suite] = initialTarget.split('/');
			if (repository !== undefined && suite !== undefined && repository !== '' && suite !== '')
				void showDetail(repository, suite);
		}
	});
</script>

<p class="page-description">
	Synchronizing a suite refreshes and verifies upstream metadata indexes. Individual package
	files are captured into local NVMe and S3 on demand when requested by clients. Observed
	{formatTimestamp(sampledAt)}.
</p>

<div class="toolbar spaced-panel">
	<label class="checkbox-item">
		<input type="checkbox" bind:checked={configuredOnly} />
		<span>Configured only</span>
	</label>

	<label class="field-inline">
		<span>Search</span>
		<input
			class="input"
			type="search"
			bind:value={search}
			placeholder="debian/trixie..."
		/>
	</label>

	<label class="field-inline">
		<span>Ecosystem</span>
		<select class="input" bind:value={ecosystem}>
			<option value="all">All</option>
			<option value="apt">APT</option>
			<option value="pacman">Pacman</option>
			<option value="rpm">RPM</option>
		</select>
	</label>

	<label class="field-inline">
		<span>Status</span>
		<select class="input" bind:value={status}>
			<option value="all">All</option>
			<option value="ready">Ready</option>
			<option value="configured_not_ready">Recovering or error</option>
			<option value="candidate_unconfigured">Unconfigured candidates</option>
		</select>
	</label>

	<button class="button" type="button" onclick={loadMirrors}>
		Refresh
	</button>

	{#if canSync}
		<button
			class="button is-primary"
			type="button"
			disabled={selected.length === 0 || selected.length > 128 || busy}
			onclick={() => {
				pendingTargets = mirrors
					.filter((mirror) =>
						selected.includes(`${mirror.repository}/${mirror.suite}`)
					)
					.map(({ repository, suite }) => ({ repository, suite }));
			}}
		>
			Sync selected ({selected.length})
		</button>
	{/if}
</div>

{#if loading}
	<p role="status">Loading mirror profiles...</p>
{/if}

{#each ['apt', 'pacman', 'rpm'] as group (group)}
	{@const groupRows = visibleMirrors.filter((mirror) => mirror.ecosystem === group)}
	{#if groupRows.length > 0}
		<section class="card table-panel spaced-panel">
			<div class="table-toolbar">
				<h2>
					{group === 'apt' ? 'APT' : group === 'rpm' ? 'RPM' : 'Pacman'}
					({groupRows.length})
				</h2>
			</div>

			<div class="table-wrap">
				<table>
					<thead>
						<tr>
							<th>Select</th>
							<th>Mirror</th>
							<th>Status & phase</th>
							<th>Origin</th>
							<th>Generation</th>
							<th>Lease remaining</th>
							<th>Last observed</th>
							<th>Actions</th>
						</tr>
					</thead>
					<tbody>
						{#each groupRows as mirror (`${mirror.repository}/${mirror.suite}`)}
							{@const key = `${mirror.repository}/${mirror.suite}`}
							{@const activeJob = jobs.find((job) =>
								job.targets.some(
									(target) =>
										target.repository === mirror.repository &&
										target.suite === mirror.suite &&
										(target.state === 'queued' || target.state === 'running')
								)
							)}
							{@const activeTarget = activeJob?.targets.find(
								(target) =>
									target.repository === mirror.repository &&
									target.suite === mirror.suite
							)}
							{@const pass = suiteJobs.find(
								(state) =>
									state.repository === mirror.repository &&
									state.suite === mirror.suite
							)}
							<tr>
								<td>
									<input
										type="checkbox"
										aria-label={`Select ${key}`}
										disabled={canSync === false || mirror.configured === false}
										checked={selected.includes(key)}
										onchange={() => toggleSelection(key)}
									/>
								</td>

								<td>
									<button
										class="text-button"
										type="button"
										onclick={() => showDetail(mirror.repository, mirror.suite)}
									>
										{key}
									</button>
									<div class="muted">{mirror.architectures.join(', ')}</div>
								</td>

								<td>
									<StatusBadge
										tone={badgeTone(mirror)}
										label={mirror.configured === false
											? 'Candidate (unconfigured)'
											: mirror.health?.ready === true
												? 'Ready'
												: 'Configured (recovering)'}
									/>
									{#if mirror.health?.lastError !== null && mirror.health?.lastError !== undefined}
										<div class="muted">{mirror.health.lastError}</div>
									{/if}
									{#if activeJob !== undefined && activeTarget !== undefined}
										<div>
											<button
												class="text-button"
												type="button"
												onclick={() => {
													jobId = activeJob.id;
												}}
											>
												{activeTarget.phase} ({activeTarget.disposition})
											</button>
										</div>
									{:else if pass !== undefined && pass.phase !== 'idle'}
										<div class="muted">
											Pass: {pass.phase}
											{#if pass.totalArtifacts !== null}
												({pass.completedArtifacts ?? 0}/{pass.totalArtifacts})
											{/if}
										</div>
									{/if}
								</td>

								<td class="break-word">{mirror.origin}</td>

								<td class="mono">
									{mirror.health?.generationId !== null &&
									mirror.health?.generationId !== undefined
										? `${mirror.health.generationId.slice(0, 14)}...`
										: 'Unavailable'}
								</td>

								<td>
									{formatDuration(mirror.health?.leaseRemainingSeconds ?? null)}
								</td>

								<td>
									{formatDuration(mirror.health?.observedAgeSeconds ?? null)}
								</td>

								<td>
									{#if canSync && mirror.configured}
										<div class="toolbar">
											<button
												class="button"
												type="button"
												disabled={busy}
												onclick={() =>
													submitSync(
														[
															{
																repository: mirror.repository,
																suite: mirror.suite
															}
														],
														`Sync suite ${mirror.repository}/${mirror.suite}`
													)}
											>
												Sync suite
											</button>
											<button
												class="button"
												type="button"
												disabled={busy}
												onclick={() =>
													submitSync(
														mirrors
															.filter(
																(item) =>
																	item.repository ===
																		mirror.repository &&
																	item.configured
															)
															.map(({ repository, suite }) => ({
																repository,
																suite
															})),
														`Sync repository ${mirror.repository}`
													)}
											>
												Sync repository
											</button>
										</div>
									{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</section>
	{/if}
{/each}

{#if loading === false && visibleMirrors.length === 0}
	<p class="empty-state">No mirrors match these filters.</p>
{/if}

{#if detail !== null}
	{@const detailPass = suiteJobs.find(
		(state) =>
			state.repository === detail?.repository && state.suite === detail?.suite
	)}
	<Modal
		title={`${detail.repository}/${detail.suite}`}
		onclose={() => {
			detail = null;
		}}
	>
		<EvidenceTable
			values={detail}
			caption="Origin, trust policy, lease, and publication state"
		/>
		{#if detailPass !== undefined}
			<EvidenceTable
				values={detailPass}
				caption="Live synchronizer slot state"
			/>
		{/if}
	</Modal>
{/if}

{#if pendingTargets !== null}
	<Modal
		title="Sync selected suites"
		onclose={() => {
			pendingTargets = null;
		}}
	>
		<p>
			Scheduling metadata refresh for <strong>{pendingTargets.length}</strong> configured
			suites. Progress will appear in the top-right Tasks bar.
		</p>
		<form
			onsubmit={(event) => {
				event.preventDefault();
				if (pendingTargets !== null) void submitSync(pendingTargets, reason);
			}}
		>
			<label class="field">
				<span>Operator reason</span>
				<textarea bind:value={reason} required maxlength="1024"></textarea>
			</label>
			<button class="button is-primary" disabled={busy} type="submit">
				Start sync
			</button>
		</form>
	</Modal>
{/if}

{#if jobId !== null}
	<JobDetail
		id={jobId}
		{csrf}
		canCancel={canSync}
		onclose={() => {
			jobId = null;
		}}
		{onerror}
	/>
{/if}
