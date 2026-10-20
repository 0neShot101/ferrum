<script lang="ts">
	import { onMount } from 'svelte';
	import {
		acknowledgeAlert,
		fetchActivity,
		fetchAlerts,
		fetchJobs
	} from '$lib/services/api';
	import type {
		ActivityPageProps,
		ActivityPayload,
		Alert,
		AlertsPayload,
		JobsPage
	} from '$lib/types/admin';
	import { formatTimestamp } from '$lib/utils/format';
	import JobDetail from './JobDetail.svelte';
	import Modal from './Modal.svelte';
	import StatusBadge from './StatusBadge.svelte';

	let { csrf, user, onerror }: ActivityPageProps = $props();

	let jobs = $state<JobsPage | null>(null);
	let alerts = $state<AlertsPayload | null>(null);
	let activity = $state<ActivityPayload | null>(null);
	let jobState = $state('');
	let jobKind = $state('');
	let auditSearch = $state('');
	let selectedJobId = $state<string | null>(null);
	let selectedAlert = $state<Alert | null>(null);
	let note = $state('');
	let busy = $state(false);
	let loading = $state(false);
	let failed = $state(false);
	let currentCursor: string | undefined = undefined;
	let applied = { state: '', kind: '' };
	const controller = new AbortController();

	const filteredAuditEvents = $derived(
		(activity?.auditEvents ?? []).filter((event) =>
			`${event.actor} ${event.action} ${event.target} ${event.reason}`
				.toLowerCase()
				.includes(auditSearch.trim().toLowerCase())
		)
	);

	const loadActivity = async (useNextCursor = false, resetCursor = false): Promise<void> => {
		if (loading) return;
		if (resetCursor) {
			currentCursor = undefined;
			applied = { state: jobState, kind: jobKind };
		}
		if (useNextCursor) currentCursor = jobs?.nextCursor ?? undefined;
		loading = true;
		failed = false;
		try {
			const jobsResult = await fetchJobs(
				{
					state: applied.state === '' ? undefined : applied.state,
					kind: applied.kind === '' ? undefined : applied.kind,
					cursor: currentCursor
				},
				controller.signal
			);
			if (controller.signal.aborted === false) jobs = jobsResult;

			const alertsResult = await fetchAlerts(controller.signal);
			if (controller.signal.aborted === false) alerts = alertsResult;

			if (user.permissions.includes('view_audit')) {
				const eventsResult = await fetchActivity(controller.signal);
				if (controller.signal.aborted === false) activity = eventsResult;
			}
		} catch (error) {
			if (controller.signal.aborted === false) {
				failed = true;
				onerror(error);
			}
		} finally {
			loading = false;
		}
	};

	const submitAcknowledgment = async (): Promise<void> => {
		if (selectedAlert === null || busy) return;
		busy = true;
		try {
			await acknowledgeAlert(
				csrf,
				selectedAlert.conditionId,
				note,
				controller.signal
			);
			if (controller.signal.aborted === false) {
				selectedAlert = null;
				note = '';
				await loadActivity(false, false);
			}
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		} finally {
			busy = false;
		}
	};

	const badgeTone = (state: string): 'ok' | 'warn' | 'danger' | 'neutral' => {
		if (state === 'succeeded' || state === 'published' || state === 'renewed') return 'ok';
		if (state === 'running' || state === 'queued' || state === 'partial') return 'warn';
		if (state === 'failed' || state === 'rejected' || state === 'interrupted') return 'danger';
		return 'neutral';
	};

	onMount(() => {
		void loadActivity(false, false);
		const timer = setInterval(() => {
			if (document.hidden === false) void loadActivity(false, false);
		}, 10000);
		return () => {
			clearInterval(timer);
			controller.abort();
		};
	});
</script>

{#if failed}
	<p class="notice error" role="status">
		Activity refresh failed. Use Apply / refresh to retry.
	</p>
{/if}

<section class="card table-panel spaced-panel">
	<div class="table-toolbar">
		<h2>Operation jobs</h2>
		<div class="toolbar">
			<label class="field-inline">
				<span>Kind</span>
				<select class="input" bind:value={jobKind}>
					<option value="">All</option>
					<option value="sync">Sync</option>
					<option value="cache_clear">Local cache</option>
				</select>
			</label>

			<label class="field-inline">
				<span>State</span>
				<select class="input" bind:value={jobState}>
					<option value="">All</option>
					{#each ['queued', 'running', 'succeeded', 'partial', 'failed', 'cancelled', 'interrupted'] as value (value)}
						<option value={value}>{value}</option>
					{/each}
				</select>
			</label>

			<button
				class="button"
				type="button"
				disabled={loading}
				onclick={() => loadActivity(false, true)}
			>
				Apply / refresh
			</button>
		</div>
	</div>

	<div class="table-wrap">
		<table>
			<thead>
				<tr>
					<th>Operation</th>
					<th>State</th>
					<th>Actor</th>
					<th>Created</th>
					<th>Reason</th>
				</tr>
			</thead>
			<tbody>
				{#each jobs?.jobs ?? [] as job (job.id)}
					<tr>
						<td>
							<button
								class="text-button"
								type="button"
								onclick={() => {
									selectedJobId = job.id;
								}}
							>
								{job.kind} · {job.id.slice(0, 12)}...
							</button>
						</td>
						<td>
							<StatusBadge tone={badgeTone(job.state)} label={job.state} />
						</td>
						<td>{job.actor}</td>
						<td>{formatTimestamp(job.createdAt)}</td>
						<td class="break-word">{job.reason}</td>
					</tr>
				{:else}
					<tr>
						<td colspan="5" class="empty-state">
							{jobs !== null ? 'No matching operation jobs.' : 'Loading jobs...'}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>

	<div class="table-footer">
		<span>Click any operation ID to inspect per-suite phase and artifact progress.</span>
		<button
			class="button"
			type="button"
			disabled={loading || jobs?.hasMore !== true}
			onclick={() => loadActivity(true, false)}
		>
			Next page
		</button>
	</div>
</section>

<section class="card spaced-panel">
	<h2>Active & resolved alerts</h2>
	<p class="muted">
		Acknowledging an alert records an operator note in the audit log without bypassing
		enforcement.
	</p>

	{#each alerts?.alerts ?? [] as alert (alert.conditionId)}
		{@const relatedNotes = (alerts?.acknowledgments ?? []).filter(
			(item) => item.conditionId === alert.conditionId
		)}
		<article class="alert-row">
			<div>
				<StatusBadge
					tone={alert.active === false
						? 'ok'
						: alert.severity === 'critical'
							? 'danger'
							: 'warn'}
					label={`${alert.severity} · ${alert.active ? 'Active' : 'Resolved'}`}
				/>
				<strong> {alert.conditionId}</strong>
				<p>{alert.message}</p>
				<small class="muted">Changed {formatTimestamp(alert.changedAt)}</small>
				{#each relatedNotes as record (`${record.actor}-${record.createdAt}`)}
					<p class="muted">
						Note by {record.actor}: {record.note} ({formatTimestamp(record.createdAt)})
					</p>
				{/each}
			</div>

			{#if user.permissions.includes('acknowledge_alerts')}
				<button
					class="button"
					type="button"
					onclick={() => {
						selectedAlert = alert;
					}}
				>
					Acknowledge
				</button>
			{/if}
		</article>
	{:else}
		<p class="muted">No active or retained alert conditions.</p>
	{/each}
</section>

{#if user.permissions.includes('view_audit')}
	<section class="card table-panel">
		<div class="table-toolbar">
			<h2>Local audit log</h2>
			<label class="field-inline">
				<span>Filter</span>
				<input
					class="input"
					type="search"
					bind:value={auditSearch}
					placeholder="Search actor, action, target..."
				/>
			</label>
		</div>

		<div class="table-wrap">
			<table>
				<thead>
					<tr>
						<th>Timestamp</th>
						<th>Actor</th>
						<th>Action & target</th>
						<th>Outcome & reason</th>
					</tr>
				</thead>
				<tbody>
					{#each filteredAuditEvents as event (event.id)}
						<tr>
							<td>{formatTimestamp(event.createdAt)}</td>
							<td>{event.actor}</td>
							<td class="break-word">
								<strong>{event.action}</strong>
								<div class="muted">{event.target}</div>
							</td>
							<td class="break-word">
								<strong>{event.outcome}</strong>
								{#if event.reason !== ''}
									<div class="muted">{event.reason}</div>
								{/if}
							</td>
						</tr>
					{:else}
						<tr>
							<td colspan="4" class="empty-state">No matching audit events.</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	</section>
{/if}

{#if selectedAlert !== null}
	<Modal
		title="Acknowledge alert"
		onclose={() => {
			selectedAlert = null;
		}}
	>
		<p>{selectedAlert.message}</p>
		<form
			onsubmit={(event) => {
				event.preventDefault();
				void submitAcknowledgment();
			}}
		>
			<label class="field">
				<span>Operator note</span>
				<textarea bind:value={note} required maxlength="1024"></textarea>
			</label>
			<button class="button is-primary" disabled={busy} type="submit">
				Record acknowledgment
			</button>
		</form>
	</Modal>
{/if}

{#if selectedJobId !== null}
	<JobDetail
		id={selectedJobId}
		{csrf}
		canCancel={user.permissions.includes('trigger_sync')}
		onclose={() => {
			selectedJobId = null;
		}}
		{onerror}
	/>
{/if}
