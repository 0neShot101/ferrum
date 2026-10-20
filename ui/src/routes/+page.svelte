<script lang="ts">
	import { onMount } from 'svelte';
	import { asset } from '$app/paths';
	import AccountUsersPage from '$lib/components/AccountUsersPage.svelte';
	import ActivityPage from '$lib/components/ActivityPage.svelte';
	import AdminShell from '$lib/components/AdminShell.svelte';
	import DocsPage from '$lib/components/DocsPage.svelte';
	import JobDetail from '$lib/components/JobDetail.svelte';
	import MirrorsPage from '$lib/components/MirrorsPage.svelte';
	import OverviewPage from '$lib/components/OverviewPage.svelte';
	import PackagesPage from '$lib/components/PackagesPage.svelte';
	import SettingsPage from '$lib/components/SettingsPage.svelte';
	import StoragePage from '$lib/components/StoragePage.svelte';
	import {
		AdminApiError,
		fetchMirrors,
		fetchSession,
		loginAdmin,
		logoutAdmin,
		submitInitialSetup
	} from '$lib/services/api';
	import type {
		AdminUser,
		DashboardTab,
		Mirror,
		OperationJob,
		SessionState
	} from '$lib/types/admin';

	const titles: Record<DashboardTab, string> = {
		overview: 'Overview',
		mirrors: 'Mirrors',
		packages: 'Packages',
		storage: 'Cache & Storage',
		activity: 'Activity',
		settings: 'Settings',
		account: 'Account',
		users: 'Users',
		docs: 'Documentation'
	};

	let user = $state<AdminUser | null>(null);
	let csrf = $state<string | null>(null);
	let loading = $state(true);
	let setupRequired = $state(false);
	let busy = $state(false);
	let activeTab = $state<DashboardTab>('overview');
	let mirrorTarget = $state('');
	let mirrors = $state<Mirror[]>([]);
	let taskPulse = $state(0);
	let trayJobId = $state<string | null>(null);
	let username = $state('admin');
	let displayName = $state('Administrator');
	let password = $state('');
	let confirmPassword = $state('');
	let bootstrapToken = $state('');
	let error = $state('');
	let message = $state('');
	let controller = new AbortController();
	let generation = 0;
	let sessionLoading = false;

	const clearSessionState = (): void => {
		controller.abort();
		controller = new AbortController();
		generation += 1;
		user = null;
		csrf = null;
		mirrors = [];
		mirrorTarget = '';
		trayJobId = null;
		password = '';
		confirmPassword = '';
		bootstrapToken = '';
	};

	const reauthenticate = (): void => {
		clearSessionState();
		busy = false;
		loading = false;
		setupRequired = false;
		message = 'Session updated or revoked. Sign in again to continue.';
	};

	const isTabAllowed = (tab: DashboardTab): boolean => {
		if (user === null) return false;
		if (tab === 'account' || tab === 'docs') return true;
		if (tab === 'users') return user.permissions.includes('manage_users');
		if (tab === 'packages') return user.permissions.includes('view_inventory');
		return user.permissions.includes('view_status');
	};

	const selectTab = (tab: DashboardTab): void => {
		activeTab = isTabAllowed(tab) ? tab : 'account';
		error = '';
		if (typeof window !== 'undefined' && location.hash !== `#${activeTab}`)
			location.hash = activeTab;
	};

	const restoreFromHash = (): void => {
		const [page, repository, suite] = location.hash.slice(1).split('/');
		const fallbackTab =
			user?.permissions.includes('view_status') === true ? 'overview' : 'account';
		const candidateTab = Object.hasOwn(titles, page)
			? (page as DashboardTab)
			: fallbackTab;
		activeTab = isTabAllowed(candidateTab) ? candidateTab : 'account';
		try {
			mirrorTarget =
				candidateTab === 'mirrors' &&
				repository !== undefined &&
				suite !== undefined &&
				repository !== '' &&
				suite !== ''
					? `${decodeURIComponent(repository)}/${decodeURIComponent(suite)}`
					: '';
		} catch {
			mirrorTarget = '';
			error = 'Invalid mirror deep link.';
		}
	};

	const acceptSession = (state: SessionState): void => {
		if (user !== null && (state.user === null || user.id !== state.user.id)) {
			reauthenticate();
			return;
		}
		user = state.user;
		csrf = state.csrfToken;
		setupRequired = state.setupRequired;
		if (user !== null && isTabAllowed(activeTab) === false) activeTab = 'account';
	};

	const refreshSession = async (): Promise<void> => {
		if (sessionLoading) return;
		sessionLoading = true;
		const signal = controller.signal;
		const currentGen = generation;
		try {
			const result = await fetchSession(signal);
			if (signal.aborted === false && currentGen === generation)
				acceptSession(result);
		} catch (caught) {
			if (signal.aborted === false && currentGen === generation) {
				error =
					caught instanceof Error ? caught.message : 'Session check failed.';
				if (
					caught instanceof AdminApiError &&
					(caught.status === 401 || caught.status === 503)
				)
					reauthenticate();
			}
		} finally {
			sessionLoading = false;
		}
	};

	const handleError = async (caught: unknown): Promise<void> => {
		if (caught instanceof DOMException && caught.name === 'AbortError') return;
		if (caught instanceof AdminApiError && caught.status === 401 && user !== null) {
			reauthenticate();
			return;
		}
		error =
			caught instanceof Error ? caught.message : 'Unexpected request failure.';
		if (caught instanceof AdminApiError && caught.status === 403 && user !== null)
			await refreshSession();
	};

	const loadNavigationMirrors = async (): Promise<void> => {
		const signal = controller.signal;
		const currentGen = generation;
		if (user?.permissions.includes('view_status') !== true) return;
		try {
			const result = await fetchMirrors(signal);
			if (signal.aborted === false && currentGen === generation)
				mirrors = result.mirrors;
		} catch (caught) {
			if (signal.aborted === false && currentGen === generation)
				await handleError(caught);
		}
	};

	const authenticate = async (
		passwordValue: string,
		tokenValue: string
	): Promise<void> => {
		if (busy) return;
		if (setupRequired && passwordValue !== confirmPassword) {
			error = 'Password confirmation does not match.';
			return;
		}
		const passwordBytes = new TextEncoder().encode(passwordValue).length;
		if (setupRequired && (passwordBytes < 12 || passwordBytes > 1024)) {
			error = 'Passwords require 12 to 1,024 UTF-8 bytes.';
			return;
		}
		busy = true;
		error = '';
		message = '';
		clearSessionState();
		const signal = controller.signal;
		try {
			const state = setupRequired
				? await submitInitialSetup(
						username,
						displayName,
						passwordValue,
						tokenValue,
						signal
					)
				: await loginAdmin(username, passwordValue, signal);
			if (signal.aborted === false) {
				loading = true;
				acceptSession(state);
				restoreFromHash();
				await loadNavigationMirrors();
			}
		} catch (caught) {
			if (signal.aborted === false) await handleError(caught);
		} finally {
			if (signal.aborted === false) {
				busy = false;
				loading = false;
			}
		}
	};

	const handleAuthSubmit = async (event: SubmitEvent): Promise<void> => {
		event.preventDefault();
		await authenticate(password, bootstrapToken);
	};

	const handleLogout = async (): Promise<void> => {
		if (busy) return;
		const activeCsrf = csrf;
		clearSessionState();
		setupRequired = false;
		busy = true;
		try {
			await logoutAdmin(activeCsrf, controller.signal);
			message = 'Signed out.';
		} catch (caught) {
			await handleError(caught);
		} finally {
			busy = false;
		}
	};

	const handleTaskCreated = (job: OperationJob): void => {
		void job;
		taskPulse += 1;
	};

	const inspectMirror = (repository: string, suite: string): void => {
		mirrorTarget = `${repository}/${suite}`;
		selectTab('mirrors');
	};

	onMount(() => {
		const initialize = async (): Promise<void> => {
			await refreshSession();
			if (user !== null) {
				restoreFromHash();
				await loadNavigationMirrors();
			}
			loading = false;
		};
		void initialize();

		const handleHashChange = (): void => {
			try {
				restoreFromHash();
			} catch {
				error = 'Invalid mirror deep link.';
			}
		};

		const handleVisibility = (): void => {
			if (document.hidden === false && user !== null) void refreshSession();
		};

		window.addEventListener('hashchange', handleHashChange);
		document.addEventListener('visibilitychange', handleVisibility);

		const timer = setInterval(() => {
			if (document.hidden === false && user !== null) void refreshSession();
		}, 15000);

		return () => {
			controller.abort();
			generation += 1;
			clearInterval(timer);
			window.removeEventListener('hashchange', handleHashChange);
			document.removeEventListener('visibilitychange', handleVisibility);
		};
	});
</script>

<svelte:head>
	<title>
		{user !== null
			? titles[activeTab]
			: setupRequired
				? 'Create administrator'
				: 'Sign in'} · Ferrum
	</title>
	<meta name="description" content="Ferrum gateway administration" />
</svelte:head>

{#if loading || user === null}
	<main class="auth-page">
		<section class="auth-card">
			<div class="auth-brand">
				<img src={asset('/ferrum.png')} alt="" width="32" height="32" />
				<h1>Ferrum</h1>
			</div>

			{#if loading}
				<p role="status">Loading session...</p>
			{:else}
				<h2>{setupRequired ? 'Create the first administrator' : 'Sign in'}</h2>

				{#if error !== ''}
					<p class="notice error" role="alert">{error}</p>
				{/if}

				{#if message !== ''}
					<p class="notice" role="status">{message}</p>
				{/if}

				<form onsubmit={handleAuthSubmit}>
					{#if setupRequired}
						<p class="muted">
							Retrieve the protected one-time bootstrap token locally. Never place it in a
							URL.
						</p>
						<label class="field">
							<span>Bootstrap token</span>
							<input
								class="input"
								type="password"
								bind:value={bootstrapToken}
								required
								autocomplete="off"
							/>
						</label>
					{/if}

					<label class="field">
						<span>Username</span>
						<input
							class="input"
							bind:value={username}
							required
							maxlength="64"
							autocomplete="username"
						/>
					</label>

					{#if setupRequired}
						<label class="field">
							<span>Display name</span>
							<input
								class="input"
								bind:value={displayName}
								required
								maxlength="128"
							/>
						</label>
					{/if}

					<label class="field">
						<span>Password</span>
						<input
							class="input"
							type="password"
							bind:value={password}
							required
							maxlength="1024"
							autocomplete={setupRequired ? 'new-password' : 'current-password'}
						/>
					</label>

					{#if setupRequired}
						<label class="field">
							<span>Confirm password</span>
							<input
								class="input"
								type="password"
								bind:value={confirmPassword}
								required
								maxlength="1024"
								autocomplete="new-password"
							/>
						</label>
					{/if}

					<button
						class="button is-primary auth-submit"
						disabled={busy}
						type="submit"
					>
						{setupRequired ? 'Create administrator' : 'Sign in'}
					</button>
				</form>
			{/if}
		</section>
	</main>
{:else}
	<AdminShell
		{activeTab}
		{user}
		{busy}
		{csrf}
		{taskPulse}
		{mirrors}
		onselect={selectTab}
		onlogout={handleLogout}
		onselectjob={(selectedId) => {
			trayJobId = selectedId;
		}}
		onmirror={inspectMirror}
		onerror={handleError}
	>
		{#if error !== ''}
			<div class="notice error" role="alert">
				<span>{error}</span>
				<button
					type="button"
					class="button"
					onclick={() => {
						error = '';
					}}
				>
					Dismiss
				</button>
			</div>
		{/if}

		{#if message !== ''}
			<p class="notice" role="status">{message}</p>
		{/if}

		{#key `${user.id}-${user.permissions.join(',')}`}
			{#if isTabAllowed('overview')}
				<div hidden={activeTab !== 'overview'}>
					<OverviewPage
						active={activeTab === 'overview'}
						{csrf}
						canSync={user.permissions.includes('trigger_sync')}
						onnavigate={selectTab}
						oninspectmirror={inspectMirror}
						onerror={handleError}
					/>
				</div>
			{/if}

			{#key activeTab}
				{#if activeTab === 'mirrors' && isTabAllowed('mirrors')}
					<MirrorsPage
						{csrf}
						canSync={user.permissions.includes('trigger_sync')}
						initialTarget={mirrorTarget}
						ontaskcreated={handleTaskCreated}
						onerror={handleError}
					/>
				{:else if activeTab === 'packages' && isTabAllowed('packages')}
					<PackagesPage onerror={handleError} />
				{:else if activeTab === 'storage' && isTabAllowed('storage')}
					<StoragePage
						{csrf}
						canManage={user.permissions.includes('manage_cache')}
						ontaskcreated={handleTaskCreated}
						onerror={handleError}
					/>
				{:else if activeTab === 'activity' && isTabAllowed('activity')}
					<ActivityPage {csrf} {user} onerror={handleError} />
				{:else if activeTab === 'settings' && isTabAllowed('settings')}
					<SettingsPage
						{csrf}
						canManage={user.permissions.includes('manage_config')}
						onerror={handleError}
					/>
				{:else if activeTab === 'docs'}
					<DocsPage />
				{:else if activeTab === 'account' || (activeTab === 'users' && isTabAllowed('users'))}
					<AccountUsersPage
						{csrf}
						{user}
						mode={activeTab}
						onerror={handleError}
						onreauth={reauthenticate}
					/>
				{:else if activeTab !== 'overview'}
					<p class="notice" role="alert">
						Insufficient permissions for this page.
					</p>
				{/if}
			{/key}
		{/key}

		{#if trayJobId !== null}
			<JobDetail
				id={trayJobId}
				{csrf}
				canCancel={user.permissions.includes('trigger_sync')}
				onclose={() => {
					trayJobId = null;
				}}
				onerror={handleError}
			/>
		{/if}
	</AdminShell>
{/if}
