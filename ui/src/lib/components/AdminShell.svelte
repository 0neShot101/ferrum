<script lang="ts">
	import { asset } from '$app/paths';
	import { onMount, tick } from 'svelte';
	import type { DashboardTab } from '$lib/types/admin';
	import type {
		AdminShellProps,
		NavigationEntry,
		NavigationIcon,
		NavigationTheme
	} from '$lib/types/navigation';
	import TaskTray from './TaskTray.svelte';

	let {
		activeTab,
		user,
		busy,
		csrf,
		taskPulse,
		onselect,
		onlogout,
		onselectjob,
		onerror,
		children,
		mirrors = [],
		onmirror
	}: AdminShellProps = $props();

	const instanceId = $props.id();
	const sidebarPreference = 'ferrum.sidebar-collapsed';
	const themePreference = 'ferrum.theme';
	const sections = ['Main', 'Settings'] as const;

	const entries: NavigationEntry[] = [
		{ tab: 'overview', label: 'Overview', icon: 'traffic', section: 'Main', permission: 'view_status' },
		{ tab: 'mirrors', label: 'Mirrors', icon: 'mirrors', section: 'Main', permission: 'view_status' },
		{ tab: 'packages', label: 'Packages', icon: 'storage', section: 'Main', permission: 'view_inventory' },
		{ tab: 'storage', label: 'Cache & Storage', icon: 'storage', section: 'Main', permission: 'view_status' },
		{ tab: 'activity', label: 'Activity', icon: 'traffic', section: 'Main', permission: 'view_status' },
		{ tab: 'settings', label: 'Settings', icon: 'storage', section: 'Settings', permission: 'view_status' },
		{ tab: 'account', label: 'Account', icon: 'account', section: 'Settings' },
		{ tab: 'users', label: 'Users', icon: 'users', section: 'Settings', permission: 'manage_users' },
		{ tab: 'docs', label: 'Documentation', icon: 'docs', section: 'Settings' }
	];

	const pageTitles: Record<DashboardTab, string> = {
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

	const paths: Record<NavigationIcon, string> = {
		mirrors: 'M4 3h16v7H4z M4 14h16v7H4z M8 6.5h.01 M8 17.5h.01 M12 6.5h5 M12 17.5h5',
		storage: 'M20 6c0 2.2-16 2.2-16 0s16-2.2 16 0Z M4 6v12c0 3 16 3 16 0V6 M4 12c0 3 16 3 16 0',
		traffic: 'M3 3v18h18 M7 14l4-4 4 3 6-8 M17 5h4v4',
		account: 'M16 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z M4 21v-2a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v2',
		users: 'M15 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z M3 21v-2a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v2 M18 3a4 4 0 0 1 0 8 M21 14a6 6 0 0 1 2 5v2',
		search: 'M19 10a7 7 0 1 1-14 0 7 7 0 0 1 14 0Z M15 15l6 6',
		chevron: 'M14 6l-6 6 6 6',
		menu: 'M4 6h16 M4 12h16 M4 18h16',
		close: 'M6 6l12 12 M18 6 6 18',
		sun: 'M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z M12 2v2 M12 20v2 M2 12h2 M20 12h2 M5 5l1.5 1.5 M17.5 17.5 19 19 M5 19l1.5-1.5 M17.5 6.5 19 5',
		moon: 'M20.5 13A9 9 0 0 1 11 3.5 9 9 0 1 0 20.5 13Z',
		logout: 'M9 4H4v16h5 M14 8l4 4-4 4 M8 12h12',
		tasks: 'M12 6v6l4 2 M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z',
		docs: 'M4 4h11l5 5v11H4z M14 4v6h6 M8 13h8 M8 17h6'
	};

	let collapsed = $state(true);
	let mobile = $state(false);
	let drawerOpen = $state(false);
	let query = $state('');
	let theme = $state<NavigationTheme>('dark');
	let shortcut = $state('Ctrl K');
	let drawer = $state<HTMLDialogElement>();
	let menuButton = $state<HTMLButtonElement>();
	let desktopSearch = $state<HTMLInputElement>();
	let mobileSearch = $state<HTMLInputElement>();
	let pageHeading = $state<HTMLHeadingElement>();
	let explicitCollapsed: boolean | null = null;
	let returnDrawerFocus = true;

	const visibleEntries = $derived(
		entries.filter(
			(entry) =>
				(entry.permission === undefined || user.permissions.includes(entry.permission)) &&
				entry.label.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase())
		)
	);

	const title = $derived(pageTitles[activeTab]);

	const mirrorResults = $derived(
		query.trim() !== '' && user.permissions.includes('view_status')
			? mirrors
					.filter((mirror) =>
						`${mirror.repository}/${mirror.suite}`
							.toLowerCase()
							.includes(query.trim().toLowerCase())
					)
					.slice(0, 20)
			: []
	);

	const accountName = $derived(user.displayName === '' ? user.username : user.displayName);

	const readPreference = (key: string): string | null => {
		try {
			return window.localStorage.getItem(key);
		} catch {
			return null;
		}
	};

	const savePreference = (key: string, value: string): void => {
		try {
			window.localStorage.setItem(key, value);
		} catch {
			return;
		}
	};

	const setCollapsed = (value: boolean): void => {
		collapsed = value;
		explicitCollapsed = value;
		if (value === true) query = '';
		savePreference(sidebarPreference, String(value));
	};

	const toggleCollapsed = (): void => setCollapsed(collapsed === false);

	const toggleTheme = (): void => {
		theme = theme === 'dark' ? 'light' : 'dark';
		document.documentElement.dataset.theme = theme;
		savePreference(themePreference, theme);
	};

	const openDrawer = (): void => {
		if (drawer === undefined || drawer.open === true) return;
		returnDrawerFocus = true;
		drawer.showModal();
		drawerOpen = true;
	};

	const closeDrawer = (restoreFocus = true): void => {
		if (drawer === undefined || drawer.open === false) return;
		returnDrawerFocus = restoreFocus;
		drawer.close();
		drawerOpen = false;
		query = '';
	};

	const handleDrawerClose = (): void => {
		drawerOpen = false;
		if (returnDrawerFocus === true) menuButton?.focus();
	};

	const cancelDrawer = (event: Event): void => {
		event.preventDefault();
		closeDrawer();
	};

	const dismissBackdrop = (event: PointerEvent): void => {
		if (event.target !== drawer || drawer === undefined) return;
		const bounds = drawer.getBoundingClientRect();
		if (
			event.clientX < bounds.left ||
			event.clientX > bounds.right ||
			event.clientY < bounds.top ||
			event.clientY > bounds.bottom
		)
			closeDrawer();
	};

	const focusSearch = async (): Promise<void> => {
		if (mobile === true) openDrawer();
		else if (collapsed === true) setCollapsed(false);
		await tick();
		const input = mobile === true ? mobileSearch : desktopSearch;
		input?.focus();
		input?.select();
	};

	const selectPage = async (event: MouseEvent, tab: DashboardTab): Promise<void> => {
		if (
			event.button !== 0 ||
			event.ctrlKey ||
			event.metaKey ||
			event.shiftKey ||
			event.altKey
		)
			return;
		onselect(tab);
		query = '';
		closeDrawer(false);
		await tick();
		pageHeading?.focus({ preventScroll: true });
	};

	const handleMirrorSelect = (
		event: MouseEvent,
		repository: string,
		suite: string
	): void => {
		if (
			event.button !== 0 ||
			event.ctrlKey ||
			event.metaKey ||
			event.shiftKey ||
			event.altKey
		)
			return;
		onmirror?.(repository, suite);
		query = '';
		closeDrawer(false);
	};

	onMount(() => {
		shortcut = window.navigator.platform.startsWith('Mac') ? 'Cmd K' : 'Ctrl K';
		const narrow = window.matchMedia('(max-width: 1279px)');
		const phone = window.matchMedia('(max-width: 899px)');
		const storedCollapsed = readPreference(sidebarPreference);
		explicitCollapsed =
			storedCollapsed === 'true' ? true : storedCollapsed === 'false' ? false : null;
		collapsed = explicitCollapsed ?? narrow.matches;
		mobile = phone.matches;
		theme = readPreference(themePreference) === 'light' ? 'light' : 'dark';
		document.documentElement.dataset.theme = theme;

		const updateViewport = (): void => {
			mobile = phone.matches;
			if (explicitCollapsed === null) collapsed = narrow.matches;
			if (collapsed === true && mobile === false) query = '';
			if (mobile === false) closeDrawer(false);
		};

		const handleShortcut = (event: KeyboardEvent): void => {
			if ((event.ctrlKey || event.metaKey) === false || event.key.toLowerCase() !== 'k')
				return;
			event.preventDefault();
			void focusSearch();
		};

		narrow.addEventListener('change', updateViewport);
		phone.addEventListener('change', updateViewport);
		window.addEventListener('keydown', handleShortcut);
		return () => {
			narrow.removeEventListener('change', updateViewport);
			phone.removeEventListener('change', updateViewport);
			window.removeEventListener('keydown', handleShortcut);
			if (drawer?.open === true) drawer.close();
		};
	});
</script>

{#snippet icon(name: NavigationIcon)}
	<svg
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		stroke-width="1.75"
		stroke-linecap="round"
		stroke-linejoin="round"
		aria-hidden="true"
	>
		<path d={paths[name]} />
	</svg>
{/snippet}

{#snippet navigation(compact: boolean, inDrawer: boolean)}
	<div class="brand-header">
		<div class="brand" aria-label="Ferrum">
			<img src={asset('/ferrum.png')} width="26" height="26" alt="" />
			{#if compact === false}
				<span>Ferrum</span>
			{/if}
		</div>
		{#if inDrawer}
			<button
				class="icon-button drawer-close"
				type="button"
				onclick={() => closeDrawer()}
				aria-label="Close navigation"
				title="Close navigation"
			>
				{@render icon('close')}
			</button>
		{/if}
	</div>

	<div class="navigation-body">
		{#if compact}
			<button
				class="rail-search icon-button"
				type="button"
				onclick={focusSearch}
				aria-label="Search pages"
				title="Search pages (Ctrl/Cmd K)"
			>
				{@render icon('search')}
			</button>
		{:else}
			<div class="page-search">
				{@render icon('search')}
				<label
					class="visually-hidden"
					for={`${instanceId}-${inDrawer ? 'drawer' : 'desktop'}-search`}
				>
					Search pages
				</label>
				{#if inDrawer}
					<input
						id={`${instanceId}-drawer-search`}
						bind:this={mobileSearch}
						bind:value={query}
						type="search"
						placeholder="Search pages or mirrors"
						autocomplete="off"
					/>
				{:else}
					<input
						id={`${instanceId}-desktop-search`}
						bind:this={desktopSearch}
						bind:value={query}
						type="search"
						placeholder="Search pages or mirrors"
						autocomplete="off"
					/>
				{/if}
				<kbd class="shortcut">{shortcut}</kbd>
			</div>
		{/if}

		<nav aria-label="Main" class={['destinations', compact && 'compact']}>
			{#each sections as section}
				{@const sectionEntries = visibleEntries.filter((entry) => entry.section === section)}
				{#if sectionEntries.length > 0}
					<div class="navigation-group">
						{#if compact === false}
							<p class="section-label">{section}</p>
						{/if}
						{#each sectionEntries as entry (entry.tab)}
							<a
								href={`#${entry.tab}`}
								class="navigation-link"
								aria-current={activeTab === entry.tab ? 'page' : undefined}
								aria-label={entry.label}
								title={compact ? entry.label : undefined}
								onclick={(event) => selectPage(event, entry.tab)}
							>
								<span class="nav-icon">{@render icon(entry.icon)}</span>
								{#if compact === false}
									<span>{entry.label}</span>
								{/if}
							</a>
						{/each}
					</div>
				{/if}
			{/each}

			{#if visibleEntries.length === 0 && mirrorResults.length === 0}
				<p class="search-empty" role="status">No pages or mirrors found.</p>
			{/if}

			{#if compact === false && mirrorResults.length > 0}
				<p class="section-label">Mirrors</p>
				{#each mirrorResults as mirror (`${mirror.repository}/${mirror.suite}`)}
					<a
						class="navigation-link"
						href={`#mirrors/${encodeURIComponent(mirror.repository)}/${encodeURIComponent(mirror.suite)}`}
						onclick={(event) => handleMirrorSelect(event, mirror.repository, mirror.suite)}
					>
						<span>
							{mirror.repository}/{mirror.suite}
							<small>{mirror.configured ? '' : ' · Candidate'}</small>
						</span>
					</a>
				{/each}
			{/if}
		</nav>
	</div>

	<footer class={['sidebar-footer', compact && 'compact']}>
		<button
			class="theme-control"
			type="button"
			role="switch"
			aria-checked={theme === 'dark'}
			aria-label="Dark mode"
			title={compact ? 'Dark mode' : undefined}
			onclick={toggleTheme}
		>
			<span class="nav-icon">{@render icon(theme === 'dark' ? 'moon' : 'sun')}</span>
			{#if compact === false}
				<span class="theme-label">Dark mode</span>
				<span class="switch-track" aria-hidden="true"><span></span></span>
			{/if}
		</button>

		<div class="account-row">
			{#if compact === false}
				<span class="nav-icon">{@render icon('account')}</span>
				<span class="account-name" title={accountName}>{accountName}</span>
			{/if}
			<button
				class="icon-button signout"
				type="button"
				disabled={busy}
				onclick={onlogout}
				aria-label="Sign out"
				title="Sign out"
			>
				{@render icon('logout')}
			</button>
		</div>
	</footer>
{/snippet}

<div class={['admin-shell', collapsed && 'rail']}>
	<a class="skip-link" href="#main-content">Skip to content</a>

	<aside class="desktop-sidebar" aria-label="Workspace navigation">
		{@render navigation(collapsed, false)}
		<button
			class="collapse-tab"
			type="button"
			aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
			aria-expanded={collapsed === false}
			title={collapsed ? 'Expand navigation' : 'Collapse navigation'}
			onclick={toggleCollapsed}
		>
			<span class={['collapse-chevron', collapsed && 'reversed']}>
				{@render icon('chevron')}
			</span>
		</button>
	</aside>

	<div class="content-column">
		<div class="mobile-header">
			<button
				class="icon-button"
				type="button"
				bind:this={menuButton}
				onclick={openDrawer}
				aria-label="Open navigation"
				aria-expanded={drawerOpen}
				aria-controls={`${instanceId}-navigation-drawer`}
			>
				{@render icon('menu')}
			</button>
			<div class="brand">
				<img src={asset('/ferrum.png')} width="26" height="26" alt="" />
				<span>Ferrum</span>
			</div>
		</div>

		<header class="workspace-header">
			<h1 bind:this={pageHeading} tabindex="-1">{title}</h1>
			{#if user.permissions.includes('view_status')}
				<TaskTray
					{csrf}
					canCancel={user.permissions.includes('trigger_sync')}
					pulseSignal={taskPulse}
					{onselectjob}
					{onerror}
				/>
			{/if}
		</header>

		<main id="main-content" tabindex="-1" class="workspace">
			{@render children()}
		</main>
	</div>
</div>

<dialog
	id={`${instanceId}-navigation-drawer`}
	bind:this={drawer}
	class="navigation-drawer"
	aria-label="Navigation"
	oncancel={cancelDrawer}
	onclose={handleDrawerClose}
	onpointerdown={dismissBackdrop}
>
	<div class="drawer-content">
		{@render navigation(false, true)}
	</div>
</dialog>

<style>
	.admin-shell {
		--sidebar-width: 224px;
		display: grid;
		grid-template-columns: var(--sidebar-width) minmax(0, 1fr);
		min-height: 100dvh;
		background: var(--bg, #18181b);
		color: var(--fg, #fafafa);
		font-family: 'Segoe UI', sans-serif;
		font-size: 13px;
		font-variant-numeric: tabular-nums;
		transition: grid-template-columns 180ms ease;
	}

	.admin-shell.rail {
		--sidebar-width: 64px;
	}

	.desktop-sidebar {
		position: sticky;
		top: 0;
		display: flex;
		flex-direction: column;
		height: 100dvh;
		min-width: 0;
		background: var(--sidebar-bg, #111113);
		border-right: 1px solid var(--border, #343438);
		z-index: 10;
	}

	.brand-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		min-height: 48px;
		padding: 8px 12px;
	}

	.admin-shell.rail .desktop-sidebar .brand-header {
		justify-content: center;
		padding: 8px 0;
	}

	.brand {
		display: flex;
		align-items: center;
		gap: 10px;
		min-width: 0;
		color: var(--fg, #fafafa);
		font-size: 14px;
		font-weight: 600;
	}

	.brand img {
		display: block;
		flex: 0 0 auto;
		border-radius: 4px;
	}

	.brand span,
	.navigation-link span:not(.nav-icon),
	.account-name {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.navigation-body {
		display: flex;
		flex-direction: column;
		flex: 1 1 auto;
		gap: 12px;
		min-height: 0;
		padding: 6px 10px 10px;
		overflow-y: auto;
	}

	.page-search {
		display: grid;
		grid-template-columns: 16px minmax(0, 1fr) auto;
		align-items: center;
		gap: 8px;
		min-height: 36px;
		padding: 0 10px;
		background: var(--input-bg, #18181b);
		border: 1px solid var(--border, #343438);
		border-radius: 6px;
		color: var(--muted, #a1a1aa);
	}

	.page-search:focus-within {
		border-color: var(--focus, #d4d4d8);
		color: var(--fg, #fafafa);
	}

	.page-search input {
		width: 100%;
		min-width: 0;
		padding: 0;
		background: transparent;
		border: 0;
		color: var(--fg, #fafafa);
		font: inherit;
		outline: none;
	}

	.page-search input::placeholder {
		color: var(--muted, #a1a1aa);
	}

	.shortcut {
		padding: 2px 5px;
		border: 1px solid var(--border, #343438);
		border-radius: 4px;
		color: var(--muted, #a1a1aa);
		font: inherit;
		font-size: 11px;
		line-height: 1.2;
	}

	.rail-search {
		align-self: center;
		width: 40px;
		height: 36px;
	}

	.destinations {
		display: flex;
		flex-direction: column;
		gap: 14px;
	}

	.navigation-group {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.section-label {
		margin: 0;
		padding: 4px 10px;
		color: var(--muted, #a1a1aa);
		font-size: 11px;
		font-weight: 600;
		letter-spacing: 0.04em;
		text-transform: uppercase;
	}

	.navigation-link {
		position: relative;
		display: flex;
		align-items: center;
		gap: 10px;
		min-height: 36px;
		padding: 6px 10px;
		border-radius: 6px;
		color: var(--muted, #a1a1aa);
		font-weight: 500;
		text-decoration: none;
	}

	.destinations.compact .navigation-link {
		justify-content: center;
		width: 40px;
		margin: 0 auto;
		padding: 6px;
	}

	.navigation-link:hover,
	.theme-control:hover,
	.icon-button:hover,
	.collapse-tab:hover {
		background: var(--hover, #242427);
		color: var(--fg, #fafafa);
	}

	.navigation-link[aria-current='page'] {
		background: var(--surface-elevated, #27272a);
		color: var(--fg, #fafafa);
		font-weight: 600;
	}

	.navigation-link[aria-current='page']::before {
		content: '';
		position: absolute;
		left: 0;
		top: 7px;
		bottom: 7px;
		width: 2px;
		border-radius: 2px;
		background: var(--accent, #ff7518);
	}

	.nav-icon,
	.icon-button svg,
	.page-search :global(svg),
	.collapse-tab svg {
		display: inline-flex;
		flex: 0 0 16px;
		width: 16px;
		height: 16px;
	}

	.search-empty {
		margin: 0;
		padding: 8px 10px;
		color: var(--muted, #a1a1aa);
	}

	.sidebar-footer {
		display: flex;
		flex-direction: column;
		gap: 6px;
		padding: 10px;
		border-top: 1px solid var(--border, #343438);
	}

	.theme-control {
		display: grid;
		grid-template-columns: 16px minmax(0, 1fr) auto;
		align-items: center;
		gap: 10px;
		width: 100%;
		min-height: 36px;
		padding: 6px 10px;
		background: transparent;
		border: 0;
		border-radius: 6px;
		color: var(--muted, #a1a1aa);
		cursor: pointer;
		font: inherit;
		text-align: left;
	}

	.sidebar-footer.compact .theme-control {
		display: flex;
		justify-content: center;
		width: 40px;
		margin: 0 auto;
		padding: 6px;
	}

	.switch-track {
		display: inline-flex;
		align-items: center;
		width: 28px;
		height: 16px;
		padding: 2px;
		background: var(--surface, #1c1c1f);
		border: 1px solid var(--border, #343438);
		border-radius: 999px;
	}

	.switch-track span {
		width: 10px;
		height: 10px;
		border-radius: 50%;
		background: var(--muted, #a1a1aa);
		transition: transform 150ms ease, background-color 150ms ease;
	}

	.theme-control[aria-checked='true'] .switch-track span {
		transform: translateX(12px);
		background: var(--fg, #fafafa);
	}

	.account-row {
		display: grid;
		grid-template-columns: 16px minmax(0, 1fr) auto;
		align-items: center;
		gap: 10px;
		min-height: 36px;
		padding: 0 4px 0 10px;
		color: var(--fg, #fafafa);
	}

	.sidebar-footer.compact .account-row {
		display: flex;
		justify-content: center;
		padding: 0;
	}

	.icon-button {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 32px;
		height: 32px;
		padding: 0;
		background: transparent;
		border: 1px solid transparent;
		border-radius: 6px;
		color: var(--muted, #a1a1aa);
		cursor: pointer;
	}

	.icon-button:disabled {
		cursor: not-allowed;
		opacity: 0.45;
	}

	.collapse-tab {
		position: absolute;
		top: 14px;
		right: -11px;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 22px;
		height: 22px;
		padding: 0;
		background: var(--surface, #1c1c1f);
		border: 1px solid var(--border, #343438);
		border-radius: 999px;
		color: var(--muted, #a1a1aa);
		cursor: pointer;
	}

	.collapse-chevron.reversed {
		transform: rotate(180deg);
	}

	.content-column {
		display: flex;
		flex-direction: column;
		min-width: 0;
	}

	.mobile-header {
		display: none;
		align-items: center;
		gap: 10px;
		min-height: 48px;
		padding: 8px 16px;
		background: var(--sidebar-bg, #111113);
		border-bottom: 1px solid var(--border, #343438);
	}

	.workspace-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 16px;
		padding: 20px 24px 0;
	}

	.workspace-header h1 {
		margin: 0;
		color: var(--fg, #fafafa);
		font-size: 20px;
		font-weight: 600;
		line-height: 1.3;
		outline: none;
	}

	.workspace {
		flex: 1 1 auto;
		min-width: 0;
		padding: 16px 24px 32px;
		outline: none;
	}

	.navigation-drawer {
		width: min(256px, calc(100vw - 48px));
		max-width: none;
		height: 100dvh;
		max-height: none;
		margin: 0;
		padding: 0;
		background: var(--sidebar-bg, #111113);
		border: 0;
		border-right: 1px solid var(--border, #343438);
		color: var(--fg, #fafafa);
	}

	.navigation-drawer::backdrop {
		background: rgba(9, 9, 11, 0.68);
	}

	.drawer-content {
		display: flex;
		flex-direction: column;
		height: 100%;
	}

	.skip-link {
		position: fixed;
		top: 8px;
		left: 8px;
		z-index: 40;
		padding: 8px 12px;
		background: var(--surface-elevated, #27272a);
		border: 1px solid var(--focus, #d4d4d8);
		border-radius: 6px;
		color: var(--fg, #fafafa);
		text-decoration: none;
		transform: translateY(-160%);
	}

	.skip-link:focus {
		transform: translateY(0);
	}

	.visually-hidden {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip: rect(0, 0, 0, 0);
		white-space: nowrap;
		border: 0;
	}

	.navigation-link:focus-visible,
	.theme-control:focus-visible,
	.icon-button:focus-visible,
	.collapse-tab:focus-visible {
		outline: 2px solid var(--focus, #d4d4d8);
		outline-offset: 2px;
	}

	@media (max-width: 899px) {
		.admin-shell {
			grid-template-columns: minmax(0, 1fr);
		}

		.desktop-sidebar {
			display: none;
		}

		.mobile-header {
			display: flex;
		}

		.workspace-header {
			padding: 16px 16px 0;
		}

		.workspace {
			padding: 14px 16px 24px;
		}
	}

	@media (prefers-reduced-motion: reduce) {
		.admin-shell,
		.switch-track span {
			transition: none;
		}
	}
</style>
