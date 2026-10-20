import type { Snippet } from 'svelte';
import type { AdminUser, DashboardTab, Permission } from '$lib/types/admin';

/** Inputs for the authenticated administration shell. */
export interface AdminShellProps {
	/** Active page, owned by the parent. */
	activeTab: DashboardTab;
	/** Authenticated account and its navigation permissions. */
	user: AdminUser;
	/** Whether sign-out is currently in flight. */
	busy: boolean;
	/** Active session CSRF token for the top-right task tray. */
	csrf: string | null;
	/** Incrementing signal that pulses and opens the top-right task tray. */
	taskPulse: number;
	/** Selects a page without transferring page-state ownership. */
	onselect: (tab: DashboardTab) => void;
	/** Signs out through the parent's session action. */
	onlogout: () => void;
	/** Opens a job detail modal when selected from the top-right task tray. */
	onselectjob: (jobId: string) => void;
	/** Handles background task tray errors. */
	onerror: (error: unknown) => void;
	/** Compiled mirrors for Ctrl/Cmd+K quick navigation. */
	mirrors?: { repository: string; suite: string; configured: boolean }[];
	/** Selects a specific mirror from quick search. */
	onmirror?: (repository: string, suite: string) => void;
	/** Content for the selected page. */
	children: Snippet;
}

/** Outline symbols used consistently throughout the shell. */
export type NavigationIcon =
	| 'mirrors'
	| 'storage'
	| 'traffic'
	| 'account'
	| 'users'
	| 'search'
	| 'chevron'
	| 'menu'
	| 'close'
	| 'sun'
	| 'moon'
	| 'logout'
	| 'tasks'
	| 'docs';

/** Searchable destination with an optional permission requirement. */
export interface NavigationEntry {
	/** Parent-owned page identifier and URL fragment. */
	tab: DashboardTab;
	/** Human-readable destination name. */
	label: string;
	/** Shared outline symbol. */
	icon: NavigationIcon;
	/** Navigation group heading. */
	section: 'Main' | 'Settings';
	/** Permission needed to show the destination. */
	permission?: Permission;
}

/** Persisted neutral color scheme. */
export type NavigationTheme = 'dark' | 'light';
