<script lang="ts">
	import { onMount } from 'svelte';
	import {
		createAdminUser,
		deleteAdminUser,
		fetchOwnSessions,
		fetchUserSessions,
		fetchUsers,
		revokeOwnSession,
		revokeUserSession,
		updateAdminUser,
		updateOwnAccount
	} from '$lib/services/api';
	import type {
		AccountUsersPageProps,
		AdminSession,
		AdminUser,
		Permission
	} from '$lib/types/admin';
	import { formatPermission, formatTimestamp } from '$lib/utils/format';
	import Modal from './Modal.svelte';
	import StatusBadge from './StatusBadge.svelte';

	let { user, csrf, mode, onerror, onreauth }: AccountUsersPageProps = $props();

	const allPermissions: Permission[] = [
		'view_status',
		'view_inventory',
		'view_audit',
		'trigger_sync',
		'manage_cache',
		'manage_users',
		'manage_config',
		'acknowledge_alerts'
	];

	let users = $state<AdminUser[]>([]);
	let sessions = $state<AdminSession[]>([]);
	let sessionTargetUser = $state<AdminUser | null>(null);
	let username = $state('');
	let displayName = $state('');
	let currentPassword = $state('');
	let password = $state('');
	let permissions = $state<Permission[]>(['view_status']);
	let disabled = $state(false);
	let editingUser = $state<AdminUser | null>(null);
	let editorOpen = $state(false);
	let busy = $state(false);
	let loaded = $state(false);
	let message = $state('');
	let userToDelete = $state<AdminUser | null>(null);
	let sessionToRevoke = $state<AdminSession | null>(null);
	const controller = new AbortController();

	const loadData = async (): Promise<void> => {
		try {
			if (mode === 'users') {
				const result = await fetchUsers(controller.signal);
				if (controller.signal.aborted === false) users = result;
			} else {
				const result = await fetchOwnSessions(controller.signal);
				if (controller.signal.aborted === false) sessions = result;
			}
			loaded = true;
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		}
	};

	const openUserEditor = (target: AdminUser | null): void => {
		editingUser = target;
		username = target?.username ?? '';
		displayName = target?.displayName ?? '';
		password = '';
		permissions = target !== null ? [...target.permissions] : ['view_status'];
		disabled = target?.disabled ?? false;
		editorOpen = true;
	};

	const applyPreset = (presetName: string): void => {
		const grants: Permission[] =
			presetName === 'Administrator'
				? allPermissions
				: presetName === 'Operator'
					? [
							'view_status',
							'view_inventory',
							'view_audit',
							'trigger_sync',
							'manage_cache',
							'acknowledge_alerts'
						]
					: ['view_status', 'view_inventory'];
		permissions = grants.filter((permission) =>
			user.permissions.includes(permission)
		);
	};

	const togglePermission = (permission: Permission): void => {
		permissions = permissions.includes(permission)
			? permissions.filter((item) => item !== permission)
			: [...permissions, permission];
	};

	const saveOwnAccount = async (): Promise<void> => {
		if (busy) return;
		busy = true;
		try {
			await updateOwnAccount(
				csrf,
				{
					username: username !== user.username ? username : undefined,
					displayName,
					currentPassword: currentPassword === '' ? undefined : currentPassword,
					newPassword: password === '' ? undefined : password
				},
				controller.signal
			);
			if (controller.signal.aborted === false) onreauth();
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		} finally {
			currentPassword = '';
			password = '';
			busy = false;
		}
	};

	const saveManagedUser = async (): Promise<void> => {
		if (busy) return;
		busy = true;
		try {
			const passwordBytes = new TextEncoder().encode(password).length;
			if (password !== '' && (passwordBytes < 12 || passwordBytes > 1024))
				throw new Error('Passwords require 12 to 1,024 UTF-8 bytes.');

			if (editingUser !== null)
				await updateAdminUser(
					csrf,
					editingUser.id,
					{
						displayName,
						password: password === '' ? undefined : password,
						permissions,
						disabled
					},
					controller.signal
				);
			else
				await createAdminUser(
					csrf,
					{
						username,
						displayName,
						password,
						permissions
					},
					controller.signal
				);

			if (controller.signal.aborted === false) {
				const isSelf = editingUser?.id === user.id;
				editorOpen = false;
				message = 'User saved.';
				if (isSelf) onreauth();
				else await loadData();
			}
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		} finally {
			password = '';
			busy = false;
		}
	};

	const confirmDeleteUser = async (): Promise<void> => {
		if (userToDelete === null || busy) return;
		busy = true;
		try {
			await deleteAdminUser(csrf, userToDelete.id, controller.signal);
			if (controller.signal.aborted === false) {
				userToDelete = null;
				await loadData();
			}
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		} finally {
			busy = false;
		}
	};

	const inspectUserSessions = async (target: AdminUser): Promise<void> => {
		try {
			const result = await fetchUserSessions(target.id, controller.signal);
			if (controller.signal.aborted === false) {
				sessions = result;
				sessionTargetUser = target;
			}
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		}
	};

	const confirmRevokeSession = async (): Promise<void> => {
		if (sessionToRevoke === null || busy) return;
		busy = true;
		try {
			if (sessionTargetUser !== null)
				await revokeUserSession(
					csrf,
					sessionTargetUser.id,
					sessionToRevoke.id,
					controller.signal
				);
			else await revokeOwnSession(csrf, sessionToRevoke.id, controller.signal);

			if (controller.signal.aborted === false) {
				const wasCurrent = sessionToRevoke.current;
				sessions = sessions.filter((item) => item.id !== sessionToRevoke?.id);
				sessionToRevoke = null;
				if (wasCurrent) onreauth();
			}
		} catch (error) {
			if (controller.signal.aborted === false) onerror(error);
		} finally {
			busy = false;
		}
	};

	onMount(() => {
		username = user.username;
		displayName = user.displayName;
		void loadData();
		return () => {
			controller.abort();
			password = '';
			currentPassword = '';
		};
	});
</script>

{#snippet sessionTable()}
	<p class="muted">
		Sessions expire after 8 hours absolute or 30 minutes idle. Session tokens are hashed with
		SHA-256 at rest.
	</p>
	<div class="table-wrap">
		<table>
			<thead>
				<tr>
					<th>Session</th>
					<th>Created</th>
					<th>Last activity</th>
					<th>Expires</th>
					<th>Actions</th>
				</tr>
			</thead>
			<tbody>
				{#each sessions as session (session.id)}
					<tr>
						<td class="mono">
							{session.current ? 'Current session' : `${session.id.slice(0, 14)}...`}
						</td>
						<td>{formatTimestamp(session.createdAt)}</td>
						<td>{formatTimestamp(session.lastSeenAt)}</td>
						<td>{formatTimestamp(session.expiresAt)}</td>
						<td>
							<button
								class="button is-danger"
								type="button"
								disabled={busy}
								onclick={() => {
									sessionToRevoke = session;
								}}
							>
								Revoke
							</button>
						</td>
					</tr>
				{:else}
					<tr>
						<td colspan="5" class="empty-state">
							{loaded ? 'No active sessions.' : 'Loading sessions...'}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/snippet}

{#if mode === 'account'}
	<section class="card spaced-panel">
		<h2>Your account</h2>
		<p class="muted">
			Passwords are hashed with Argon2id (64 MiB memory, 3 iterations). Updating your account
			revokes existing sessions and requires signing in again.
		</p>

		<form
			onsubmit={(event) => {
				event.preventDefault();
				void saveOwnAccount();
			}}
		>
			<div class="filter-grid">
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

				<label class="field">
					<span>Display name</span>
					<input
						class="input"
						bind:value={displayName}
						required
						maxlength="128"
					/>
				</label>

				<label class="field">
					<span>Current password (required to change username or password)</span>
					<input
						class="input"
						bind:value={currentPassword}
						type="password"
						autocomplete="current-password"
					/>
				</label>

				<label class="field">
					<span>New password (12 to 1,024 bytes; leave blank to keep current)</span>
					<input
						class="input"
						bind:value={password}
						type="password"
						autocomplete="new-password"
						maxlength="1024"
					/>
				</label>
			</div>

			<button class="button is-primary" disabled={busy} type="submit">
				Save account
			</button>
		</form>
	</section>

	<section class="card">
		<h2>Your active sessions</h2>
		{@render sessionTable()}
	</section>
{:else}
	<section class="card table-panel">
		<div class="table-toolbar">
			<h2>User administration</h2>
			<div class="toolbar">
				<button class="button" type="button" onclick={loadData}>
					Refresh users
				</button>
				<button
					class="button is-primary"
					type="button"
					onclick={() => openUserEditor(null)}
				>
					Create user
				</button>
			</div>
		</div>

		{#if message !== ''}
			<p class="panel-note" role="status">{message}</p>
		{/if}

		<div class="table-wrap">
			<table>
				<thead>
					<tr>
						<th>Account</th>
						<th>Permissions</th>
						<th>Last login</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody>
					{#each users as target (target.id)}
						<tr>
							<td>
								<strong>{target.displayName}</strong>
								<div class="muted">
									@{target.username} ·
									<StatusBadge
										tone={target.disabled ? 'danger' : 'ok'}
										label={target.disabled ? 'Disabled' : 'Enabled'}
									/>
								</div>
							</td>
							<td>
								{target.permissions.map(formatPermission).join(', ')}
							</td>
							<td>{formatTimestamp(target.lastLoginAt)}</td>
							<td>
								<div class="toolbar">
									<button
										class="button"
										type="button"
										onclick={() => openUserEditor(target)}
									>
										Edit
									</button>
									<button
										class="button"
										type="button"
										onclick={() => inspectUserSessions(target)}
									>
										Sessions
									</button>
									<button
										class="button is-danger"
										type="button"
										disabled={target.id === user.id}
										onclick={() => {
											userToDelete = target;
										}}
									>
										Delete
									</button>
								</div>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	</section>
{/if}

{#if editorOpen}
	<Modal
		title={editingUser !== null ? `Edit @${editingUser.username}` : 'Create user'}
		onclose={() => {
			editorOpen = false;
			password = '';
		}}
	>
		<form
			onsubmit={(event) => {
				event.preventDefault();
				void saveManagedUser();
			}}
		>
			<label class="field">
				<span>Username</span>
				<input
					class="input"
					bind:value={username}
					required
					maxlength="64"
					disabled={editingUser !== null}
				/>
			</label>

			<label class="field">
				<span>Display name</span>
				<input
					class="input"
					bind:value={displayName}
					maxlength="128"
					required
				/>
			</label>

			<label class="field">
				<span>
					{editingUser !== null
						? 'Password reset (optional, 12 to 1,024 bytes)'
						: 'Initial password (12 to 1,024 bytes)'}
				</span>
				<input
					class="input"
					bind:value={password}
					type="password"
					autocomplete="new-password"
					required={editingUser === null}
					maxlength="1024"
				/>
			</label>

			<label class="field">
				<span>Permission preset</span>
				<select
					class="input"
					value="Custom"
					onchange={(event) => applyPreset(event.currentTarget.value)}
				>
					<option>Custom</option>
					<option>Viewer</option>
					<option>Operator</option>
					<option>Administrator</option>
				</select>
			</label>

			<div class="checkbox-grid">
				{#each allPermissions as permission (permission)}
					<label class="checkbox-item">
						<input
							type="checkbox"
							disabled={permission === 'view_status' ||
								user.permissions.includes(permission) === false}
							checked={permissions.includes(permission)}
							onchange={() => togglePermission(permission)}
						/>
						<span>{formatPermission(permission)}</span>
					</label>
				{/each}
			</div>

			{#if editingUser !== null}
				<label class="checkbox-item">
					<input type="checkbox" bind:checked={disabled} />
					<span>Disable account and revoke active sessions</span>
				</label>
			{/if}

			<button class="button is-primary" disabled={busy} type="submit">
				Save user
			</button>
		</form>
	</Modal>
{/if}

{#if sessionTargetUser !== null}
	<Modal
		title={`Sessions for @${sessionTargetUser.username}`}
		onclose={() => {
			sessionTargetUser = null;
			sessions = [];
		}}
	>
		{@render sessionTable()}
	</Modal>
{/if}

{#if userToDelete !== null}
	<Modal
		title={`Delete @${userToDelete.username}?`}
		onclose={() => {
			userToDelete = null;
		}}
	>
		<p>This revokes access immediately and cannot be undone.</p>
		<button
			class="button is-danger"
			type="button"
			disabled={busy}
			onclick={confirmDeleteUser}
		>
			Confirm delete account
		</button>
	</Modal>
{/if}

{#if sessionToRevoke !== null}
	<Modal
		title="Revoke session?"
		onclose={() => {
			sessionToRevoke = null;
		}}
	>
		<p>
			{sessionToRevoke.current
				? 'This signs out your current browser session immediately.'
				: 'The selected session loses access immediately.'}
		</p>
		<button
			class="button is-danger"
			type="button"
			disabled={busy}
			onclick={confirmRevokeSession}
		>
			Confirm revoke
		</button>
	</Modal>
{/if}
