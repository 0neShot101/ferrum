<script lang="ts">
	import type { StatusBadgeProps } from '$lib/types/admin';

	let { tone, label, class: className }: StatusBadgeProps = $props();
</script>

<span
	class={[
		'status-text',
		tone === 'warn' && 'is-warn',
		tone === 'danger' && 'is-danger',
		tone === 'neutral' && 'is-neutral',
		className
	]}
>
	{#if tone === 'warn' || tone === 'danger'}
		<svg
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			stroke-width="1.75"
			stroke-linecap="round"
			stroke-linejoin="round"
			aria-hidden="true"
		>
			{#if tone === 'warn'}
				<path d="M10.3 3.9 2 18.2A2 2 0 0 0 3.7 21h16.6a2 2 0 0 0 1.7-2.8L13.7 3.9a2 2 0 0 0-3.4 0Z" />
			{:else}
				<circle cx="12" cy="12" r="9" />
			{/if}
			<path d="M12 8v5m0 4h.01" />
		</svg>
	{/if}
	{label}
</span>
