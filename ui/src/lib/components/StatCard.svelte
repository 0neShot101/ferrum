<script lang="ts">
	import type { StatCardProps } from '$lib/types/admin';

	let { title, value, subtitle, class: className }: StatCardProps = $props();
</script>

<article class={['stat-block', className]}>
	<p class="stat-title">{title}</p>
	<p class="stat-value">{value}</p>
	{#if subtitle !== undefined}
		<p class="stat-caption">{subtitle}</p>
	{/if}
</article>
