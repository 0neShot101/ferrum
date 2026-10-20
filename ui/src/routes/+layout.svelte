<script lang="ts">
	import '$lib/app.css';
	import type { LayoutProps } from '$lib/types/admin';

	let { children }: LayoutProps = $props();
</script>

{@render children()}
