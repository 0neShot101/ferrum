<script lang="ts">
	import type { EvidenceTableProps } from '$lib/types/admin';
	import { formatBytes } from '$lib/utils/format';

	let { values, caption = 'Recorded values' }: EvidenceTableProps = $props();

	const entries = $derived(Object.entries(values));

	const formatLabel = (key: string): string =>
		key.replace(/([A-Z])/g, ' $1').replace(/^./, (char) => char.toUpperCase());

	const isByteField = (key: string, value: unknown): value is string | number =>
		/bytes$/i.test(key) && (typeof value === 'string' || typeof value === 'number');
</script>

<div class="table-wrap">
	<table>
		<caption>{caption}</caption>
		<thead>
			<tr>
				<th>Field</th>
				<th>Recorded value</th>
			</tr>
		</thead>
		<tbody>
			{#each entries as [key, value] (key)}
				<tr>
					<th scope="row">{formatLabel(key)}</th>
					<td class="break-word">
						{#if value !== null && typeof value === 'object'}
							<pre>{JSON.stringify(value, null, 2)}</pre>
						{:else if value === null || value === undefined}
							Unavailable
						{:else if isByteField(key, value)}
							<span title={String(value)}>{formatBytes(value)}</span>
							<small class="muted"> ({String(value)} bytes)</small>
						{:else}
							{String(value)}
						{/if}
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
</div>
