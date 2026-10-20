<script lang="ts">
	import type { MetricChartProps, TelemetrySample } from '$lib/types/admin';
	import { formatBytes, formatTimestamp } from '$lib/utils/format';

	let { samples, metric, title, unit, range, resolution }: MetricChartProps = $props();

	const chartId = $props.id();

	const formatValue = (value: number | null | undefined): string => {
		if (value === null || value === undefined) return 'Unavailable';
		if (metric === 'bytesPerSecond') return `${formatBytes(Math.round(value))}/s`;
		if (metric === 'latencyP95Seconds') return `${(value * 1000).toFixed(1)} ms`;
		return `${value.toFixed(2)} req/s`;
	};

	const latestSample = $derived(samples.at(-1) ?? null);
	const latestValue = $derived(formatValue(latestSample?.[metric] ?? null));

	const peakValue = $derived.by(() => {
		let maxVal: number | null = null;
		for (const sample of samples) {
			const current = sample[metric];
			if (current !== null && (maxVal === null || current > maxVal)) maxVal = current;
		}
		return formatValue(maxVal);
	});

	const maximum = $derived.by(() => {
		let maxVal = 1;
		for (const sample of samples) {
			const current = sample[metric] ?? 0;
			if (current > maxVal) maxVal = current;
		}
		return maxVal;
	});

	const paths = $derived.by(() => {
		const segments: string[] = [];
		let currentSegment = '';
		let previous: TelemetrySample | undefined = undefined;
		const firstTime = samples[0]?.sampleAt ?? 0;
		const lastTime = samples.at(-1)?.sampleAt ?? firstTime;
		const duration = Math.max(1, lastTime - firstTime);

		for (const sample of samples) {
			const value = sample[metric];
			const hasGap =
				sample.gap ||
				(previous !== undefined &&
					(sample.bootId !== previous.bootId ||
						sample.sampleAt - previous.sampleAt > resolution * 1.5));

			if (hasGap || value === null) {
				if (currentSegment !== '') segments.push(currentSegment);
				currentSegment = '';
			}

			if (value !== null && sample.gap === false) {
				const x = 44 + ((sample.sampleAt - firstTime) / duration) * 636;
				const y = 148 - (value / maximum) * 118;
				const command = currentSegment === '' ? 'M' : ' L';
				currentSegment += `${command}${x.toFixed(2)},${y.toFixed(2)}`;
			}

			previous = sample;
		}

		if (currentSegment !== '') segments.push(currentSegment);
		return segments;
	});
</script>

<figure class="metric-chart">
	<figcaption class="chart-header">
		<div>
			<strong id={chartId}>{title} ({unit}, {range})</strong>
			<p class="muted">
				Resolution {resolution}s · Latest {formatTimestamp(latestSample?.sampleAt ?? null)}
			</p>
		</div>
		<div class="chart-summary">
			<span>Latest: <strong>{latestValue}</strong></span>
			<span>Peak: <strong>{peakValue}</strong></span>
		</div>
	</figcaption>

	{#if samples.length > 0}
		<svg viewBox="0 0 720 185" role="img" aria-labelledby={chartId}>
			<path class="chart-axis" d="M44 20V148H684" />
			<text x="0" y="26">{maximum.toFixed(1)}</text>
			<text x="24" y="152">0</text>
			{#each paths as pathSegment (pathSegment)}
				<path class="chart-line" d={pathSegment} />
			{/each}
			<text x="44" y="176">
				{new Date(samples[0].sampleAt * 1000).toLocaleTimeString()}
			</text>
			<text x="564" y="176">
				{new Date(samples[samples.length - 1].sampleAt * 1000).toLocaleTimeString()}
			</text>
		</svg>
	{:else}
		<p class="empty-state">Collecting initial 5-second telemetry samples.</p>
	{/if}
</figure>
