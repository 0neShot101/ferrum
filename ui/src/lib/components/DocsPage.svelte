<script lang="ts">
	import { marked } from 'marked';
	import type { DocEntry } from '$lib/types/admin';

	const rawFiles = import.meta.glob('$lib/docs/*.md', {
		query: '?raw',
		import: 'default',
		eager: true
	}) as Record<string, string>;

	const extractTitle = (markdown: string, fallback: string): string => {
		const match = /^#\s+(.+)$/m.exec(markdown);
		return match !== null ? match[1].trim() : fallback;
	};

	const buildDocs = (): DocEntry[] => {
		const entries = Object.entries(rawFiles).sort(([left], [right]) =>
			left.localeCompare(right)
		);
		return entries.map(([filePath, raw]) => {
			const fileName = filePath.split('/').pop() ?? filePath;
			const slug = fileName.replace(/\.md$/i, '').replace(/^\d+-/, '');
			const title = extractTitle(raw, slug);
			const html = marked.parse(raw, { async: false });
			return {
				slug,
				title,
				raw,
				html
			};
		});
	};

	const docs = buildDocs();
	let activeSlug = $state(docs[0]?.slug ?? '');
	let searchQuery = $state('');

	const filteredDocs = $derived(
		searchQuery.trim() === ''
			? docs
			: docs.filter(
					(doc) =>
						doc.title.toLowerCase().includes(searchQuery.trim().toLowerCase()) ||
						doc.raw.toLowerCase().includes(searchQuery.trim().toLowerCase())
				)
	);

	const activeDoc = $derived(
		filteredDocs.find((doc) => doc.slug === activeSlug) ?? filteredDocs[0] ?? null
	);

	const selectDoc = (slug: string): void => {
		activeSlug = slug;
	};
</script>

<div class="docs-layout">
	<aside class="docs-sidebar card" aria-label="Documentation topics">
		<label class="field">
			<span>Search documentation</span>
			<input
				class="input"
				type="search"
				bind:value={searchQuery}
				placeholder="Search guides, TOML keys..."
			/>
		</label>

		<nav class="docs-nav" aria-label="Guides">
			{#each filteredDocs as doc (doc.slug)}
				<button
					type="button"
					class={['docs-nav-item', activeDoc?.slug === doc.slug && 'is-selected']}
					onclick={() => selectDoc(doc.slug)}
				>
					{doc.title}
				</button>
			{:else}
				<p class="muted">No guides match your search.</p>
			{/each}
		</nav>

		<p class="muted docs-hint">
			Guides are compiled from <code>ui/src/lib/docs/*.md</code> via <code>marked</code>.
		</p>
	</aside>

	<article class="docs-article card">
		{#if activeDoc !== null}
			<div class="markdown-body">
				{@html activeDoc.html}
			</div>
		{:else}
			<p class="empty-state">Select a documentation topic or clear your search filter.</p>
		{/if}
	</article>
</div>
