<script lang="ts">
	// Ported from bullnym (pwa/lib/components/BullFooter.svelte).
	let { width = 140 }: { width?: number } = $props()

	const lightLogo = `${import.meta.env.BASE_URL}bb-logo-light.png`
	const darkLogo = `${import.meta.env.BASE_URL}bb-logo-dark.png`
</script>

<div class="flex justify-center py-4">
	<a
		href="https://bullbitcoin.com"
		target="_blank"
		rel="noopener noreferrer"
		aria-label="Bull Bitcoin"
		class="inline-block transition hover:opacity-80"
	>
		<img src={lightLogo} alt="Bull Bitcoin" class="bb-banner block dark:hidden" {width} />
		<img src={darkLogo} alt="Bull Bitcoin" class="bb-banner hidden dark:block" {width} />
	</a>
</div>

<style>
	.bb-banner {
		height: auto;
	}
</style>
