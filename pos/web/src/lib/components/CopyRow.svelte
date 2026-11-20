<script lang="ts">
	// One payment instruction with a copy button, for payers who cannot scan
	// the combined QR code.
	import { Check, Copy } from 'lucide-svelte'
	import { shortId } from '$lib/money'

	let { label, value }: { label: string; value: string } = $props()
	let copied = $state(false)

	async function copy() {
		try {
			await navigator.clipboard.writeText(value)
			copied = true
			setTimeout(() => (copied = false), 1500)
		} catch {
			/* clipboard unavailable */
		}
	}
</script>

<button
	type="button"
	class="flex min-h-12 w-full items-center justify-between gap-3 rounded-md bg-[#eadfce] px-4 py-2 text-left text-sm dark:bg-[#2c2922]"
	onclick={copy}
	aria-label={`Copy ${label}`}
>
	<span class="min-w-0">
		<span class="block text-xs font-semibold uppercase tracking-[0.12em] text-[#776b5a] dark:text-[#b9aa91]">{label}</span>
		<span class="block truncate font-mono">{shortId(value)}</span>
	</span>
	{#if copied}
		<Check size={18} class="shrink-0 text-[#1f513a] dark:text-[#8bc8a4]" />
	{:else}
		<Copy size={18} class="shrink-0" />
	{/if}
</button>
