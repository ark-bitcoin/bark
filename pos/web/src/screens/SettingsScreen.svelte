<script lang="ts">
	// After bullnym's SettingsScreen (nostr-pos's Settings look). The owner
	// manages the store from the wallet, so this screen shows the setup and
	// can only remove this device.
	import { formatSats } from '$lib/money'
	import { session } from '$lib/session.svelte'
	import BullFooter from '$lib/components/BullFooter.svelte'
	import Button from '$lib/components/Button.svelte'

	let confirming = $state(false)

	const store = $derived(session.terminal?.store ?? null)

	function unpair() {
		if (!confirming) {
			confirming = true
			return
		}
		session.signOut()
		location.hash = '#/'
	}
</script>

<main class="min-h-screen bg-[#f5f0e8] px-5 py-5 text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
	<div class="mx-auto max-w-xl">
		<header class="mb-8 flex items-center justify-between gap-4">
			<a class="inline-flex min-h-12 items-center gap-2 rounded-md px-2 text-sm font-semibold" href="#/">← Back</a>
		</header>

		<h1 class="mb-5 font-display text-4xl uppercase tracking-display leading-none">Settings</h1>

		<dl class="space-y-3 rounded-lg border border-[#d7c8b4] bg-[#fffaf0] p-5 text-sm dark:border-[#3a342a] dark:bg-[#211f1a]">
			<div class="flex justify-between gap-4">
				<dt class="text-[#776b5a] dark:text-[#b9aa91]">Store</dt>
				<dd class="text-right font-semibold">{store?.name ?? '—'}</dd>
			</div>
			<div class="flex justify-between gap-4">
				<dt class="text-[#776b5a] dark:text-[#b9aa91]">This device</dt>
				<dd class="text-right font-semibold">{session.terminal?.device_name ?? '—'}</dd>
			</div>
			<div class="flex justify-between gap-4">
				<dt class="text-[#776b5a] dark:text-[#b9aa91]">Currency</dt>
				<dd class="text-right font-semibold">{store?.currency ?? '—'}</dd>
			</div>
			<div class="flex justify-between gap-4">
				<dt class="text-[#776b5a] dark:text-[#b9aa91]">Lightning address</dt>
				<dd class="break-all text-right font-semibold">{store?.lightning_address ?? 'Not set'}</dd>
			</div>
			<div class="flex justify-between gap-4">
				<dt class="text-[#776b5a] dark:text-[#b9aa91]">On-chain from</dt>
				<dd class="text-right font-semibold">{store ? formatSats(store.onchain_min_sat) : '—'}</dd>
			</div>
		</dl>
		<p class="mt-3 text-xs text-[#776b5a] dark:text-[#b9aa91]">
			The owner changes these settings in the wallet. Payments go to the owner's wallet; this device cannot send funds.
		</p>

		<section class="mt-8">
			<Button variant="danger" onclick={unpair}>{confirming ? 'Tap again to remove this device' : 'Remove this device'}</Button>
			{#if confirming}
				<p class="mt-2 text-xs text-[#776b5a] dark:text-[#b9aa91]">
					This device stops taking payments. To use it again, the owner must send a new link.
				</p>
			{/if}
		</section>

		<BullFooter />
	</div>
</main>
