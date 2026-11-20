<script lang="ts">
	// Pairing, after nostr-pos's Activate screen. The owner's wallet makes a
	// single-use link; this screen exchanges its code for a device token.
	import { ShieldCheck } from 'lucide-svelte'
	import { ApiError, PosClient } from '$lib/api'
	import { session } from '$lib/session.svelte'
	import Button from '$lib/components/Button.svelte'
	import BullFooter from '$lib/components/BullFooter.svelte'

	let { code }: { code: string } = $props()

	let deviceName = $state('')
	let busy = $state(false)
	let errorMsg = $state<string | null>(null)

	const standalone =
		window.matchMedia('(display-mode: standalone)').matches ||
		(navigator as Navigator & { standalone?: boolean }).standalone === true

	async function activate() {
		const name = deviceName.trim()
		if (!name || busy) return
		busy = true
		errorMsg = null
		try {
			const res = await new PosClient().pair(code, name)
			session.signIn(res.token)
			// Leave the one-time link so a reload does not try the code again.
			history.replaceState(null, '', '/#/')
		} catch (e) {
			if (e instanceof ApiError && e.status === 404) {
				errorMsg = 'This link was already used or has expired. Ask the owner for a new link.'
			} else if (e instanceof ApiError && e.status === 0) {
				errorMsg = 'The server is not reachable. Check the connection and try again.'
			} else {
				errorMsg = e instanceof Error ? e.message : 'Something went wrong'
			}
		} finally {
			busy = false
		}
	}
</script>

<main class="grid min-h-screen place-items-center bg-[#f5f0e8] px-5 text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
	<section class="w-full max-w-md text-center">
		<ShieldCheck class="mx-auto text-[#1f513a]" size={44} />
		<h1 class="mt-5 text-3xl font-black">Activate this terminal</h1>
		<p class="mt-3 text-[#776b5a] dark:text-[#b9aa91]">
			Give this device a name. Staff see the name on receipts and the owner sees it in the device list.
		</p>
		{#if !standalone}
			<p class="mt-3 rounded-md bg-[#fff0c7] px-4 py-3 text-sm text-[#725315] dark:bg-[#3a321f] dark:text-[#f0d38a]">
				To use this terminal as an app, add it to the home screen first, then open it from there and activate it.
				The link works once.
			</p>
		{/if}
		<form
			class="my-8 flex flex-col gap-3 text-left"
			onsubmit={(e) => {
				e.preventDefault()
				void activate()
			}}
		>
			<label class="flex flex-col gap-1.5">
				<span class="text-xs font-medium uppercase tracking-[0.12em] text-[#776b5a] dark:text-[#b9aa91]">Device name</span>
				<input
					class="min-h-12 rounded-lg border border-[#d7c8b4] bg-[#fffaf0] px-4 py-3 text-base outline-none focus:ring-2 focus:ring-[#B7000B] dark:border-[#3a342a] dark:bg-[#211f1a]"
					bind:value={deviceName}
					placeholder="Front till"
					maxlength="60"
					autocomplete="off"
				/>
			</label>
			{#if errorMsg}
				<p class="rounded-md bg-[#ffe0d9] px-4 py-3 text-sm font-semibold text-[#8c2d28]">{errorMsg}</p>
			{/if}
			<Button type="submit" disabled={!deviceName.trim() || busy}>{busy ? 'Activating' : 'Activate'}</Button>
		</form>
		<BullFooter />
	</section>
</main>
