<script lang="ts">
	// Terminal shell. "/pair/<code>" activates the device; once it has a
	// token, the app is hash-routed like bullnym's POS.
	import { ApiError } from '$lib/api'
	import { router } from '$lib/router.svelte'
	import { client, pairingCodeFromPath, session } from '$lib/session.svelte'
	import BullSpinner from '$lib/components/BullSpinner.svelte'
	import HistoryScreen from './screens/HistoryScreen.svelte'
	import KeypadScreen from './screens/KeypadScreen.svelte'
	import PairScreen from './screens/PairScreen.svelte'
	import PayScreen from './screens/PayScreen.svelte'
	import ReceiptScreen from './screens/ReceiptScreen.svelte'
	import SettingsScreen from './screens/SettingsScreen.svelte'
	import UnpairedScreen from './screens/UnpairedScreen.svelte'

	const pairingCode = pairingCodeFromPath(location.pathname)

	// An installed app always opens at its start_url, which carries the
	// pairing code. A device that is already paired ignores the code.
	if (session.token && pairingCode) history.replaceState(null, '', `/${location.hash || '#/'}`)

	let loadError = $state<string | null>(null)

	$effect(() => {
		const token = session.token
		if (!token) return
		let current = true
		loadError = null
		client()
			.terminal()
			.then((t) => {
				if (current) session.terminal = t
			})
			.catch((e) => {
				if (current && !(e instanceof ApiError && e.isUnauthorized)) {
					loadError = e instanceof ApiError && e.status === 0 ? 'The server is not reachable.' : 'Could not load the terminal.'
				}
			})
		return () => {
			current = false
		}
	})

	const payId = $derived(router.match('/pay/:id')?.id)
	const receiptId = $derived(router.match('/receipt/:id')?.id)
</script>

{#if !session.token}
	{#if pairingCode}
		<PairScreen code={pairingCode} />
	{:else}
		<UnpairedScreen />
	{/if}
{:else if !session.terminal}
	<main class="grid min-h-screen place-items-center bg-[#f5f0e8] px-5 text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
		{#if loadError}
			<div class="text-center">
				<p class="font-semibold">{loadError}</p>
				<button class="mt-4 min-h-12 rounded-md bg-[#eadfce] px-5 font-semibold dark:bg-[#2c2922]" onclick={() => location.reload()}>
					Try again
				</button>
			</div>
		{:else}
			<BullSpinner size={72} label="Loading" />
		{/if}
	</main>
{:else if payId}
	{#key payId}
		<PayScreen id={payId} />
	{/key}
{:else if receiptId}
	{#key receiptId}
		<ReceiptScreen id={receiptId} />
	{/key}
{:else if router.path === '/history'}
	<HistoryScreen />
{:else if router.path === '/settings'}
	<SettingsScreen />
{:else}
	<KeypadScreen />
{/if}
