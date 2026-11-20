<script lang="ts">
	// After bullnym's PayScreen and PayFlow: the amount, one QR code for every
	// rail, and the payment state, kept current with posd's long-poll.
	import { untrack } from 'svelte'
	import { ApiError, type Sale } from '$lib/api'
	import { formatFiat, formatSats } from '$lib/money'
	import { router } from '$lib/router.svelte'
	import { countdown, isLive, railLabel, saleAmountLabel } from '$lib/sale'
	import { cachedSale, rememberSale } from '$lib/sale-cache'
	import { client } from '$lib/session.svelte'
	import BullSpinner from '$lib/components/BullSpinner.svelte'
	import Button from '$lib/components/Button.svelte'
	import CopyRow from '$lib/components/CopyRow.svelte'
	import HeaderLinks from '$lib/components/HeaderLinks.svelte'
	import QrCard from '$lib/components/QrCard.svelte'
	import SuccessScreen from '$lib/components/SuccessScreen.svelte'
	import TerminalPanel from '$lib/components/TerminalPanel.svelte'

	let { id }: { id: string } = $props()

	const RETRY_MS = 2_000

	let sale = $state<Sale | null>(untrack(() => cachedSale(id) ?? null))
	let notFound = $state(false)
	let offline = $state(false)
	let canceling = $state(false)
	let nowMs = $state(Date.now())

	// Long-poll until the sale leaves its live states. Each request returns
	// when the state changes or after the server's wait limit.
	$effect(() => {
		const abort = new AbortController()
		async function run() {
			let current = untrack(() => sale)
			if (!current) {
				try {
					current = await client().sale(id)
					sale = current
					rememberSale(current)
				} catch (e) {
					if (e instanceof ApiError && e.status === 404) {
						notFound = true
						return
					}
				}
			}
			while (!abort.signal.aborted) {
				if (current && !isLive(current.state)) return
				try {
					const next = current ? await client().waitSale(id, current.state, abort.signal) : await client().sale(id)
					offline = false
					current = next
					sale = next
					rememberSale(next)
				} catch (e) {
					if (abort.signal.aborted) return
					if (e instanceof ApiError && e.status === 404) {
						notFound = true
						return
					}
					offline = e instanceof ApiError && e.status === 0
					await new Promise((r) => setTimeout(r, RETRY_MS))
				}
			}
		}
		void run()
		return () => abort.abort()
	})

	$effect(() => {
		const timer = setInterval(() => (nowMs = Date.now()), 1000)
		return () => clearInterval(timer)
	})

	// An expired sale returns to the keypad on its own, as in bullnym.
	$effect(() => {
		if (sale?.state !== 'expired') return
		const t = setTimeout(newSale, 1800)
		return () => clearTimeout(t)
	})

	const amountLabel = $derived(sale ? saleAmountLabel(sale, (a, c) => formatFiat(a, c)) : '')
	const remaining = $derived(sale ? countdown(sale.expires_at, nowMs) : null)

	function newSale() {
		router.go('/')
	}

	async function cancel() {
		if (!sale || sale.state !== 'open') {
			newSale()
			return
		}
		canceling = true
		try {
			const next = await client().cancelSale(sale.id)
			rememberSale(next)
			sale = next
			newSale()
		} catch (e) {
			// A payment arrived first; the long-poll shows it.
			if (!(e instanceof ApiError && e.status === 409)) newSale()
		} finally {
			canceling = false
		}
	}
</script>

<main class="min-h-screen bg-[#f5f0e8] text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
	<div class="mx-auto grid min-h-screen max-w-4xl grid-rows-1">
		<section class="px-5 py-5 sm:px-8">
			<header class="mb-6 flex items-center justify-between">
				<button
					type="button"
					class="inline-flex min-h-12 items-center gap-2 rounded-md px-2 text-sm font-semibold disabled:opacity-50"
					onclick={cancel}
					disabled={canceling || sale?.state === 'in-progress'}
				>
					← {sale?.state === 'open' || !sale ? 'Cancel sale' : 'New sale'}
				</button>
				<HeaderLinks />
			</header>

			{#if notFound}
				<TerminalPanel icon="×" tone="err" title="Not found" detail="This sale could not be found." actionLabel="Back" onaction={newSale} />
			{:else if !sale}
				<div class="grid min-h-[60vh] place-items-center">
					<BullSpinner size={72} label="Preparing" />
				</div>
			{:else if sale.state === 'paid'}
				<div class="flex flex-col items-center gap-3">
					<SuccessScreen
						{amountLabel}
						rail={railLabel(sale.paid_rail)}
						actionLabel="New Sale"
						onaction={newSale}
						secondaryLabel="Receipt"
						onsecondary={() => router.go(`/receipt/${id}`)}
					/>
					{#if sale.received_sat > sale.amount_sat}
						<p class="max-w-sm rounded-md bg-[#fff0c7] px-4 py-3 text-center text-sm font-semibold text-[#725315] dark:bg-[#3a321f] dark:text-[#f0d38a]">
							Paid more than the sale: received {formatSats(sale.received_sat)}, expected {formatSats(sale.amount_sat)}.
						</p>
					{/if}
				</div>
			{:else if sale.state === 'expired'}
				<TerminalPanel icon="×" tone="err" title="Expired" detail="This sale expired without payment. Returning..." />
			{:else if sale.state === 'canceled'}
				<TerminalPanel icon="×" tone="err" title="Canceled" detail="This sale was canceled." actionLabel="Back" onaction={newSale} />
			{:else if sale.state === 'in-progress'}
				<div class="mx-auto flex max-w-md flex-col items-center gap-5 py-6 text-center">
					<p class="font-display text-7xl tabular-nums tracking-display leading-none">{amountLabel}</p>
					<BullSpinner size={72} label="Payment in progress" />
					<div class="rounded-md bg-[#fff0c7] px-5 py-4 text-[#725315] dark:bg-[#3a321f] dark:text-[#f0d38a]">
						<p class="font-semibold">The bitcoin payment is in the mempool.</p>
						<p class="mt-1 text-sm">
							The sale is paid at 1 confirmation, which usually takes 10 to 60 minutes. You can start a new sale; this one
							stays in history and completes on its own.
						</p>
					</div>
					<Button variant="secondary" onclick={newSale}>New Sale</Button>
				</div>
			{:else}
				<div class="mx-auto flex w-full max-w-md flex-col items-center gap-5">
					<div class="flex w-full flex-col items-center gap-1">
						<p class="font-display text-7xl tabular-nums tracking-display leading-none">{amountLabel}</p>
						{#if sale.fiat_amount !== null}
							<p class="text-sm tabular-nums text-[#776b5a] dark:text-[#b9aa91]">{formatSats(sale.amount_sat)}</p>
						{/if}
						<p class="inline-flex items-center gap-1.5 text-xs font-semibold text-[#725315] dark:text-[#f0d38a]">
							<span class="inline-block h-1.5 w-1.5 rounded-full bg-current"></span>
							{offline ? 'Reconnecting…' : 'Waiting for payment'}{remaining ? ` · ${remaining}` : ''}
						</p>
						{#if sale.memo}
							<p class="text-center text-sm text-[#776b5a] dark:text-[#b9aa91]">{sale.memo}</p>
						{/if}
					</div>

					<QrCard value={sale.payment_request} label="Payment code for Lightning, Ark and bitcoin" />

					<div class="flex w-full flex-col gap-2">
						<CopyRow label="Lightning invoice" value={sale.lightning_invoice} />
						{#if sale.onchain_address}
							<CopyRow label="Bitcoin address" value={sale.onchain_address} />
						{/if}
					</div>
					{#if !sale.onchain_address}
						<p class="text-center text-xs text-[#776b5a] dark:text-[#b9aa91]">On-chain payment is not offered for this amount.</p>
					{/if}
				</div>
			{/if}
		</section>
	</div>
</main>
