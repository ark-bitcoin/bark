<script lang="ts">
	// Ported from bullnym's ReceiptScreen (nostr-pos's Receipt layout): back
	// link, Print and Share, the receipt card and a status banner. Receipts
	// print at 80 mm.
	import { untrack } from 'svelte'
	import { Printer, RotateCw, Share2 } from 'lucide-svelte'
	import { ApiError, type Sale } from '$lib/api'
	import { formatFiat, formatSats, shortId } from '$lib/money'
	import { router } from '$lib/router.svelte'
	import { railLabel, receiptNumber, saleAmountLabel, stateLabel } from '$lib/sale'
	import { cachedSale, rememberSale } from '$lib/sale-cache'
	import { client, session } from '$lib/session.svelte'
	import Button from '$lib/components/Button.svelte'
	import ReceiptView from '$lib/components/ReceiptView.svelte'

	let { id }: { id: string } = $props()

	let sale = $state<Sale | null>(untrack(() => cachedSale(id) ?? null))
	let notFound = $state(false)

	$effect(() => {
		client()
			.sale(id)
			.then((s) => {
				rememberSale(s)
				sale = s
			})
			.catch((e) => {
				if (e instanceof ApiError && e.status === 404) notFound = true
			})
	})

	const isPaid = $derived(sale?.state === 'paid')
	const dateLabel = $derived(sale ? new Date(sale.paid_at ?? sale.created_at).toLocaleString() : '—')

	async function share() {
		await navigator.share?.({ title: 'Receipt', url: location.href })
	}

	$effect(() => {
		document.body.classList.add('paper-80mm')
		const style = document.createElement('style')
		style.textContent = '@media print { @page { size: 80mm auto; margin: 5mm; } }'
		document.head.appendChild(style)
		return () => {
			document.body.classList.remove('paper-80mm')
			style.remove()
		}
	})
</script>

<main class="min-h-screen bg-[#f5f0e8] px-5 py-5 text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
	<div class="no-print mx-auto mb-5 flex max-w-xl items-center justify-between">
		<button class="inline-flex min-h-12 items-center gap-2 rounded-md font-bold" onclick={() => history.back()}>← Back</button>
		<div class="flex gap-2">
			{#if isPaid}
				<Button variant="secondary" onclick={() => window.print()}><Printer size={18} />Print</Button>
				<Button variant="ghost" onclick={share}><Share2 size={18} />Share</Button>
			{:else}
				<Button variant="secondary" onclick={() => router.go('/')}><RotateCw size={18} />New sale</Button>
			{/if}
		</div>
	</div>

	{#if notFound}
		<p class="py-20 text-center">Receipt not found.</p>
	{:else if sale}
		<ReceiptView
			merchantName={session.terminal?.store.name ?? ''}
			posName={sale.device_name ?? 'Lightning address'}
			receiptNumber={receiptNumber(sale.id)}
			{dateLabel}
			methodLabel={railLabel(sale.paid_rail)}
			statusLabel={stateLabel(sale.state)}
			amountSatsLabel={formatSats(sale.state === 'paid' ? sale.received_sat : sale.amount_sat)}
			amountFiatLabel={saleAmountLabel(sale, (a, c) => formatFiat(a, c))}
			note={sale.memo ?? undefined}
			saleIdShort={shortId(sale.id)}
		/>
		<div class="no-print mx-auto mt-5 max-w-sm text-center">
			<div
				class={`rounded-md px-5 py-4 ${
					isPaid ? 'bg-[#d9f3df] text-[#14522d]' : 'bg-[#fff0c7] text-[#725315] dark:bg-[#3a321f] dark:text-[#f0d38a]'
				}`}
			>
				<p class="font-display text-5xl uppercase tracking-display leading-none">{stateLabel(sale.state)}</p>
				<p class="mt-1 text-sm">{isPaid ? 'Receipt ready.' : 'Start a new sale.'}</p>
			</div>
		</div>
	{/if}
</main>
