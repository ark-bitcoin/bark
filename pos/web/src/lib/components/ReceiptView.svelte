<script lang="ts">
	// Ported from bullnym (pwa/lib/components/ReceiptView.svelte).
	let {
		merchantName,
		posName,
		receiptNumber,
		dateLabel,
		methodLabel,
		statusLabel,
		amountSatsLabel,
		amountFiatLabel,
		note,
		saleIdShort,
		settlementIdShort,
	}: {
		merchantName: string
		posName: string
		receiptNumber: string
		dateLabel: string
		methodLabel: string
		statusLabel: string
		amountSatsLabel: string
		amountFiatLabel: string
		note?: string
		saleIdShort: string
		settlementIdShort?: string
	} = $props()
</script>

<article class="receipt-paper mx-auto max-w-sm rounded-md border border-[#d7c8b4] bg-[#fffaf0] p-6 text-[#211f1a] shadow-sm">
	<header class="border-b border-dashed border-[#9f8d73] pb-4 text-center">
		<h1 class="text-2xl font-black">{merchantName}</h1>
		<p class="text-sm">{posName}</p>
		<p class="mt-2 text-xs">Receipt {receiptNumber}</p>
	</header>

	<dl class="my-5 space-y-3 text-sm">
		<div class="flex justify-between gap-4">
			<dt>Date</dt>
			<dd>{dateLabel}</dd>
		</div>
		<div class="flex justify-between gap-4">
			<dt>Method</dt>
			<dd>{methodLabel}</dd>
		</div>
		<div class="flex justify-between gap-4">
			<dt>Status</dt>
			<dd>{statusLabel}</dd>
		</div>
		<div class="flex justify-between gap-4">
			<dt>Amount</dt>
			<dd>{amountSatsLabel}</dd>
		</div>
		{#if note}
			<div class="border-t border-dashed border-[#9f8d73] pt-3">
				<dt>Note</dt>
				<dd>{note}</dd>
			</div>
		{/if}
	</dl>

	<div class="border-y border-dashed border-[#9f8d73] py-4">
		<div class="flex justify-between text-lg font-black">
			<span>Total</span>
			<span>{amountFiatLabel}</span>
		</div>
	</div>

	<footer class="pt-4 text-center text-xs">
		<p>Sale {saleIdShort}</p>
		{#if settlementIdShort}
			<p>Settlement {settlementIdShort}</p>
		{/if}
	</footer>
</article>
