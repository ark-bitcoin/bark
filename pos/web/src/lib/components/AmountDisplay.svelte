<script lang="ts">
	// Ported from bullnym, which ported nostr-pos's AmountDisplay. `unit` is a
	// store currency code or 'sat' for an amount keyed in sats.
	import { formatFiatAmount } from '$lib/money'

	let {
		amount,
		unit,
		precision = 2,
		hint,
	}: { amount: string; unit: string; precision?: number; hint?: string } = $props()

	const display = $derived(
		unit === 'sat'
			? `${new Intl.NumberFormat().format(Math.trunc(Number(amount || '0')))} sats`
			: formatFiatAmount(amount, unit, precision),
	)
</script>

<div class="text-right">
	<div class="font-display text-xs uppercase tracking-[0.18em] text-[#776b5a] dark:text-[#b9aa91]">Total</div>
	<div
		class="mt-1 whitespace-nowrap font-display tabular-nums tracking-display text-[clamp(2.5rem,10vw,7.5rem)] leading-[0.95] text-[#211f1a] dark:text-[#fff6e8]"
	>
		{display}
	</div>
	{#if hint}
		<div class="mt-1 text-sm tabular-nums text-[#776b5a] dark:text-[#b9aa91]">{hint}</div>
	{/if}
</div>
