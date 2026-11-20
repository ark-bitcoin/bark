<script lang="ts">
	// Ported from bullnym, which ported nostr-pos's TransactionSheet: the same
	// markup and classes over posd sales.
	import { ChevronRight } from 'lucide-svelte'
	import type { Sale } from '$lib/api'
	import { formatFiat } from '$lib/money'
	import { railLabel, saleAmountLabel, stateBorderTone, stateLabel } from '$lib/sale'

	let { rows }: { rows: Sale[] } = $props()

	function when(sale: Sale): string {
		return new Date(sale.paid_at ?? sale.created_at).toLocaleString([], {
			month: 'short',
			day: 'numeric',
			hour: '2-digit',
			minute: '2-digit',
		})
	}
</script>

<section>
	{#if rows.length === 0}
		<p
			class="rounded-lg border border-[#d7c8b4] bg-[#fffaf0] py-12 text-center text-sm text-[#776b5a] dark:border-[#3a342a] dark:bg-[#211f1a] dark:text-[#b9aa91]"
		>
			Completed sales will appear here.
		</p>
	{:else}
		<div class="space-y-1.5">
			{#each rows as row (row.id)}
				<a
					class={`grid grid-cols-[1fr_auto] items-center gap-3 rounded-lg border-l-4 bg-[#fbf4e8] px-4 py-3 transition hover:bg-[#f3e7d6] dark:bg-[#26231d] ${stateBorderTone(row.state)}`}
					href={`#/receipt/${row.id}`}
				>
					<div class="min-w-0">
						<div class="flex items-baseline gap-2">
							<span class="font-black tabular-nums">{saleAmountLabel(row, (a, c) => formatFiat(a, c))}</span>
							{#if row.state !== 'paid'}
								<span class="text-xs font-semibold text-[#776b5a] dark:text-[#b9aa91]">{stateLabel(row.state)}</span>
							{/if}
						</div>
						<div class="mt-0.5 truncate text-xs text-[#776b5a] dark:text-[#b9aa91]">
							{when(row)} &middot; {railLabel(row.paid_rail)}{row.memo ? ` · ${row.memo}` : ''}
						</div>
					</div>
					<ChevronRight size={18} class="text-[#b1a287] dark:text-[#6d634f]" />
				</a>
			{/each}
		</div>
	{/if}
</section>
