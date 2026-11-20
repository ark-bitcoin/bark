<script lang="ts">
	// Ported from bullnym's HistoryScreen (nostr-pos's Transactions layout),
	// reading sales from posd with paging and a CSV export.
	import { Download } from 'lucide-svelte'
	import type { Sale } from '$lib/api'
	import { isoDate } from '$lib/sale'
	import { client, session } from '$lib/session.svelte'
	import BullFooter from '$lib/components/BullFooter.svelte'
	import Button from '$lib/components/Button.svelte'
	import HeaderLinks from '$lib/components/HeaderLinks.svelte'
	import TransactionSheet from '$lib/components/TransactionSheet.svelte'

	const PAGE = 50

	let rows = $state<Sale[]>([])
	let loading = $state(true)
	let more = $state(false)
	let errorMsg = $state<string | null>(null)

	const today = new Date()
	let from = $state(isoDate(new Date(today.getFullYear(), today.getMonth(), 1)))
	let to = $state(isoDate(today))
	let exporting = $state(false)

	async function load(before?: string) {
		loading = true
		errorMsg = null
		try {
			const page = await client().sales({ before, limit: PAGE })
			rows = before ? [...rows, ...page] : page
			more = page.length === PAGE
		} catch (e) {
			errorMsg = e instanceof Error ? e.message : 'Could not load sales'
		} finally {
			loading = false
		}
	}

	void load()

	async function exportCsv() {
		if (exporting || !from || !to) return
		exporting = true
		errorMsg = null
		try {
			const blob = await client().salesCsv(from, to)
			const url = URL.createObjectURL(blob)
			const a = document.createElement('a')
			a.href = url
			a.download = `sales-${from}-to-${to}.csv`
			document.body.appendChild(a)
			a.click()
			a.remove()
			setTimeout(() => URL.revokeObjectURL(url), 1000)
		} catch (e) {
			errorMsg = e instanceof Error ? e.message : 'Could not export sales'
		} finally {
			exporting = false
		}
	}
</script>

<main class="min-h-screen bg-[#f5f0e8] px-5 py-5 text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
	<div class="mx-auto max-w-3xl">
		<header class="mb-8 flex items-center justify-between gap-4">
			<a class="inline-flex min-h-12 items-center gap-2 rounded-md px-2 text-sm font-semibold" href="#/">← Back</a>
			<HeaderLinks history={false} />
		</header>

		<div class="mb-5">
			<h1 class="font-display text-4xl uppercase tracking-display leading-none">Recent sales</h1>
			<p class="mt-1 text-xs font-medium uppercase tracking-[0.12em] text-[#776b5a] dark:text-[#b9aa91]">
				{session.terminal?.store.name ?? ''}
			</p>
		</div>

		{#if errorMsg}
			<p class="mb-4 rounded-md bg-[#ffe0d9] px-4 py-3 text-sm font-semibold text-[#8c2d28]">{errorMsg}</p>
		{/if}

		<TransactionSheet {rows} />

		{#if more}
			<div class="mt-4 flex justify-center">
				<Button variant="secondary" disabled={loading} onclick={() => load(rows[rows.length - 1]?.id)}>
					{loading ? 'Loading' : 'Load more'}
				</Button>
			</div>
		{/if}

		<section class="mt-8 rounded-lg border border-[#d7c8b4] bg-[#fffaf0] p-4 dark:border-[#3a342a] dark:bg-[#211f1a]">
			<h2 class="font-display text-2xl uppercase tracking-display leading-none">Export</h2>
			<p class="mt-1 text-sm text-[#776b5a] dark:text-[#b9aa91]">Download the sales between two dates as a CSV file.</p>
			<div class="mt-3 grid grid-cols-2 gap-3">
				<label class="flex flex-col gap-1.5">
					<span class="text-xs font-medium uppercase tracking-[0.12em] text-[#776b5a] dark:text-[#b9aa91]">From</span>
					<input type="date" bind:value={from} class="min-h-12 rounded-lg border border-[#d7c8b4] bg-[#fffaf0] px-3 dark:border-[#3a342a] dark:bg-[#161512]" />
				</label>
				<label class="flex flex-col gap-1.5">
					<span class="text-xs font-medium uppercase tracking-[0.12em] text-[#776b5a] dark:text-[#b9aa91]">To</span>
					<input type="date" bind:value={to} class="min-h-12 rounded-lg border border-[#d7c8b4] bg-[#fffaf0] px-3 dark:border-[#3a342a] dark:bg-[#161512]" />
				</label>
			</div>
			<div class="mt-3">
				<Button variant="secondary" disabled={exporting || !from || !to} onclick={exportCsv}>
					<Download size={18} />{exporting ? 'Exporting' : 'Export CSV'}
				</Button>
			</div>
		</section>

		<BullFooter />
	</div>
</main>
