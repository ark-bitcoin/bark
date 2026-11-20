<script lang="ts">
	// Ported from bullnym's KeypadScreen (nostr-pos's Keypad layout): header
	// with the store name and History/Settings buttons, a big amount, the
	// keypad, a memo, and the Charge button pinned at the bottom.
	import { ApiError, type Rate } from '$lib/api'
	import { applyAmountInput } from '$lib/amount-input'
	import { currencyPrecision, fiatToSats, formatFiat, formatRate, formatSats, normalizeFiat } from '$lib/money'
	import { router } from '$lib/router.svelte'
	import { rememberSale } from '$lib/sale-cache'
	import { client, session } from '$lib/session.svelte'
	import AmountDisplay from '$lib/components/AmountDisplay.svelte'
	import BullFooter from '$lib/components/BullFooter.svelte'
	import Button from '$lib/components/Button.svelte'
	import HeaderLinks from '$lib/components/HeaderLinks.svelte'
	import Keypad from '$lib/components/Keypad.svelte'

	const RATE_REFRESH_MS = 60_000

	const store = $derived(session.terminal?.store ?? null)
	const currency = $derived(store?.currency ?? 'USD')

	let unit = $state<'fiat' | 'sat'>('fiat')
	let amount = $state('')
	let memo = $state('')
	let creating = $state(false)
	let errorMsg = $state<string | null>(null)
	let rate = $state<Rate | null>(null)
	let rateError = $state(false)

	const precision = $derived(unit === 'sat' ? 0 : currencyPrecision(currency))

	$effect(() => {
		let stopped = false
		async function load() {
			try {
				const next = await client().rate()
				if (!stopped) {
					rate = next
					rateError = false
				}
			} catch {
				if (!stopped) rateError = true
			}
		}
		void load()
		const timer = setInterval(load, RATE_REFRESH_MS)
		return () => {
			stopped = true
			clearInterval(timer)
		}
	})

	const sats = $derived(unit === 'sat' ? Math.trunc(Number(amount || '0')) : rate ? fiatToSats(amount, rate.btc_price) : 0)
	const hint = $derived.by(() => {
		if (!amount || !rate) return undefined
		if (unit === 'fiat') return `≈ ${formatSats(sats)}`
		const fiat = (sats / 1e8) * Number(rate.btc_price)
		return `≈ ${formatFiat(fiat, rate.currency)}`
	})
	const rateReady = $derived(unit === 'sat' || rate !== null)
	const canCharge = $derived(sats > 0 && rateReady && !creating)

	function applyInput(key: string) {
		amount = applyAmountInput(amount, key, precision)
	}

	function setUnit(next: 'fiat' | 'sat') {
		if (unit === next) return
		unit = next
		amount = ''
	}

	async function charge() {
		if (!canCharge) return
		creating = true
		errorMsg = null
		const note = memo.trim() || undefined
		try {
			const sale = await client().createSale(
				unit === 'sat' ? { amount_sat: sats, memo: note } : { fiat_amount: normalizeFiat(amount, precision), memo: note },
			)
			rememberSale(sale)
			amount = ''
			memo = ''
			router.go(`/pay/${sale.id}`)
		} catch (e) {
			if (e instanceof ApiError && e.status === 0) errorMsg = 'The server is not reachable'
			else if (e instanceof ApiError && e.status === 502) errorMsg = 'Payments are not available right now. Try again in a moment.'
			else errorMsg = e instanceof Error ? e.message : 'Something went wrong'
		} finally {
			creating = false
		}
	}
</script>

<main class="h-[100dvh] overflow-hidden bg-[#f5f0e8] text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
	<div class="mx-auto flex h-[100dvh] max-w-4xl flex-col overflow-hidden">
		<section class="flex min-h-0 flex-1 flex-col overflow-hidden px-5 py-3 sm:px-8 sm:py-5">
			<header class="mb-3 flex shrink-0 items-center justify-between gap-4 sm:mb-5">
				<div class="min-w-0">
					<h1 class="truncate font-display text-3xl uppercase tracking-display leading-none">{store?.name ?? 'Point of sale'}</h1>
					{#if session.terminal}
						<p class="mt-0.5 truncate text-xs font-medium uppercase tracking-[0.12em] text-[#776b5a] dark:text-[#b9aa91]">
							{session.terminal.device_name}
						</p>
					{/if}
				</div>
				<HeaderLinks />
			</header>

			<div class="mx-auto flex min-h-0 w-full max-w-xl flex-1 flex-col overflow-y-auto scrollbar-none">
				<div class="my-auto flex w-full flex-col gap-3 sm:gap-5">
					<div class="flex justify-end">
						<div class="inline-flex rounded-md bg-[#eadfce] p-0.5 text-xs dark:bg-[#2c2922]" role="tablist" aria-label="Amount unit">
							{#each [['fiat', currency], ['sat', 'Sats']] as [value, label] (value)}
								<button
									type="button"
									role="tab"
									aria-selected={unit === value}
									class={`min-h-9 rounded-md px-4 font-semibold transition ${
										unit === value
											? 'bg-[#fffaf0] text-[#1f513a] shadow-sm dark:bg-[#161512] dark:text-[#8bc8a4]'
											: 'text-[#5f5547] dark:text-[#c9bca7]'
									}`}
									onclick={() => setUnit(value as 'fiat' | 'sat')}
								>
									{label}
								</button>
							{/each}
						</div>
					</div>
					<AmountDisplay amount={amount || '0'} unit={unit === 'sat' ? 'sat' : currency} {precision} {hint} />
					<Keypad {precision} onInput={applyInput} />
					<label class="flex shrink-0 flex-col gap-1.5">
						<span class="text-xs font-medium uppercase tracking-[0.12em] text-[#776b5a] dark:text-[#b9aa91]">Memo</span>
						<textarea
							class="min-h-12 rounded-lg border border-[#d7c8b4] bg-[#fffaf0] px-4 py-3 text-base outline-none focus:ring-2 focus:ring-[#B7000B] dark:border-[#3a342a] dark:bg-[#211f1a]"
							bind:value={memo}
							placeholder="Add a memo for this sale"
							maxlength="200"
							rows="1"
						></textarea>
					</label>
					<div class={`text-center text-xs ${rateError ? 'text-[#a9362f] dark:text-[#e8a49e]' : 'text-[#776b5a] dark:text-[#b9aa91]'}`}>
						{#if rate}
							Rate: {formatRate(rate.btc_price, rate.currency)}{rateError ? ' (not updated)' : ''}
						{:else if rateError}
							Rate unavailable. You can still charge in sats.
						{:else}
							Updating rate…
						{/if}
					</div>
					{#if errorMsg}
						<p class="rounded-md bg-[#ffe0d9] px-4 py-3 text-sm font-semibold text-[#8c2d28]">{errorMsg}</p>
					{/if}
					<BullFooter />
				</div>
			</div>

			<div
				class="mx-auto mt-2 flex w-full max-w-xl shrink-0 flex-col bg-gradient-to-t from-[#f5f0e8] from-60% to-transparent pb-[max(0.25rem,env(safe-area-inset-bottom))] pt-2 dark:from-[#161512]"
			>
				<Button disabled={!canCharge} onclick={charge}>
					{creating ? 'Preparing' : 'Charge'}
				</Button>
			</div>
		</section>
	</div>
</main>
