// Presentation of a Sale: labels, tones and the receipt number.
import type { PaidRail, Sale, SaleState } from './api'

export function railLabel(rail: PaidRail | null): string {
	switch (rail) {
		case 'lightning':
			return 'Lightning'
		case 'ark':
			return 'Ark'
		case 'onchain':
			return 'Bitcoin'
		default:
			return '—'
	}
}

export function stateLabel(state: SaleState): string {
	switch (state) {
		case 'open':
			return 'Waiting for payment'
		case 'in-progress':
			return 'In progress'
		case 'paid':
			return 'Paid'
		case 'expired':
			return 'Expired'
		case 'canceled':
			return 'Canceled'
	}
}

/** Left-border tone for a history row, as in nostr-pos's TransactionSheet. */
export function stateBorderTone(state: SaleState): string {
	switch (state) {
		case 'paid':
			return 'border-[#1f513a]'
		case 'in-progress':
		case 'open':
			return 'border-[#c99a2e]'
		default:
			return 'border-[#a9362f]'
	}
}

/** The sale is still waiting for its payment. */
export function isLive(state: SaleState): boolean {
	return state === 'open' || state === 'in-progress'
}

/** "12-3456" from the last six characters of the sale ID, as in bullnym. */
export function receiptNumber(id: string): string {
	const clean = id.replace(/-/g, '').toUpperCase()
	const last6 = clean.slice(-6).padStart(6, '0')
	return `${last6.slice(0, 2)}-${last6.slice(2)}`
}

/** The headline amount: fiat when the sale was keyed in fiat, else sats. */
export function saleAmountLabel(sale: Sale, format: (amount: string, currency: string) => string): string {
	if (sale.fiat_amount !== null && sale.currency) return format(sale.fiat_amount, sale.currency)
	return `${new Intl.NumberFormat().format(sale.amount_sat)} sats`
}

/** Remaining time as "m:ss", or null once expired. */
export function countdown(expiresAt: string, nowMs: number): string | null {
	const seconds = Math.ceil((Date.parse(expiresAt) - nowMs) / 1000)
	if (!Number.isFinite(seconds) || seconds <= 0) return null
	return `${Math.floor(seconds / 60)}:${(seconds % 60).toString().padStart(2, '0')}`
}

/** "YYYY-MM-DD" for a local date. */
export function isoDate(d: Date): string {
	const pad = (n: number) => n.toString().padStart(2, '0')
	return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}
