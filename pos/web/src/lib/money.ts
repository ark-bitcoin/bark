// Currency formatting, ported from bullnym (pwa/lib/money.ts). posd sends
// fiat amounts and prices as decimal strings in major units.

/**
 * Minor-unit digits typed and shown for a currency. The colón has cents in
 * ISO 4217, but nobody prices in them, so it is entered as whole colones.
 */
const PRECISION_OVERRIDES: Record<string, number> = { CRC: 0 }

export function currencyPrecision(currency: string): number {
	const override = PRECISION_OVERRIDES[currency.toUpperCase()]
	if (override !== undefined) return override
	try {
		return new Intl.NumberFormat('en', { style: 'currency', currency }).resolvedOptions().maximumFractionDigits ?? 2
	} catch {
		return 2
	}
}

/** Format a major-unit fiat amount, for example ("8500", "CRC") → "₡8,500". */
export function formatFiat(amount: string | number, currency: string, precision = currencyPrecision(currency)): string {
	const value = typeof amount === 'string' ? Number(amount) : amount
	try {
		return new Intl.NumberFormat(undefined, {
			style: 'currency',
			currency,
			minimumFractionDigits: precision,
			maximumFractionDigits: precision,
		}).format(value)
	} catch {
		return `${new Intl.NumberFormat(undefined, {
			minimumFractionDigits: precision,
			maximumFractionDigits: precision,
		}).format(value)} ${currency}`
	}
}

/**
 * Format the amount as the Keypad builds it. Cents show only after a
 * decimal point is typed, as in nostr-pos.
 */
export function formatFiatAmount(amount: string, currency: string, precision: number): string {
	const digits = precision === 0 ? 0 : amount.includes('.') ? precision : 0
	return formatFiat(amount || '0', currency, digits)
}

export function formatSats(sats: number): string {
	return `${new Intl.NumberFormat().format(sats)} sats`
}

/** Format a price, for example ("62500000", "CRC") → "₡62,500,000/BTC". */
export function formatRate(btcPrice: string, currency: string): string {
	return `${formatFiat(btcPrice, currency, currencyPrecision(currency))}/BTC`
}

/** Sats for a fiat amount at a BTC price, rounded to the nearest sat. */
export function fiatToSats(fiatAmount: string, btcPrice: string): number {
	const fiat = Number(fiatAmount)
	const price = Number(btcPrice)
	if (!Number.isFinite(fiat) || !Number.isFinite(price) || fiat <= 0 || price <= 0) return 0
	return Math.round((fiat / price) * 1e8)
}

/**
 * The fiat amount as posd expects it: a decimal string with exactly the
 * currency's minor digits, for example ("12.5", 2) → "12.50".
 */
export function normalizeFiat(amount: string, precision: number): string {
	const value = Number(amount || '0')
	return value.toFixed(precision)
}

/** Ported from nostr-pos's shortId. */
export function shortId(value?: string | null): string {
	if (!value) return '—'
	if (value.length <= 12) return value
	return `${value.slice(0, 6)}...${value.slice(-6)}`
}
