import { describe, expect, it } from 'vitest'
import { currencyPrecision, fiatToSats, formatFiatAmount, formatSats, normalizeFiat, shortId } from './money'

describe('currencyPrecision', () => {
	it('enters colones as whole units', () => {
		expect(currencyPrecision('CRC')).toBe(0)
	})

	it('uses the ISO minor unit for other currencies', () => {
		expect(currencyPrecision('USD')).toBe(2)
		expect(currencyPrecision('JPY')).toBe(0)
	})

	it('falls back to 2 for an unknown code', () => {
		expect(currencyPrecision('???')).toBe(2)
	})
})

describe('fiatToSats', () => {
	it('converts at the BTC price and rounds to the nearest sat', () => {
		expect(fiatToSats('12.50', '62500')).toBe(20000)
		expect(fiatToSats('1', '3')).toBe(33333333)
	})

	it('returns 0 for an empty amount or a missing price', () => {
		expect(fiatToSats('', '62500')).toBe(0)
		expect(fiatToSats('10', '0')).toBe(0)
		expect(fiatToSats('10', 'x')).toBe(0)
	})
})

describe('normalizeFiat', () => {
	it('pads to the currency precision', () => {
		expect(normalizeFiat('12.5', 2)).toBe('12.50')
		expect(normalizeFiat('12.', 2)).toBe('12.00')
		expect(normalizeFiat('8500', 0)).toBe('8500')
		expect(normalizeFiat('', 2)).toBe('0.00')
	})
})

describe('formatting', () => {
	it('shows cents only after a decimal point is typed', () => {
		expect(formatFiatAmount('12', 'USD', 2)).toBe(new Intl.NumberFormat(undefined, { style: 'currency', currency: 'USD', maximumFractionDigits: 0, minimumFractionDigits: 0 }).format(12))
		expect(formatFiatAmount('12.5', 'USD', 2)).toBe(new Intl.NumberFormat(undefined, { style: 'currency', currency: 'USD', minimumFractionDigits: 2 }).format(12.5))
	})

	it('never shows cents for a currency without them', () => {
		expect(formatFiatAmount('11.', 'CRC', 0)).not.toContain('.00')
	})

	it('groups sats', () => {
		expect(formatSats(35000)).toBe(`${new Intl.NumberFormat().format(35000)} sats`)
	})

	it('shortens long IDs', () => {
		expect(shortId('4f1c9a2e-0000-4000-8000-1234567890ab')).toBe('4f1c9a...7890ab')
		expect(shortId(null)).toBe('—')
	})
})
