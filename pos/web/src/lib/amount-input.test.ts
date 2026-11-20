// Ported from bullnym (pwa/lib/amount-input.test.ts). Every reduce wraps
// applyAmountInput in a 2-argument arrow: passing it directly would feed the
// array index in as maxDecimalDigits.
import { describe, expect, it } from 'vitest'
import { applyAmountInput } from './amount-input'

function type(keys: string[], maxDecimalDigits?: number): string {
	return keys.reduce((acc, k) => applyAmountInput(acc, k, maxDecimalDigits), '')
}

describe('amount keypad input', () => {
	it('enters whole amounts without cents until decimal is pressed', () => {
		expect(type(['1', '2', '3'])).toBe('123')
	})

	it('starts cents entry with 0 when decimal is pressed first', () => {
		expect(applyAmountInput('', '.')).toBe('0.')
	})

	it('allows up to two cents digits after decimal', () => {
		expect(type(['1', '2', '.', '3', '4', '5'])).toBe('12.34')
	})

	it('keeps only one decimal point', () => {
		expect(type(['1', '.', '.', '2'])).toBe('1.2')
	})

	it('deletes across cents and decimal point', () => {
		expect(type(['1', '2', '.', '3', 'back', 'back', '4'])).toBe('124')
	})

	it('00 key appends two zeros for zero-decimal currency entry', () => {
		expect(type(['3', '00'])).toBe('300')
	})

	it('00 key on empty input strips leading zeros', () => {
		expect(applyAmountInput('', '00')).toBe('0')
		expect(type(['00', '5'])).toBe('5')
	})

	it('00 key is a no-op once a decimal point is present', () => {
		expect(type(['1', '.', '00'])).toBe('1.')
	})

	it('ignores a decimal point for a currency without a minor unit', () => {
		expect(type(['1', '.', '5'], 0)).toBe('15')
	})

	it('caps whole digits at nine', () => {
		expect(type(['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'])).toBe('123456789')
	})
})
