// Ported from bullnym (pwa/lib/amount-input.ts), which ported it from
// nostr-pos. Governs the decimal-string amount typed on the Keypad.
//
// The Keypad shows '00' instead of '.' for a currency with no minor unit,
// so a cashier cannot type cents on such a currency.

const maxWholeDigits = 9
const defaultMaxDecimalDigits = 2

export function applyAmountInput(current: string, key: string, maxDecimalDigits = defaultMaxDecimalDigits): string {
	if (key === 'back') return current.slice(0, -1)
	if (key === '.') {
		if (maxDecimalDigits === 0 || current.includes('.')) return current
		return current ? `${current}.` : '0.'
	}
	if (key === '00') {
		if (current.includes('.')) return current
		const next = `${current || '0'}00`.replace(/^0+(?=\d)/, '')
		return next.length > maxWholeDigits ? current : next
	}
	if (!/^\d$/.test(key)) return current

	const [whole, cents] = current.split('.')
	if (cents !== undefined) {
		if (cents.length >= maxDecimalDigits) return current
		return `${whole}.${cents}${key}`
	}

	const next = `${current}${key}`.replace(/^0+(?=\d)/, '')
	return next.length > maxWholeDigits ? current : next
}
