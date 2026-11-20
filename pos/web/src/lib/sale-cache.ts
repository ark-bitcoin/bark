// Sales this page created or loaded, so the pay and receipt screens can
// render at once and refresh from posd after.
import type { Sale } from './api'

const sales = new Map<string, Sale>()

export function rememberSale(sale: Sale): void {
	sales.set(sale.id, sale)
}

export function cachedSale(id: string): Sale | undefined {
	return sales.get(id)
}
