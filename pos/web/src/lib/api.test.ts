import { describe, expect, it, vi } from 'vitest'
import { ApiError, PosClient, localDayRange, type Fetch } from './api'

type Call = { url: string; init: RequestInit }

function fakeFetch(responses: Response[]): { fetch: Fetch; calls: Call[] } {
	const calls: Call[] = []
	const fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
		calls.push({ url: String(input), init: init ?? {} })
		const next = responses.shift()
		if (!next) throw new Error('unexpected request')
		return next
	}) as Fetch
	return { fetch, calls }
}

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function header(call: Call, name: string): string | undefined {
	return (call.init.headers as Record<string, string> | undefined)?.[name]
}

describe('PosClient', () => {
	it('pairs without a token and sends the device name', async () => {
		const { fetch, calls } = fakeFetch([json({ token: 't', store: { name: 'S' } })])
		const res = await new PosClient({ fetch, token: 'old' }).pair('abc', 'Front till')
		expect(res.token).toBe('t')
		expect(calls[0]!.url).toBe('/api/v1/pair')
		expect(calls[0]!.init.method).toBe('POST')
		expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ code: 'abc', device_name: 'Front till' })
		expect(header(calls[0]!, 'Authorization')).toBeUndefined()
	})

	it('sends the bearer token on terminal calls', async () => {
		const { fetch, calls } = fakeFetch([json({ currency: 'CRC', btc_price: '1', fetched_at: 'x' })])
		await new PosClient({ fetch, token: 'tok' }).rate()
		expect(calls[0]!.url).toBe('/api/v1/rate')
		expect(header(calls[0]!, 'Authorization')).toBe('Bearer tok')
	})

	it('creates a fiat sale with the contract body', async () => {
		const { fetch, calls } = fakeFetch([json({ id: 's1' })])
		await new PosClient({ fetch, token: 'tok' }).createSale({ fiat_amount: '12.50', memo: 'coffee' })
		expect(calls[0]!.url).toBe('/api/v1/sales')
		expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ fiat_amount: '12.50', memo: 'coffee' })
	})

	it('long-polls with the known state', async () => {
		const { fetch, calls } = fakeFetch([json({ id: 's1', state: 'paid' })])
		const sale = await new PosClient({ fetch, token: 'tok' }).waitSale('s1', 'open')
		expect(sale.state).toBe('paid')
		expect(calls[0]!.url).toBe('/api/v1/sales/s1?wait=open')
	})

	it('pages history with before and limit', async () => {
		const { fetch, calls } = fakeFetch([json({ sales: [] }), json({ sales: [{ id: 'a' }] })])
		const client = new PosClient({ fetch, token: 'tok' })
		await client.sales()
		const page = await client.sales({ before: 'x', limit: 50 })
		expect(calls[0]!.url).toBe('/api/v1/sales')
		expect(calls[1]!.url).toBe('/api/v1/sales?before=x&limit=50')
		expect(page).toEqual([{ id: 'a' }])
	})

	it('requests the CSV export for a date range', async () => {
		const { fetch, calls } = fakeFetch([new Response('id\n', { status: 200 })])
		const blob = await new PosClient({ fetch, token: 'tok' }).salesCsv('2026-11-01', '2026-11-20')
		const range = localDayRange('2026-11-01', '2026-11-20')
		expect(calls[0]!.url).toBe(`/api/v1/sales.csv?${new URLSearchParams(range)}`)
		expect(await blob.text()).toBe('id\n')
	})

	it('cancels a sale', async () => {
		const { fetch, calls } = fakeFetch([json({ id: 's1', state: 'canceled' })])
		await new PosClient({ fetch, token: 'tok' }).cancelSale('s1')
		expect(calls[0]!.url).toBe('/api/v1/sales/s1/cancel')
		expect(calls[0]!.init.method).toBe('POST')
	})

	it('raises the server error message', async () => {
		const { fetch } = fakeFetch([json({ error: 'sale is not open' }, 409)])
		const err = await new PosClient({ fetch, token: 'tok' }).cancelSale('s1').catch((e) => e)
		expect(err).toBeInstanceOf(ApiError)
		expect(err.status).toBe(409)
		expect(err.message).toBe('sale is not open')
	})

	it('reports a revoked token once and throws', async () => {
		const onUnauthorized = vi.fn()
		const { fetch } = fakeFetch([json({ error: 'revoked' }, 401)])
		const err = await new PosClient({ fetch, token: 'tok', onUnauthorized }).terminal().catch((e) => e)
		expect(onUnauthorized).toHaveBeenCalledOnce()
		expect(err.isUnauthorized).toBe(true)
	})

	it('maps a network failure to status 0', async () => {
		const fetch = (async () => {
			throw new TypeError('Failed to fetch')
		}) as Fetch
		const err = await new PosClient({ fetch }).rate().catch((e) => e)
		expect(err).toBeInstanceOf(ApiError)
		expect(err.status).toBe(0)
	})
})

describe('localDayRange', () => {
	it('covers whole local days, end included', () => {
		const { from, to } = localDayRange('2026-11-20', '2026-11-20')
		expect(new Date(to).getTime() - new Date(from).getTime()).toBe(24 * 3600 * 1000)
		expect(new Date(from).getDate()).toBe(20)
	})
})
