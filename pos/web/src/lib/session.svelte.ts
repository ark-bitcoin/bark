// The device token lives in the installed app's own storage. On iOS a
// home-screen app does not share storage with Safari, so the app pairs
// after install, from the start_url that carries the code.
import { PosClient, type Terminal } from './api'

const TOKEN_KEY = 'scuttle-pos:token'

function readToken(): string | null {
	try {
		return localStorage.getItem(TOKEN_KEY)
	} catch {
		return null
	}
}

const state = $state<{ token: string | null; terminal: Terminal | null }>({
	token: readToken(),
	terminal: null,
})

export const session = {
	get token(): string | null {
		return state.token
	},
	get terminal(): Terminal | null {
		return state.terminal
	},
	set terminal(value: Terminal | null) {
		state.terminal = value
	},
	signIn(token: string): void {
		try {
			localStorage.setItem(TOKEN_KEY, token)
		} catch {
			/* storage unavailable: the token lasts for this page only */
		}
		state.token = token
	},
	signOut(): void {
		try {
			localStorage.removeItem(TOKEN_KEY)
		} catch {
			/* storage unavailable */
		}
		state.token = null
		state.terminal = null
	},
}

/** A client with the current device token. A 401 unpairs this device. */
export function client(): PosClient {
	return new PosClient({ token: state.token, onUnauthorized: () => session.signOut() })
}

/** The pairing code in "/pair/<code>", or null. */
export function pairingCodeFromPath(pathname: string): string | null {
	const match = pathname.match(/^\/pair\/([^/]+)\/?$/)
	return match ? decodeURIComponent(match[1]!) : null
}
