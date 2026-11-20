import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import tailwindcss from '@tailwindcss/vite'
import { VitePWA } from 'vite-plugin-pwa'
import { resolve } from 'node:path'

// posd embeds dist/ and serves it at the site root. The SPA handles both
// "/" and "/pair/<code>", so assets use root-absolute URLs.
//
// posd serves the manifests itself: "/manifest.webmanifest" for a paired
// terminal and "/pair/<code>/manifest.webmanifest" for an install link, so
// the plugin must not emit one.
export default defineConfig({
	base: '/',
	plugins: [
		svelte(),
		tailwindcss(),
		VitePWA({
			manifest: false,
			injectRegister: null,
			registerType: 'autoUpdate',
			workbox: {
				globPatterns: ['**/*.{js,css,html,woff2,png,svg}'],
				navigateFallback: '/index.html',
				navigateFallbackDenylist: [/^\/api\//, /^\/\.well-known\//, /\.webmanifest$/],
				runtimeCaching: [],
			},
		}),
	],
	resolve: {
		alias: { $lib: resolve(__dirname, 'src/lib') },
	},
	build: {
		outDir: 'dist',
		assetsDir: 'assets',
	},
	server: {
		proxy: {
			'/api': 'http://127.0.0.1:3080',
			'/pair': {
				target: 'http://127.0.0.1:3080',
				bypass: (req) => (req.url?.endsWith('.webmanifest') ? undefined : '/index.html'),
			},
			'/manifest.webmanifest': 'http://127.0.0.1:3080',
		},
	},
})
