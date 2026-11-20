<script lang="ts">
	// Ported from bullnym, which ported nostr-pos's QrCard: the same
	// qrcode-to-data-URL approach and card chrome. The QR encodes the full
	// BIP 321 URI, so one code serves every rail.
	import QRCode from 'qrcode'
	import { Copy } from 'lucide-svelte'
	import Button from './Button.svelte'

	let { value, label = 'Payment code' }: { value: string; label?: string } = $props()
	let dataUrl = $state('')
	let copied = $state(false)

	$effect(() => {
		const exactValue = value
		let current = true
		dataUrl = ''
		QRCode.toDataURL(exactValue, {
			margin: 4,
			width: 300,
			errorCorrectionLevel: 'L',
			color: { dark: '#000000', light: '#ffffff' },
		}).then((next) => {
			if (current) dataUrl = next
		})
		return () => {
			current = false
		}
	})

	async function copy() {
		try {
			await navigator.clipboard.writeText(value)
			copied = true
			setTimeout(() => (copied = false), 1500)
		} catch {
			/* clipboard unavailable */
		}
	}
</script>

<div
	class="mx-auto w-full max-w-sm rounded-lg border border-[#d7c8b4] bg-[#fffaf0] p-4 text-center shadow-sm dark:border-[#3a342a] dark:bg-[#211f1a]"
>
	{#if dataUrl}
		<img class="mx-auto aspect-square w-full max-w-[300px]" src={dataUrl} alt={label} />
	{:else}
		<div class="mx-auto aspect-square w-full max-w-[300px]"></div>
	{/if}
	<div class="mt-3 flex flex-wrap items-center justify-center gap-2">
		<Button variant="secondary" onclick={copy}>
			<Copy size={18} />
			{copied ? 'Copied' : 'Copy'}
		</Button>
	</div>
</div>
