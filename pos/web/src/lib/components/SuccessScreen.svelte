<script lang="ts">
	// Ported from bullnym (pwa/lib/components/SuccessScreen.svelte).
	import confetti from 'canvas-confetti'
	import Button from './Button.svelte'

	let {
		amountLabel,
		rail,
		actionLabel,
		onaction,
		secondaryLabel,
		onsecondary,
	}: {
		amountLabel: string
		rail: string | null
		actionLabel?: string
		onaction?: () => void
		secondaryLabel?: string
		onsecondary?: () => void
	} = $props()

	$effect(() => {
		const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
		if (!reduceMotion) {
			// The library's default instance is created with useWorker: true; its
			// blob: worker violates the page CSP (script-src 'self' is the
			// worker-src fallback), silently killing the burst. Create a
			// no-worker cannon instead — one-shot main-thread rendering is fine.
			const fire = confetti.create(null as unknown as HTMLCanvasElement, {
				resize: true,
				useWorker: false,
			})
			fire({
				particleCount: 120,
				spread: 70,
				origin: { y: 0.6 },
				colors: ['#B7000B', '#1f513a', '#fffaf0'],
			})
		}

		if ('vibrate' in navigator) {
			navigator.vibrate([200])
		}

		try {
			const ctx = new AudioContext()
			const osc = ctx.createOscillator()
			const gain = ctx.createGain()
			osc.type = 'sine'
			osc.frequency.value = 880
			gain.gain.setValueAtTime(0.15, ctx.currentTime)
			gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.4)
			osc.connect(gain)
			gain.connect(ctx.destination)
			osc.start()
			osc.stop(ctx.currentTime + 0.4)
			osc.onended = () => void ctx.close()
		} catch {
			/* audio unavailable: skip chime */
		}
	})
</script>

<div class="flex flex-col items-center gap-4 py-10">
	<div
		class="grid h-20 w-20 place-items-center rounded-full bg-[#d9f3df] text-4xl text-[#14522d] dark:bg-[#1f3d2a] dark:text-[#8bc8a4]"
	>
		✓
	</div>
	<p class="font-display text-6xl tabular-nums tracking-display leading-none text-[#211f1a] dark:text-[#fff6e8]">
		{amountLabel}
	</p>
	{#if rail}
		<p class="text-sm text-[#776b5a] dark:text-[#b9aa91]">{rail === 'Multiple rails' ? rail : `via ${rail}`}</p>
	{/if}
	{#if secondaryLabel && onsecondary}
		<Button variant="secondary" onclick={onsecondary}>{secondaryLabel}</Button>
	{/if}
	{#if actionLabel && onaction}
		<Button onclick={onaction}>{actionLabel}</Button>
	{/if}
</div>
