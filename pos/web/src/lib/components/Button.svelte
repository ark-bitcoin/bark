<script lang="ts">
	// Ported from bullnym (pwa/lib/components/Button.svelte).
	import type { Snippet } from 'svelte'

	let {
		variant = 'primary',
		id,
		type = 'button',
		disabled = false,
		href,
		onclick,
		children,
	}: {
		variant?: 'primary' | 'secondary' | 'ghost' | 'danger'
		id?: string
		type?: 'button' | 'submit'
		disabled?: boolean
		href?: string
		onclick?: () => void
		children?: Snippet
	} = $props()

	const classes = $derived(
		[
			'inline-flex min-h-12 items-center justify-center gap-2 rounded-md px-5 py-3 font-display text-lg uppercase tracking-[0.06em] transition active:translate-y-px disabled:cursor-not-allowed disabled:opacity-50',
			variant === 'primary' && 'bg-[#B7000B] text-[#fffaf0] shadow-sm hover:bg-[#8f0009]',
			variant === 'secondary' &&
				'bg-[#eadfce] text-[#2d2418] hover:bg-[#dfd1bc] dark:bg-[#2c2922] dark:text-[#fbf0df]',
			variant === 'ghost' && 'text-[#2d2418] hover:bg-[#eadfce] dark:text-[#fbf0df] dark:hover:bg-[#2c2922]',
			variant === 'danger' && 'bg-[#a9362f] text-[#fffaf0] hover:bg-[#8c2d28]',
		]
			.filter(Boolean)
			.join(' '),
	)
</script>

{#if href}
	<a class={classes} {href}>{@render children?.()}</a>
{:else}
	<button {id} class={classes} {type} {disabled} {onclick}>{@render children?.()}</button>
{/if}
