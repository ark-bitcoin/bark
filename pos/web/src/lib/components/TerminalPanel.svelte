<script lang="ts">
	// The warning and error panel from bullnym's PayFlow.
	import Button from './Button.svelte'

	let {
		icon,
		tone,
		title,
		detail,
		actionLabel,
		onaction,
	}: {
		icon: string
		tone: 'warn' | 'err'
		title: string
		detail: string
		actionLabel?: string
		onaction?: () => void
	} = $props()
</script>

<div class="mx-auto flex max-w-lg flex-col items-center gap-3 py-10 text-center">
	<div
		class={`grid h-20 w-20 place-items-center rounded-full text-4xl ${
			tone === 'err'
				? 'bg-[#ffe0d9] text-[#8c2d28] dark:bg-[#3a211e] dark:text-[#e8a49e]'
				: 'bg-[#fff0c7] text-[#725315] dark:bg-[#3a321f] dark:text-[#f0d38a]'
		}`}
	>
		{icon}
	</div>
	<p class="font-display text-4xl uppercase tracking-display leading-none">{title}</p>
	<p class="text-sm text-[#776b5a] dark:text-[#b9aa91]">{detail}</p>
	{#if actionLabel && onaction}
		<Button variant="secondary" onclick={onaction}>{actionLabel}</Button>
	{/if}
</div>
