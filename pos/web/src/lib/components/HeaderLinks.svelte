<script lang="ts">
	// The History and Settings icon buttons from bullnym's POS header.
	import { History, Settings } from 'lucide-svelte'

	let { history = true }: { history?: boolean } = $props()
</script>

<div class="flex items-center gap-2">
	{#if history}
		<a
			class="grid min-h-12 min-w-12 place-items-center rounded-md bg-[#eadfce] text-[#211f1a] dark:bg-[#2c2922] dark:text-[#fff6e8]"
			href="#/history"
			aria-label="Recent sales"
		>
			<History size={22} />
		</a>
	{/if}
	<a
		class="grid min-h-12 min-w-12 place-items-center rounded-md bg-[#eadfce] text-[#211f1a] dark:bg-[#2c2922] dark:text-[#fff6e8]"
		href="#/settings"
		aria-label="Settings"
	>
		<Settings size={22} />
	</a>
</div>
