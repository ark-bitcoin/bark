<script lang="ts">
	import { ShieldCheck } from 'lucide-svelte'
	import BullFooter from '$lib/components/BullFooter.svelte'
</script>

<main class="grid min-h-screen place-items-center bg-[#f5f0e8] px-5 text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
	<section class="w-full max-w-md text-center">
		<ShieldCheck class="mx-auto text-[#776b5a] dark:text-[#b9aa91]" size={44} />
		<h1 class="mt-5 text-3xl font-black">This terminal is not active</h1>
		<p class="mt-3 text-[#776b5a] dark:text-[#b9aa91]">
			In the owner's wallet, choose Add terminal, then open the link on this device.
		</p>
		<BullFooter />
	</section>
</main>
