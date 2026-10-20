<script lang="ts">
	import type { ModalProps } from '$lib/types/admin';

	let { title, onclose, children }: ModalProps = $props();
	let dialog = $state<HTMLDialogElement>();
	const headingId = $props.id();

	const closeDialog = (): void => {
		dialog?.close();
	};

	const handleBackdropPointerDown = (event: PointerEvent): void => {
		if (event.target !== dialog || dialog === undefined) return;
		const bounds = dialog.getBoundingClientRect();
		const clickedOutside =
			event.clientX < bounds.left ||
			event.clientX > bounds.right ||
			event.clientY < bounds.top ||
			event.clientY > bounds.bottom;
		if (clickedOutside) dialog.close();
	};

	const preventBackdropWheel = (event: WheelEvent): void => {
		if (event.target === dialog) event.preventDefault();
	};

	$effect(() => {
		const element = dialog;
		if (element === undefined) return;
		element.showModal();
		document.documentElement.classList.add('modal-open');
		document.body.classList.add('modal-open');
		return () => {
			if (element.open) element.close();
			if (document.querySelectorAll('dialog[open]').length === 0) {
				document.documentElement.classList.remove('modal-open');
				document.body.classList.remove('modal-open');
			}
		};
	});
</script>

<dialog
	bind:this={dialog}
	class="dashboard-dialog"
	aria-labelledby={headingId}
	onclose={onclose}
	onpointerdown={handleBackdropPointerDown}
	onwheel={preventBackdropWheel}
>
	<div class="row-between dialog-header">
		<h2 id={headingId}>{title}</h2>
		<button
			class="button"
			type="button"
			onclick={closeDialog}
			aria-label="Close dialog"
		>
			Close
		</button>
	</div>
	<div class="dialog-body">
		{@render children()}
	</div>
</dialog>
