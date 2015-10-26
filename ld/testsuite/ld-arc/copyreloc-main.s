	.text
	.global	main
main:
        ld	r0,[@global_a]
        j_s	[blink]
