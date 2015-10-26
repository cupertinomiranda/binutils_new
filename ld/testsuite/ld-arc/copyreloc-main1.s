        .text
        .global main
main:
        ld 	r2,[pcl,@a_glob@gotpc]
        ld_s	r0,[r2]
        j_s 	[blink]
