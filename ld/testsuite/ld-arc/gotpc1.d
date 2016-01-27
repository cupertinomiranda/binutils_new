#source: gotpc1.s
#as: -mcpu=arc700
#ld: -q -T gotpc1.ld
#ld_after_inputfiles: tmpdir/libdummy.so.0
#objdump: -rd

.*:     file format .*


Disassembly of section \.text:

000100d4 <__start>:
   100d4:	2730 7f84 0000 011c 	ld	r4,\[pcl,0x11c\]
			100d8: R_ARC_GOTPC32	a_in_other_thread
   100dc:	1c00 0f80 0000 0001 	st[ \t]+0x1,\[r4,0\]
