#source: gotpc1.s
#as: -mcpu=arc700
#ld: -q -T gotpc2.ld
#ld_after_inputfiles: tmpdir/libdummy.so.0
#objdump: -rd

.*:     file format elf32-littlearc


Disassembly of section \.text:

[0-9a-f]+ <__start>:
   [0-9a-f]+:	2730 7f84 ffff fffc 	ld[ \t]+r4,\[pcl,0xfffffffc\]
			10170: R_ARC_GOTPC32	a_in_other_thread
   [0-9a-f]+:	1c00 0f80 0000 0001 	st[ \t]+0x1,\[r4,0\]
