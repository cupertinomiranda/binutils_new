#source: gc-sections1.s
#as: -mcpu=arc700
#ld: -shared --gc-sections --version-script=gc-sections1.ver
#objdump: -rd

.*:     file format .*


Disassembly of section \.text:

00000290 <bar>:
 290:	264a 7000.+
