/* ldsym.h -

   Copyright (C) 1991 Free Software Foundation, Inc.

   This file is part of GLD, the Gnu Linker.

   GLD is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 1, or (at your option)
   any later version.

   GLD is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GLD; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.  */

typedef struct user_symbol_struct
{
  /* Point to next symbol in this hash chain */
  struct user_symbol_struct *link;

  /* Name of this symbol.  */
  char *name;			

  /* Pointer to next symbol in order of symbol creation */
  struct user_symbol_struct *next; 

  /* Chain of asymbols we see from input files 
     note that we point to the entry in the canonical table of 
     the pointer to the asymbol, *not* the asymbol. This means
     that we can run back and fix all refs to point to the
     defs nearly for free.
     */
  asymbol **srefs_chain;
  asymbol **sdefs_chain;

  /* only ever point to the largest ever common definition -
   * all the rest are turned into refs 
   * scoms and sdefs are never != NULL at same time
   */
  asymbol **scoms_chain;

} ldsym_type;


PROTO(ldsym_type *, ldsym_get, (CONST char *));
PROTO(ldsym_type *, ldsym_get_soft, (CONST char *));
PROTO(void, ldsym_print_symbol_table,(void));
PROTO(void, ldsym_write, (void));
PROTO(boolean, ldsym_undefined, (CONST char *));
#define FOR_EACH_LDSYM(x)						\
	extern ldsym_type *symbol_head;					\
	ldsym_type *x;							\
	for (x = symbol_head; x != (ldsym_type *)NULL; x = x->next) 	


