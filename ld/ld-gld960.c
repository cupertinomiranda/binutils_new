/* Copyright (C) 1991 Free Software Foundation, Inc.

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

/*
   $Id$ 

   $Log$
   Revision 1.3  1991/04/14 03:22:11  steve
   checkpoint before a merge

 * Revision 1.2  1991/03/22  23:02:30  steve
 * Brought up to sync with Intel again.
 *
 * Revision 1.3  1991/03/16  22:27:24  rich
 * fish
 *
 * Revision 1.2  1991/03/15  18:45:55  rich
 * foo
 *
 * Revision 1.1  1991/03/13  00:48:12  chrisb
 * Initial revision
 *
 * Revision 1.4  1991/03/10  09:31:19  rich
 *  Modified Files:
 *  	Makefile config.h ld-emul.c ld-emul.h ld-gld.c ld-gld960.c
 *  	ld-lnk960.c ld.h lddigest.c ldexp.c ldexp.h ldfile.c ldfile.h
 *  	ldgram.y ldinfo.h ldlang.c ldlang.h ldlex.h ldlex.l ldmain.c
 *  	ldmain.h ldmisc.c ldmisc.h ldsym.c ldsym.h ldversion.c
 *  	ldversion.h ldwarn.h ldwrite.c ldwrite.h y.tab.h
 *
 * As of this round of changes, ld now builds on all hosts of (Intel960)
 * interest and copy passes my copy test on big endian hosts again.
 *
 * Revision 1.3  1991/02/22  17:14:57  sac
 * Added RCS keywords and copyrights
 *
*/

/* 
 * emulate the Intels port of  gld
 */


#include "sysdep.h"
#include "bfd.h"


#include "ld.h"
#include "config.h"
#include "ld-emul.h"
#include "ldfile.h"
#include "ldmisc.h"


/* IMPORTS */
extern char *output_filename;
extern  boolean lang_float_flag;


extern enum bfd_architecture ldfile_output_architecture;
extern unsigned long ldfile_output_machine;
extern char *ldfile_output_machine_name;

extern bfd *output_bfd;



static void gld960_before_parse()
{
  char *env ;
  env =  getenv("G960LIB");
  if (env) {
    ldfile_add_library_path(env);
  }
  env = getenv("G960BASE");
  if (env) {
    ldfile_add_library_path(concat(env,"/lib",""));
  }
  ldfile_output_architecture = bfd_arch_i960;
}


static void 
gld960_after_parse()
{

}

static void
gld960_after_allocation()
{

}

static void
gld960_before_allocation()
{

}


static void
gld960_set_output_arch()
{
  /* Set the output architecture and machine if possible */
  unsigned long  machine = 0;
  bfd_set_arch_mach(output_bfd, ldfile_output_architecture, machine);
}

static char *
gld960_choose_target()
{
  char *from_outside = getenv(TARGET_ENVIRON);
  output_filename = "b.out";

  if (from_outside != (char *)NULL)
    return from_outside;
  return GLD960_TARGET;
}

static void
gld960_syslib()
{
  info("%S SYSLIB ignored\n");
}

static void
gld960_hll()
{
  info("%S HLL ignored\n");
}


static char *script = 
#include "ld-gld960.x"
;


static char *
gld960_get_script()
{
return script;
}

struct ld_emulation_xfer_struct ld_gld960_emulation = 
{
  gld960_before_parse,
  gld960_syslib,
  gld960_hll,
  gld960_after_parse,
  gld960_after_allocation,
  gld960_set_output_arch,
  gld960_choose_target,
  gld960_before_allocation,
  gld960_get_script,
};
