/* ARC-specific support for 32-bit ELF
   Copyright (C) 1994-2015 Free Software Foundation, Inc.
   Contributed by Cupertino Miranda (cmiranda@synopsys.com).

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.	*/

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "elf/arc.h"
#include "libiberty.h"
#include "opcode/arc-func.h"
#include <stdint.h>

#define printf(...)
#define fprintf(...)
#define ARC_DEBUG(...)
#define DEBUG(...) printf (__ARGV__)
#define DEBUG_ARC_RELOC(A)

struct arc_local_data
{
  bfd_vma	  sdata_begin_symbol_vma;
  asection	 *sdata_output_section;
  bfd_vma	  got_symbol_vma;
};

struct arc_local_data global_arc_data = {
  .sdata_begin_symbol_vma = 0,
  .sdata_output_section = NULL,
  .got_symbol_vma = 0,
};

struct dynamic_sections
{
  bfd_boolean	  initialized;
  asection	 *sgot;
  asection	 *srelgot;
  asection	 *sgotplt;
  asection	 *sdyn;
  asection	 *splt;
  asection	 *srelplt;
};

static struct dynamic_sections
arc_create_dynamic_sections (bfd * abfd, struct bfd_link_info *info);

enum dyn_section_types
{
  got = 0,
  relgot,
  gotplt,
  dyn,
  plt,
  relplt,
  DYN_SECTION_TYPES_END
};

const char *dyn_section_names[DYN_SECTION_TYPES_END] = {
  ".got",
  ".rela.got",
  ".got.plt",
  ".dynamic",
  ".plt",
  ".rela.plt"
};

/* The default symbols representing the init and fini dyn values */
/* TODO! Check what is the relation of those strings with arclinux.em
   and DT_INIT.  */
#define INIT_SYM_STRING "_init"
#define FINI_SYM_STRING "_fini"

char * init_str = INIT_SYM_STRING;
char * fini_str = FINI_SYM_STRING;


#define ARC_RELOC_HOWTO(TYPE, VALUE, SIZE, BITSIZE, RELOC_FUNCTION, OVERFLOW, FORMULA) \
      case VALUE: \
	return #TYPE; \
	break;

static ATTRIBUTE_UNUSED const char *
reloc_type_to_name (unsigned int type)
{
  switch (type)
    {
      #include "elf/arc-reloc.def"

      default:
	return "UNKNOWN";
	break;
    }
}
#undef ARC_RELOC_HOWTO

/* Try to minimize the amount of space occupied by relocation tables
   on the ROM (not that the ROM won't be swamped by other ELF overhead).  */

#define USE_REL 1

static ATTRIBUTE_UNUSED bfd_boolean
is_reloc_PC_relative (reloc_howto_type *howto)
{
  return (strstr (howto->name, "PC") != NULL) ? TRUE : FALSE;
}
static bfd_boolean
is_reloc_SDA_relative (reloc_howto_type *howto)
{
  return (strstr (howto->name, "SDA") != NULL) ? TRUE : FALSE;
}
static bfd_boolean
is_reloc_for_GOT (reloc_howto_type * howto)
{
  return (strstr (howto->name, "GOT") != NULL) ? TRUE : FALSE;
}
static		bfd_boolean
is_reloc_for_PLT (reloc_howto_type * howto)
{
  return (strstr (howto->name, "PLT") != NULL) ? TRUE : FALSE;
}

#define arc_bfd_get_8(A,B,C) bfd_get_8(A,B)
#define arc_bfd_get_16(A,B,C) bfd_get_16(A,B)
#define arc_bfd_put_8(A,B,C,D) bfd_put_8(A,B,C)
#define arc_bfd_put_16(A,B,C,D) bfd_put_16(A,B,C)

static long
arc_bfd_get_32 (bfd * abfd, void *loc, asection * input_section)
{
  long insn = bfd_get_32 (abfd, loc);

  if (!bfd_big_endian (abfd)
     && elf_elfheader (abfd)->e_machine != EM_ARC && input_section
     && (input_section->flags & SEC_CODE))
    insn = ((0x0000fffff & insn) << 16) | ((0xffff0000 & insn) >> 16);

  return insn;
}
static void
arc_bfd_put_32 (bfd * abfd, long insn, void *loc, asection * input_section)
{
  if (!bfd_big_endian (abfd)
     && elf_elfheader (abfd)->e_machine != EM_ARC && input_section
     && (input_section->flags & SEC_CODE))
    insn = ((0x0000fffff & insn) << 16) | ((0xffff0000 & insn) >> 16);

  bfd_put_32 (abfd, insn, loc);
}

static bfd_reloc_status_type
arc_elf_reloc (bfd *abfd ATTRIBUTE_UNUSED,
	       arelent *reloc_entry,
	       asymbol *symbol_in,
	       void *data ATTRIBUTE_UNUSED,
	       asection *input_section,
	       bfd *output_bfd,
	       char ** error_message ATTRIBUTE_UNUSED)
{
  if (output_bfd != NULL)
    {
      reloc_entry->address += input_section->output_offset;

      /* In case of relocateable link and if the reloc is against a
	 section symbol, the addend needs to be adjusted according to
	 where the section symbol winds up in the output section.  */
      if ((symbol_in->flags & BSF_SECTION_SYM) && symbol_in->section)
	reloc_entry->addend += symbol_in->section->output_offset;

      return bfd_reloc_ok;
    }

  return bfd_reloc_continue;
}


#define ARC_RELOC_HOWTO(TYPE, VALUE, SIZE, BITSIZE, RELOC_FUNCTION, OVERFLOW, FORMULA) \
  TYPE = VALUE,
enum howto_list {
#include "elf/arc-reloc.def"
  HOWTO_LIST_LAST
};
#undef ARC_RELOC_HOWTO

#define ARC_RELOC_HOWTO(TYPE, VALUE, RSIZE, BITSIZE, RELOC_FUNCTION, OVERFLOW, FORMULA) \
  [TYPE] = HOWTO (R_##TYPE, 0, RSIZE, BITSIZE, FALSE, 0, complain_overflow_##OVERFLOW, arc_elf_reloc, #TYPE, FALSE, 0, 0, FALSE),

static struct reloc_howto_struct elf_arc_howto_table[] = {
#include "elf/arc-reloc.def"
/* This reloc does nothing. Currently kept as an example.
 HOWTO (R_ARC_NONE, // Type.
    0, // Rightshift.
    2, // Size (0 = byte, 1 = short, 2 = long).
    32, // Bitsize.
    FALSE, // PC_relative.
    0, // Bitpos.
    complain_overflow_bitfield, // Complain_on_overflow.
    bfd_elf_generic_reloc, // Special_function.
    "R_ARC_NONE", // Name.
    TRUE, // Partial_inplace.
    0, // Src_mask.
    0, // Dst_mask.
    FALSE), // PCrel_offset.
*/
};
#undef ARC_RELOC_HOWTO

static void arc_elf_howto_init (void)
{
#define ARC_RELOC_HOWTO(TYPE, VALUE, SIZE, BITSIZE, RELOC_FUNCTION, OVERFLOW, FORMULA) \
  elf_arc_howto_table[TYPE].pc_relative = (strstr (#FORMULA, " P ") != NULL);

  #include "elf/arc-reloc.def"
}
#undef ARC_RELOC_HOWTO


#define ARC_RELOC_HOWTO(TYPE, VALUE, SIZE, BITSIZE, RELOC_FUNCTION, OVERFLOW, FORMULA) \
  [TYPE] = VALUE,
const int	howto_table_lookup[] = {
  #include "elf/arc-reloc.def"
};
#undef ARC_RELOC_HOWTO

#define ARC_ELF_HOWTO(r_type) \
  (&elf_arc_howto_table[r_type])

/* Map BFD reloc types to ARC ELF reloc types.	*/

struct arc_reloc_map
{
  bfd_reloc_code_real_type bfd_reloc_val;
  unsigned char   elf_reloc_val;
};

#define ARC_RELOC_HOWTO(TYPE, VALUE, SIZE, BITSIZE, RELOC_FUNCTION, OVERFLOW, FORMULA) \
  { BFD_RELOC_##TYPE, R_##TYPE },
static const struct arc_reloc_map arc_reloc_map[] = {
  #include "elf/arc-reloc.def"
  {BFD_RELOC_8,  R_ARC_8},
  {BFD_RELOC_16, R_ARC_16},
  {BFD_RELOC_24, R_ARC_24},
  {BFD_RELOC_32, R_ARC_32},
};
#undef ARC_RELOC_HOWTO

static reloc_howto_type *
bfd_elf32_bfd_reloc_type_lookup (bfd * abfd ATTRIBUTE_UNUSED,
				 bfd_reloc_code_real_type code)
{
  unsigned int	  i;
  static int fully_initialized = FALSE;
  if (fully_initialized == FALSE)
    {
      arc_elf_howto_init ();
      fully_initialized = TRUE; // TODO: CHECK THIS IF IT STOPS WORKING
    }

  for (i = ARRAY_SIZE (arc_reloc_map); i--;)
    {
      if (arc_reloc_map[i].bfd_reloc_val == code)
	return elf_arc_howto_table + arc_reloc_map[i].elf_reloc_val;
    }

  return NULL;
}

static reloc_howto_type *
bfd_elf32_bfd_reloc_name_lookup (bfd * abfd ATTRIBUTE_UNUSED, const char *r_name)
{
  unsigned int	  i;

  for (i = 0; i < sizeof (elf_arc_howto_table) / sizeof (elf_arc_howto_table[0]); i++)
    {
      if (elf_arc_howto_table[i].name != NULL
	  && strcasecmp (elf_arc_howto_table[i].name, r_name) == 0)
	    return &elf_arc_howto_table[i];
    }

  return NULL;
}


/* Set the howto pointer for an ARC ELF reloc.	*/
static void
arc_info_to_howto_rel (bfd * abfd ATTRIBUTE_UNUSED,
		       arelent * cache_ptr, Elf_Internal_Rela * dst)
{
  unsigned int	  r_type;

  r_type = ELF32_R_TYPE (dst->r_info);
  BFD_ASSERT (r_type < (unsigned int) R_ARC_max);
  cache_ptr->howto = &elf_arc_howto_table[r_type];
}

/* Set the right machine number for an ARC ELF file.  */
static		bfd_boolean
arc_elf_object_p (bfd * abfd)
{
  /* Make sure this is initialised, or you'll have the potential of passing
   * garbage---or misleading values---into the call to
   * bfd_default_set_arch_mach ().  */
  int		  mach = bfd_mach_arc_arc700;
  unsigned long   arch = elf_elfheader (abfd)->e_flags & EF_ARC_MACH_MSK;
  unsigned	  e_machine = elf_elfheader (abfd)->e_machine;

  if (e_machine == EM_ARCOMPACT || e_machine == EM_ARCV2)
    {
      switch (arch)
	{
	  case E_ARC_MACH_ARC600:
	    mach = bfd_mach_arc_arc600;
	    break;
	  case E_ARC_MACH_ARC601:
	    mach = bfd_mach_arc_arc601;
	    break;
	  case E_ARC_MACH_ARC700:
	    mach = bfd_mach_arc_arc700;
	    break;
	  case EF_ARC_CPU_ARCV2HS:
	  case EF_ARC_CPU_ARCV2EM:
	    mach = bfd_mach_arc_arcv2;
	    break;
	  default:
	    mach = bfd_mach_arc_arc700;
	    break;
	}
    }
  else
    {
      /* This is an old ARC, throw a warning. Probably the best is to
       * return FALSE.  */
      (*_bfd_error_handler)
	  (_("Warning: unset or old architecture flags. \n"
	     "	       Use default machine.\n"));
    }

  return bfd_default_set_arch_mach (abfd, bfd_arch_arc, mach);
}

/* The final processing done just before writing out an ARC ELF object file.
   This gets the ARC architecture right based on the machine number.  */

static void
arc_elf_final_write_processing (bfd * abfd, bfd_boolean linker ATTRIBUTE_UNUSED)
{
  unsigned long   val;

  switch (bfd_get_mach (abfd))
    {
      case bfd_mach_arc_arc600:
	val = E_ARC_MACH_ARC600;
	break;
      default:
      case bfd_mach_arc_arc601:
	val = E_ARC_MACH_ARC601;
	break;
      case bfd_mach_arc_arc700:
	val = E_ARC_MACH_ARC700;
	break;
      case bfd_mach_arc_arcv2:
	val = EF_ARC_CPU_ARCV2HS;
	/* TODO: Check validity of this. It can also be ARCV2EM here.
	 * Previous version sets the e_machine here.  */
	break;

  }
  elf_elfheader (abfd)->e_flags &= ~EF_ARC_MACH;
  elf_elfheader (abfd)->e_flags |= val;

  /* Record whatever is the current syscall ABI version */
  elf_elfheader (abfd)->e_flags |= E_ARC_OSABI_CURRENT;
}

#define BFD_DEBUG_PIC(...)

struct arc_relocation_data
{
  bfd_vma	  reloc_offset;
  bfd_vma	  reloc_addend;
  bfd_vma	  got_offset_value;

  bfd_vma	  sym_value;
  asection	 *sym_section;

  reloc_howto_type *howto;

  asection	 *input_section;

  bfd_vma	  sdata_begin_symbol_vma;
  bfd_boolean	  sdata_begin_symbol_vma_set;
  bfd_vma	  got_symbol_vma;

  bfd_boolean	  should_relocate;
};

static void
debug_arc_reloc (struct arc_relocation_data reloc_data)
{
  fprintf (stderr, "Reloc type=%s, should_relocate = %s\n",
	   reloc_data.howto->name,
	   reloc_data.should_relocate ? "true" : "false");
  fprintf (stderr, "  offset = 0x%x, addend = 0x%x\n",
	   (unsigned int) reloc_data.reloc_offset,
	   (unsigned int) reloc_data.reloc_addend);
  fprintf (stderr, " Symbol:\n");
  fprintf (stderr, "  value = 0x%08x\n",
	   (unsigned int) reloc_data.sym_value);
  if (reloc_data.sym_section != NULL)
    {
      fprintf (stderr, "IN IF\n");
      fprintf (stderr,
	       "  section name = %s, output_offset 0x%08x",
	       reloc_data.sym_section->name,
	       (unsigned int) reloc_data.sym_section->output_offset);
      if(reloc_data.sym_section->output_section != NULL)
	fprintf (stderr,
		 ", output_section->vma = 0x%08x",
		 (unsigned int) reloc_data.sym_section->output_section->vma);

      fprintf (stderr, "\n");
    }
  else
    fprintf (stderr, "	symbol section is NULL\n");

  fprintf (stderr, " Input_section:\n");
  if (reloc_data.input_section != NULL)
    {
      fprintf (stderr,
	       "  section name = %s, output_offset 0x%08x, output_section->vma = 0x%08x\n",
	       reloc_data.input_section->name,
	       (unsigned int) reloc_data.input_section->output_offset,
	       (unsigned int) reloc_data.input_section->output_section->vma);
      fprintf (stderr, "  changed_address = 0x%08x\n",
	       (unsigned int) (reloc_data.input_section->output_section->vma +
	       reloc_data.input_section->output_offset +
	       reloc_data.reloc_offset));
    }
  else
    fprintf (stderr, "	input section is NULL\n");
}

#define TCB_SIZE (8)

#define S (reloc_data.sym_value \
	   + (reloc_data.sym_section->output_section != NULL ? \
	     (reloc_data.sym_section->output_offset \
  	      + reloc_data.sym_section->output_section->vma) : 0) \
	  )
#define L (reloc_data.sym_value \
	   + (reloc_data.sym_section->output_section != NULL ? \
	     (reloc_data.sym_section->output_offset \
	      + reloc_data.sym_section->output_section->vma) : 0) \
	  )
#define A (reloc_data.reloc_addend)
#define B (0)
#define G (reloc_data.got_offset_value)
#define GOT (reloc_data.got_symbol_vma + 12)
#define MES (0)
	/* P: relative offset to PCL The offset should be to the current location
	 * aligned to 32 bits. */
#define P ( \
	    ( \
	      (reloc_data.sym_section->output_section != NULL ? \
		reloc_data.input_section->output_section->vma : 0) \
	      + reloc_data.input_section->output_offset \
	      + (reloc_data.reloc_offset - (bitsize >= 32 ? 4 : 0)) \
	    ) & ~0x3)
#define SECTSTAR (reloc_data.input_section->output_offset)
#define SECTSTART (reloc_data.input_section->output_offset)
#define _SDA_BASE_ (reloc_data.sdata_begin_symbol_vma)	
#define TLS_REL (elf_hash_table(info)->tls_sec->output_section->vma)
#define none (0)

#define PRINT_DEBUG_RELOC_INFO_BEFORE \
      printf ("FORMULA = " #FORMULA "\n"); \
      printf ("S = 0x%x\n", S); \
      printf ("A = 0x%x\n", A); \
      printf ("L = 0x%x\n", L); \
      /* printf ("P1 = 0x%x\n", ((reloc_data.input_section->output_section->vma + reloc_data.input_section->output_offset) + reloc_data.reloc_offset)); */ \
      /* printf ("PCL = 0x%x\n", ((reloc_data.input_section->output_section->vma + reloc_data.input_section->output_offset) + reloc_data.reloc_offset) & ~0x3); */ \
      printf ("PCL = 0x%x\n", P); \
      printf ("P = 0x%x\n", P); \
      printf ("G = 0x%x\n", G); \
      printf ("SDA_OFFSET = 0x%x\n", _SDA_BASE_); \
      printf ("SDA_SET = %d\n", reloc_data.sdata_begin_symbol_vma_set); \
      printf ("GOT_OFFSET = 0x%x\n", GOT); \
      relocation = FORMULA ; \
      printf ("relocation = 0x%08x\n", relocation); \
      printf ("before = 0x%08x\n", (unsigned int) insn); \
      printf ("data   = 0x%08x (%u) (%d)\n", (unsigned int) relocation, (unsigned int) relocation, (int) relocation); 

#define PRINT_DEBUG_RELOC_INFO_AFTER \
-      printf ("after  = 0x%08x\n", (unsigned int) insn); 

#define ARC_RELOC_HOWTO(TYPE, VALUE, SIZE, BITSIZE, RELOC_FUNCTION, OVERFLOW, FORMULA) \
  case R_##TYPE: \
    { \
      bfd_vma bitsize ATTRIBUTE_UNUSED = BITSIZE; \
      relocation = FORMULA  ; \
      printf ("FORMULA = " #FORMULA "\n"); \
      printf ("S = 0x%x\n", S); \
      printf ("A = 0x%x\n", A); \
      printf ("L = 0x%x\n", L); \
      printf ("P1 = 0x%x\n", ((reloc_data.input_section->output_section->vma + reloc_data.input_section->output_offset) + reloc_data.reloc_offset));  \
      printf ("PCL = 0x%x\n", ((reloc_data.input_section->output_section->vma + reloc_data.input_section->output_offset) + reloc_data.reloc_offset) & ~0x3); \
      printf ("PCL = 0x%x\n", P); \
      printf ("P = 0x%x\n", P); \
      printf ("G = 0x%x\n", G); \
      printf ("SDA_OFFSET = 0x%x\n", _SDA_BASE_); \
      printf ("SDA_SET = %d\n", reloc_data.sdata_begin_symbol_vma_set); \
      printf ("GOT_OFFSET = 0x%x\n", GOT); \
      relocation = FORMULA ; \
      printf ("relocation = 0x%08x\n", relocation); \
      printf ("before = 0x%08x\n", (unsigned int) insn); \
      printf ("data   = 0x%08x (%u) (%d)\n", (unsigned int) relocation, (unsigned int) relocation, (int) relocation); \
      insn = RELOC_FUNCTION (insn, relocation); \
      printf ("after  = 0x%08x\n", (unsigned int) insn); \
    } \
    break;

static bfd_reloc_status_type
arc_do_relocation (bfd_byte * contents, struct arc_relocation_data reloc_data, struct bfd_link_info *info)
{
  bfd_vma relocation = 0;
  bfd_vma insn;
  bfd_vma orig_insn ATTRIBUTE_UNUSED;

  if (reloc_data.should_relocate == FALSE)
    return bfd_reloc_notsupported;

  switch (reloc_data.howto->size)
    {
      case 2:
	insn = arc_bfd_get_32 (reloc_data.input_section->owner, 
			       contents + reloc_data.reloc_offset, 
			       reloc_data.input_section);
	break;
      case 1:
      case 0:
	insn = arc_bfd_get_16 (reloc_data.input_section->owner, 
			       contents + reloc_data.reloc_offset, 
			       reloc_data.input_section);
	break;
      default:
	insn = 0;
	BFD_ASSERT (0);
	break;
    }

  orig_insn = insn;

  switch (reloc_data.howto->type)
    {
      #include "elf/arc-reloc.def"

      default:
	BFD_ASSERT (0);
	break;
    }

  /* Check for relocation overflow.  */
  if (reloc_data.howto->complain_on_overflow != complain_overflow_dont)
    {
      bfd_reloc_status_type flag;
      flag = bfd_check_overflow (reloc_data.howto->complain_on_overflow,
				 reloc_data.howto->bitsize,
				 reloc_data.howto->rightshift,
				 bfd_arch_bits_per_address (reloc_data.input_section->owner),
				 relocation);

#undef DEBUG_ARC_RELOC
#define DEBUG_ARC_RELOC(A) debug_arc_reloc (A)
      if (flag != bfd_reloc_ok)
	{
	  fprintf (stderr, "Relocation overflows !!!!\n");

	  DEBUG_ARC_RELOC (reloc_data);

	  fprintf (stderr,
		  "Relocation value = signed -> %d, unsigned -> %u, hex -> (0x%08x)\n",
		  (int) relocation,
		  (unsigned int) relocation,
		  (unsigned int) relocation);
	  return flag;
	}
    }
#undef DEBUG_ARC_RELOC
#define DEBUG_ARC_RELOC(A)

  switch (reloc_data.howto->size)
    {
      case 2:
	arc_bfd_put_32 (reloc_data.input_section->owner, insn,
		       contents + reloc_data.reloc_offset,
		       reloc_data.input_section);
	break;
      case 1:
      case 0:
	arc_bfd_put_16 (reloc_data.input_section->owner, insn,
		       contents + reloc_data.reloc_offset,
		       reloc_data.input_section);
	break;
      default:
	ARC_DEBUG ("size = %d\n", reloc_data.howto->size);
	BFD_ASSERT (0);
	break;
    }

  return bfd_reloc_ok;
}
#undef S
#undef A
#undef B
#undef G
#undef GOT
#undef L
#undef MES
#undef P
#undef SECTSTAR
#undef SECTSTART
#undef _SDA_BASE_
#undef none

#undef ARC_RELOC_HOWTO

static bfd_vma *
arc_get_local_got_offsets (bfd * abfd)
{
  static bfd_vma *local_got_offsets = NULL;
  if (local_got_offsets == NULL)
    {
      size_t	      size;
      register unsigned int i;

      Elf_Internal_Shdr *symtab_hdr = &((elf_tdata (abfd))->symtab_hdr);
      size = symtab_hdr->sh_info * sizeof (bfd_vma);
      local_got_offsets = (bfd_vma *) bfd_alloc (abfd, size);
      if (local_got_offsets == NULL)
	return FALSE;
      elf_local_got_offsets (abfd) = local_got_offsets;
      for (i = 0; i < symtab_hdr->sh_info; i++)
	local_got_offsets[i] = (bfd_vma) - 1;
    }

  return local_got_offsets;
}


/* Relocate an arc ELF section.  */
/* Function : elf_arc_relocate_section
 * Brief    : Relocate an arc section, by handling all the relocations
 *	     appearing in that section.
 * Args     : output_bfd    : The bfd being written to.
 *	      info	    : Link information.
 *	      input_bfd     : The input bfd.
 *	      input_section : The section being relocated.
 *	      contents	    : contents of the section being relocated.
 *	      relocs	    : List of relocations in the section.
 *	      local_syms    : is a pointer to the swapped in local symbols.
 *	      local_section : is an array giving the section in the input file
 *			      corresponding to the st_shndx field of each
 *			      local symbol.
 * Returns  :
 */
static		bfd_boolean
elf_arc_relocate_section (bfd * output_bfd,
			  struct bfd_link_info *info,
			  bfd * input_bfd,
			  asection * input_section,
			  bfd_byte * contents,
			  Elf_Internal_Rela * relocs,
			  Elf_Internal_Sym * local_syms,
			  asection ** local_sections)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  bfd_vma	 *local_got_offsets;
  Elf_Internal_Rela *rel;
  Elf_Internal_Rela *relend;

  symtab_hdr = &((elf_tdata (input_bfd))->symtab_hdr);
  sym_hashes = elf_sym_hashes (input_bfd);

  rel = relocs;
  relend = relocs + input_section->reloc_count;
  for (; rel < relend; rel++)
    {
      enum elf_arc_reloc_type r_type;
      reloc_howto_type *howto;
      unsigned long   r_symndx;
      struct elf_link_hash_entry *h;
      Elf_Internal_Sym *sym;
      asection	     *sec;

      struct arc_relocation_data reloc_data = {
	.reloc_offset = 0,	/* bfd_vma reloc_offset; */
	.reloc_addend = 0,	/* bfd_vma reloc_addend; */
	.got_offset_value = 0,	/* bfd_vma got_offset_value; */
	.sym_value = 0,		/* bfd_vma sym_value; */
	.sym_section = NULL,	/* asection *sym_section; */
	.howto = NULL,		/* reloc_howto_type *howto; */
	.input_section = NULL,	/* asection *input_section; */
	.sdata_begin_symbol_vma = 0,	/* bfd_vma sdata_begin_symbol_vma; */
	.sdata_begin_symbol_vma_set = FALSE,	/* bfd_vma sdata_begin_symbol_vma_set; */
	.got_symbol_vma = 0,	/* bfd_vma got_symbol_vma; */
	.should_relocate = FALSE	/* bfd_boolean should_relocate; */
      };


      struct elf_link_hash_entry *h2;
      h2 = elf_link_hash_lookup (elf_hash_table (info), "__SDATA_BEGIN__",
				 FALSE, FALSE, TRUE);

      if (reloc_data.sdata_begin_symbol_vma_set == FALSE
	    && h2 != NULL && h2->root.type != bfd_link_hash_undefined)
	{
	  reloc_data.sdata_begin_symbol_vma =
	    (h2->root.u.def.value +
	     h2->root.u.def.section->output_section->vma);
	  reloc_data.sdata_begin_symbol_vma_set = TRUE;
	}

      h2 = elf_link_hash_lookup (elf_hash_table (info),
				 "_GLOBAL_OFFSET_TABLE_", FALSE, FALSE,
				 TRUE);
      if (h2 != NULL && h2->root.type != bfd_link_hash_undefined)
	{
	  reloc_data.got_symbol_vma =
	      (h2->root.u.def.value +
	       h2->root.u.def.section->output_section->vma);
	}

      r_type = ELF32_R_TYPE (rel->r_info);

      if (r_type >= (int) R_ARC_max)
	{
	  bfd_set_error (bfd_error_bad_value);
	  return FALSE;
	}
      howto = &elf_arc_howto_table[r_type];

      reloc_data.input_section = input_section;
      reloc_data.howto = howto;
      reloc_data.reloc_offset = rel->r_offset;
      reloc_data.reloc_addend = rel->r_addend;

      r_symndx = ELF32_R_SYM (rel->r_info);

      /* This is a final link.	*/
      h = NULL;
      sym = NULL;
      sec = NULL;

      if (r_symndx < symtab_hdr->sh_info) /* A local symbol.  */
	{
	  sym = local_syms + r_symndx;
	  sec = local_sections[r_symndx];

	  reloc_data.sym_value = sym->st_value;
	  reloc_data.sym_section = sec;

	  if (is_reloc_for_GOT (reloc_data.howto))
	    {
	      local_got_offsets = arc_get_local_got_offsets (output_bfd);
	      reloc_data.got_offset_value = local_got_offsets[r_symndx];
	    }

	  reloc_data.should_relocate = TRUE;
	}
      else /* Global symbol.   */
	{
	  /* get the symbol's entry in the symtab */
	  h = sym_hashes[r_symndx - symtab_hdr->sh_info];

	  while (h->root.type == bfd_link_hash_indirect
		 || h->root.type == bfd_link_hash_warning)
	    h = (struct elf_link_hash_entry *) h->root.u.i.link;

	  BFD_ASSERT ((h->dynindx == -1) >= (h->forced_local != 0));
	  /* if we have encountered a definition for this symbol */
	  if (h->root.type == bfd_link_hash_defined
	      || h->root.type == bfd_link_hash_defweak)
	    {
	      reloc_data.sym_value = h->root.u.def.value;
	      reloc_data.sym_section = h->root.u.def.section;

	      reloc_data.should_relocate = TRUE;

	      if (is_reloc_for_GOT (howto) && bfd_link_pic (info))
		{
		  struct dynamic_sections ds =
		  arc_create_dynamic_sections (output_bfd, info);

		  /* TODO: Change it to use arc_do_relocation with ARC_32
		   * reloc. Try to use ADD_RELA macro. */
		  bfd_vma relocation =
		    reloc_data.sym_value + reloc_data.reloc_addend
		    + (reloc_data.sym_section->output_section != NULL ? 
			(reloc_data.sym_section->output_offset
		         + reloc_data.sym_section->output_section->vma)
		      : 0);

		  bfd_put_32 (output_bfd, relocation, ds.sgot->contents + h->got.offset);
		}
	    }
	  else if (h->root.type == bfd_link_hash_undefweak)
	    {
	      /* Is weak symbol and has no definition.	*/
	      if(!is_reloc_for_GOT(howto))
		continue;
	      else
		{
		  struct dynamic_sections ds = 
		      arc_create_dynamic_sections (output_bfd, info);
		  reloc_data.sym_value = h->root.u.def.value;
		  reloc_data.sym_section = ds.sgot;
	      	  reloc_data.should_relocate = TRUE;
	      	}
	    }
	  else
	    {
	      if (is_reloc_for_GOT (howto))
		{
		  struct dynamic_sections ds =
		      arc_create_dynamic_sections (output_bfd, info);

		  reloc_data.sym_value = h->root.u.def.value;
		  reloc_data.sym_section = ds.sgot;

		  reloc_data.should_relocate = TRUE;
		}
	      else if (is_reloc_for_PLT (howto))
		{
		  struct dynamic_sections ds =
		    arc_create_dynamic_sections (output_bfd, info);

		  reloc_data.sym_value = h->plt.offset;
		  reloc_data.sym_section = ds.splt;

		  reloc_data.should_relocate = TRUE;
		}
	      else if (!(*info->callbacks->undefined_symbol)(
			    info,
			    h->root.root.string,
			    input_bfd,
			    input_section,
			    rel->r_offset,
			    !bfd_link_pic (info))
		      )
		{
		  return FALSE;
		}
	    }

	  reloc_data.got_offset_value = h->got.offset;

	}

      if (is_reloc_SDA_relative (howto) && reloc_data.sdata_begin_symbol_vma_set == FALSE)
	{
	  (*_bfd_error_handler)
	      ("Error: Linker symbol __SDATA_BEGIN__ not found");
	  bfd_set_error (bfd_error_bad_value);
	  return FALSE;
	}

      DEBUG_ARC_RELOC (reloc_data);
      if (arc_do_relocation (contents, reloc_data, info) != bfd_reloc_ok)
	return FALSE;
    }

  return TRUE;
}

static struct dynamic_sections
arc_create_dynamic_sections (bfd * abfd, struct bfd_link_info *info)
{
  static bfd	 *dynobj = NULL;
  struct dynamic_sections ds = {
	.initialized = FALSE,
	.sgot = NULL,
	.srelgot = NULL,
	.sgotplt = NULL,
	.sdyn = NULL,
	.splt = NULL,
	.srelplt = NULL
  };

  dynobj = (elf_hash_table (info))->dynobj;
  if (dynobj == NULL)
    {
      elf_hash_table (info)->dynobj = dynobj = abfd;
      if (!_bfd_elf_create_got_section (dynobj, info))
	BFD_ASSERT(0);
      if(!_bfd_elf_create_dynamic_sections (dynobj, info))
	BFD_ASSERT(0);
    }

  ds.sgot = bfd_get_section_by_name (dynobj, ".got");
  ds.srelgot = bfd_get_section_by_name (dynobj, ".rela.got");
  if (ds.srelgot == NULL)
    {
      ds.srelgot = bfd_make_section_with_flags (dynobj, ".rela.got",
					 SEC_ALLOC
					 | SEC_LOAD
					 | SEC_HAS_CONTENTS
					 | SEC_IN_MEMORY
					 | SEC_LINKER_CREATED
					 | SEC_READONLY);
      if (ds.srelgot == NULL
	  || !bfd_set_section_alignment (dynobj, ds.srelgot, 2))
	return ds;
    }
  ds.sgotplt = bfd_get_section_by_name (dynobj, ".got.plt");

  ds.sdyn = bfd_get_section_by_name (dynobj, ".dynamic");
  ds.splt = bfd_get_section_by_name (dynobj, ".plt");
  ds.srelplt = bfd_get_section_by_name (dynobj, ".rela.plt");

  ds.initialized = TRUE;

  return ds;
}

#define ADD_SYMBOL_REF_SEC_AND_RELOC(SECNAME, COND_FOR_RELOC, H) \
  ds.s##SECNAME->size; \
  { \
    if (COND_FOR_RELOC) ds.srel##SECNAME->size += sizeof (Elf32_External_Rela); \
    if (H)  \
      if (h->dynindx == -1 && !h->forced_local) \
	if (! bfd_elf_link_record_dynamic_symbol (info, H)) \
	  return FALSE; \
    ds.s##SECNAME->size += 4; \
  }

static bfd_boolean
elf_arc_check_relocs (bfd * abfd,
		     struct bfd_link_info *info,
		     asection * sec, const Elf_Internal_Rela * relocs)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  bfd_vma	 *local_got_offsets;
  const Elf_Internal_Rela *rel;
  const Elf_Internal_Rela *rel_end;
  bfd *dynobj ATTRIBUTE_UNUSED;

  dynobj = (elf_hash_table (info))->dynobj;
  symtab_hdr = &((elf_tdata (abfd))->symtab_hdr);
  sym_hashes = elf_sym_hashes (abfd);
  local_got_offsets = arc_get_local_got_offsets (abfd);

  struct dynamic_sections ds = arc_create_dynamic_sections (abfd, info);

  rel_end = relocs + sec->reloc_count;
  for (rel = relocs; rel < rel_end; rel++)
    {
      enum elf_arc_reloc_type r_type;
      reloc_howto_type *howto;
      unsigned long   r_symndx;
      struct elf_link_hash_entry *h;

      r_type = ELF32_R_TYPE (rel->r_info);

      if (r_type >= (int) R_ARC_max)
	{
	  bfd_set_error (bfd_error_bad_value);
	  return FALSE;
	}
      howto = &elf_arc_howto_table[r_type];

      /* Load symbol information */
      r_symndx = ELF32_R_SYM (rel->r_info);
      if (r_symndx < symtab_hdr->sh_info)
	h = NULL;	/* Is a local symbol */
      else
	h = sym_hashes[r_symndx - symtab_hdr->sh_info]; /* Global
							 * one */

      if (is_reloc_for_PLT (howto) == TRUE)
	{
	  if (h == NULL)
		continue;
	  else
		h->needs_plt = 1;
	}

      if (is_reloc_for_GOT (howto) == TRUE)
	{
	  if (h == NULL)
	    {
	      /* Local symbol */
	      local_got_offsets[r_symndx] =
		ADD_SYMBOL_REF_SEC_AND_RELOC (got, bfd_link_pic (info), NULL);
	    }
	  else
	    {
	      /* Global symbol */
	      h = sym_hashes[r_symndx - symtab_hdr->sh_info];
	      h->got.offset =
		ADD_SYMBOL_REF_SEC_AND_RELOC (got, TRUE, h);
	    }
	}
    }

  return TRUE;
}

#define ELF_DYNAMIC_INTERPRETER  "/sbin/ld-uClibc.so"

/* Instructions appear in memory as a sequence of half-words (16 bit);
   individual half-words are represented on the target in target byte order.
   We use 'unsigned short' on the host to represent the PLT templates,
   and translate to target byte order as we copy to the target.  */
typedef uint16_t insn_hword;

#include "arc-plt.h"

static struct plt_version_t *
arc_get_plt_version (bfd *output_bfd)
{
  int i;
  for(i = 0; i < 1; i++) {
    printf("%d: size1 = %d, size2 = %d\n", i, plt_versions[i].entry_size, plt_versions[i].elem_size);
  }

  if (bfd_get_mach (output_bfd) == bfd_mach_arc_arcv2) i
    {
      if(bfd_link_pic (info))
        return &(plt_versions[ELF_ARCV2_PIC];
      else
        return &(plt_versions[ELF_ARCV2_ABS];
    }
  else
    {
      if(bfd_link_pic (info))
        return &(plt_versions[ELF_ARC_PIC];
      else
        return &(plt_versions[ELF_ARC_ABS];
    }
}

static		bfd_vma
add_symbol_to_plt (struct bfd_link_info *info)
{
  bfd *dynobj = (elf_hash_table (info))->dynobj;
  struct dynamic_sections ds = arc_create_dynamic_sections (dynobj, info);
  bfd_vma	  ret;

  struct plt_version_t *plt_data = arc_get_plt_version ();

  /* If this is the first .plt entry, make room for the special first entry.  */
  if (ds.splt->size == 0)
    ds.splt->size += plt_data->entry_size;

  ret = ds.splt->size;

  ds.splt->size += plt_data->elem_size;
  printf("PLT_SIZE = %d\n", ds.splt->size);

  ds.sgotplt->size += 4;
  ds.srelplt->size += sizeof (Elf32_External_Rela);

  return ret;
}

#define PLT_DO_RELOCS_FOR_ENTRY(ABFD, DS, RELOCS) \
  plt_do_relocs_for_symbol (ABFD, DS, RELOCS, 0, 0)

static void
plt_do_relocs_for_symbol (bfd *abfd,
			  struct dynamic_sections *ds,
			  struct plt_reloc *reloc,
			  bfd_vma plt_offset,
			  bfd_vma symbol_got_offset)
{
  while (SYM_ONLY (reloc->symbol) != LAST_RELOC)
    {
      bfd_vma	      relocation = 0;
      switch (SYM_ONLY (reloc->symbol))
	{
	  case SGOT:
		relocation =
		    ds->sgotplt->output_section->vma +
		    ds->sgotplt->output_offset + symbol_got_offset;
		break;
	}
      relocation += reloc->addend;

      relocation -= (IS_RELATIVE (reloc->symbol))
	  ? ds->splt->output_section->vma + ds->splt->output_offset +
	  plt_offset + reloc->offset : 0;

      if (IS_MIDDLE_ENDIAN (reloc->symbol) || bfd_big_endian (abfd))
	{
	  relocation = 
	      ((relocation & 0xffff0000) >> 16) |
	      ((relocation & 0xffff) << 16);
	}

      switch (reloc->size)
	{
	  case 32:
	    bfd_put_32 (ds->splt->output_section->owner,
			relocation,
			ds->splt->contents + plt_offset + reloc->offset);
	    break;
	}

      reloc = &(reloc[1]);	// Jump to next relocation
    }
}

static void
relocate_plt_for_symbol (bfd *output_bfd, 
			 struct bfd_link_info *info,
			 struct elf_link_hash_entry *h)
{
  bfd		 *dynobj = elf_hash_table (info)->dynobj;
  struct plt_version_t *plt_data = arc_get_plt_version ();
  struct dynamic_sections ds = arc_create_dynamic_sections (dynobj, info);

  //bfd_vma plt_index = h->plt.offset / plt_data->elem_size;
  bfd_vma plt_index = (h->plt.offset  - plt_data->entry_size) / plt_data->elem_size;
  bfd_vma got_offset = (plt_index + 3) * 4;

  printf("PLT_OFFSET = 0x%x\n", h->plt.offset);

  memcpy (ds.splt->contents + h->plt.offset, plt_data->elem, plt_data->elem_size);
  plt_do_relocs_for_symbol (output_bfd, &ds, plt_data->elem_relocs, h->plt.offset,
			    got_offset);

  /* Fill in the entry in the global offset table.  */
  bfd_put_32 (output_bfd,
              (bfd_vma) (ds.splt->output_section->vma  + ds.splt->output_offset),
    	      ds.sgotplt->contents + got_offset);
  
  //fprintf(stderr, "SIZE = %d, VMA = 0x%08x\n", ds.sgotplt->size, ds.sgotplt->output_section->vma + ds.sgotplt->output_offset);
  //fprintf(stderr, "GOT_OFFSET = 0x%x\n", got_offset);

  /* TODO: Fill in the entry in the .rela.plt section.  */
  {
    Elf_Internal_Rela rel;
    bfd_byte *loc;

    rel.r_offset = (ds.sgotplt->output_section->vma
          	  + ds.sgotplt->output_offset
          	  + got_offset);
    rel.r_addend = 0;
    rel.r_info = ELF32_R_INFO (h->dynindx, R_ARC_JMP_SLOT);

    loc = ds.srelplt->contents;
    loc += plt_index * sizeof (Elf32_External_Rela); /* relA */
    bfd_elf32_swap_reloca_out (output_bfd, &rel, loc);
  }

  //if (h->got.offset != (bfd_vma) -1)
  //  {
  //    Elf_Internal_Rela rel;
  //    bfd_byte *loc;

  //    rel.r_offset = (ds.sgot->output_section->vma
  //      	      + ds.sgot->output_offset
  //      	      + h->got.offset);
  //    fprintf(stderr, "BLA = %d\n", h->got.offset);

  //    /* If this is a -Bsymbolic link, and the symbol is defined
  //       locally, we just want to emit a RELATIVE reloc.  Likewise if
  //       the symbol was forced to be local because of a version file.
  //       The entry in the global offset table will already have been
  //       initialized in the relocate_section function.  */
  //    if (bfd_link_pic (info)
  //        && (info->symbolic || h->dynindx == -1)
  //        && h->def_regular)
  //      {
  //        rel.r_addend = 0;
  //        rel.r_info = ELF32_R_INFO (0, R_ARC_RELATIVE);
  //      }
  //    else if (h->dynindx == -1)
  //      memset (&rel, 0, sizeof rel);
  //    else
  //      {
  //        bfd_put_32 (output_bfd, (bfd_vma) 0, ds.sgot->contents + h->got.offset);
  //        /* RELA relocs */
  //        rel.r_addend = 0;
  //        rel.r_info = ELF32_R_INFO (h->dynindx, R_ARC_GLOB_DAT);
  //      }

  //    loc = ds.srelgot->contents;
  //    loc += ds.srelgot->reloc_count * sizeof (Elf32_External_Rela); /* relA */
  //    ds.srelgot->reloc_count += 1;

  //    bfd_elf32_swap_reloca_out (output_bfd, &rel, loc);
  //  }

}

static void
relocate_plt_for_entry (bfd *abfd,
			struct bfd_link_info *info)
{
  bfd *dynobj = (elf_hash_table (info))->dynobj;
  struct plt_version_t *plt_data = arc_get_plt_version ();
  struct dynamic_sections ds = arc_create_dynamic_sections (dynobj, info);

  memcpy (ds.splt->contents, plt_data->entry, plt_data->entry_size);
  PLT_DO_RELOCS_FOR_ENTRY (abfd, &ds, plt_data->entry_relocs);
}


/* Desc : Adjust a symbol defined by a dynamic object and referenced by a
   regular object.  The current definition is in some section of the
   dynamic object, but we're not including those sections.  We have to
   change the definition to something the rest of the link can
   understand.	*/

static bfd_boolean
elf_arc_adjust_dynamic_symbol (struct bfd_link_info *info,
			      struct elf_link_hash_entry *h)
{
  asection *s;
  unsigned int power_of_two;
  bfd *dynobj = (elf_hash_table (info))->dynobj;

  struct dynamic_sections ds = arc_create_dynamic_sections (dynobj, info);

  if (h->type == STT_FUNC || h->needs_plt == 1)
    {
      if (!bfd_link_pic (info) && !h->def_dynamic && !h->ref_dynamic)
	{
	  /* This case can occur if we saw a PLT32 reloc in an input
	   * file, but the symbol was never referred to by a dynamic
	   * object.  In such a case, we don't actually need to build
	   * a procedure linkage table, and we can just do a PC32
	   * reloc instead.  */
	  BFD_ASSERT (h->needs_plt);
	  return TRUE;
	}

      /* Make sure this symbol is output as a dynamic symbol.  */
      if (h->dynindx == -1 && !h->forced_local
	  && !bfd_elf_link_record_dynamic_symbol (info, h))
	return FALSE;

      if (bfd_link_pic (info) || WILL_CALL_FINISH_DYNAMIC_SYMBOL (1, 0, h))
	{
	  bfd_vma	  loc = add_symbol_to_plt (info);

	  if (!bfd_link_pic (info) && !h->def_regular)
	    {
	      h->root.u.def.section = ds.splt;
	      h->root.u.def.value = loc;
	    }
	  h->plt.offset = loc;
	}
    }
  else
    {
      h->plt.offset = (bfd_vma) - 1;
      h->needs_plt = 0;
    }

  /* If this is a weak symbol, and there is a real definition, the
     processor independent code will have arranged for us to see the
     real definition first, and we can just use the same value.  */
  if (h->u.weakdef != NULL)
    {
      BFD_ASSERT (h->u.weakdef->root.type == bfd_link_hash_defined
		  || h->u.weakdef->root.type == bfd_link_hash_defweak);
      h->root.u.def.section = h->u.weakdef->root.u.def.section;
      h->root.u.def.value = h->u.weakdef->root.u.def.value;
      return TRUE;
    }

  /* If there are no non-GOT references, we do not need a copy
     relocation.  */
  if (!h->non_got_ref)
    return TRUE;

  /* This is a reference to a symbol defined by a dynamic object which
     is not a function.  */

  /* If we are creating a shared library, we must presume that the
     only references to the symbol are via the global offset table.
     For such cases we need not do anything here; the relocations will
     be handled correctly by relocate_section.  */
  if (bfd_link_pic (info))
    return TRUE;

  /* We must allocate the symbol in our .dynbss section, which will
     become part of the .bss section of the executable.  There will be
     an entry for this symbol in the .dynsym section.  The dynamic
     object will contain position independent code, so all references
     from the dynamic object to this symbol will go through the global
     offset table.  The dynamic linker will use the .dynsym entry to
     determine the address it must put in the global offset table, so
     both the dynamic object and the regular object will refer to the
     same memory location for the variable.  */

  s = bfd_get_section_by_name (dynobj, ".dynbss");
  BFD_ASSERT (s != NULL);

  /* We must generate a R_ARC_COPY reloc to tell the dynamic linker to
     copy the initial value out of the dynamic object and into the
     runtime process image.  We need to remember the offset into the
     .rela.bss section we are going to use.  */
  if ((h->root.u.def.section->flags & SEC_ALLOC) != 0)
    {
      asection *srel;

      srel = bfd_get_section_by_name (dynobj, ".rela.bss");
      BFD_ASSERT (srel != NULL);
      srel->size += sizeof (Elf32_External_Rela);
      h->needs_copy = 1;
    }

  /* We need to figure out the alignment required for this symbol.  I
     have no idea how ELF linkers handle this.  */
  power_of_two = bfd_log2 (h->size);
  if (power_of_two > 3)
    power_of_two = 3;

  /* Apply the required alignment.  */
  s->size = BFD_ALIGN (s->size, (bfd_size_type) (1 << power_of_two));
  if (power_of_two > bfd_get_section_alignment (dynobj, s))
    {
      if (! bfd_set_section_alignment (dynobj, s, power_of_two))
	return FALSE;
    }

  /* Define the symbol as being at this point in the section.  */
  h->root.u.def.section = s;
  h->root.u.def.value = s->size;

  /* Increment the section size to make room for the symbol.  */
  s->size += h->size;

  return TRUE;
}

#define ADD_RELA(BFD, SECTION, OFFSET, SYM_IDX, TYPE, ADDEND) \
{\
  struct dynamic_sections ds = arc_create_dynamic_sections (output_bfd, info); \
  bfd_vma loc = (bfd_vma) ds.srel##SECTION->contents + ((ds.srel##SECTION->reloc_count++) * sizeof (Elf32_External_Rela)); \
  Elf_Internal_Rela rel; \
  /* Do Relocation */ \
  /* bfd_put_32 (output_bfd, (bfd_vma) 0, ds.s##SECTION->contents + OFFSET); */ \
  rel.r_addend = ADDEND; \
  rel.r_offset = (ds.s##SECTION)->output_section->vma + (ds.s##SECTION)->output_offset + OFFSET; \
  rel.r_info = ELF32_R_INFO (SYM_IDX, TYPE); \
  bfd_elf32_swap_reloca_out (BFD, &rel, (bfd_byte *) loc); \
}

/* Function :  elf_arc_finish_dynamic_symbol
 * Brief    :  Finish up dynamic symbol handling.  We set the
 *	     contents of various dynamic sections here.
 * Args     :  output_bfd :
 *	       info	  :
 *	       h	  :
 *	       sym	  :
 * Returns  : True/False as the return status.
 */
static bfd_boolean
elf_arc_finish_dynamic_symbol (bfd * output_bfd,
			       struct bfd_link_info *info,
			       struct elf_link_hash_entry *h,
			       Elf_Internal_Sym * sym)
{
  if (h->plt.offset != (bfd_vma) -1)
    relocate_plt_for_symbol (output_bfd, info, h);

  if (h->got.offset != (bfd_vma) -1)
    {
      if (bfd_link_pic (info) && (info->symbolic || h->dynindx == -1)
	  && h->def_regular)
	{
	  ADD_RELA (output_bfd, got, h->got.offset, 0, R_ARC_RELATIVE, 0);
	}
      else
	{
	  ADD_RELA (output_bfd, got, h->got.offset, h->dynindx,
		    R_ARC_GLOB_DAT, 0);
	}
    }

  /* Mark _DYNAMIC and _GLOBAL_OFFSET_TABLE_ as absolute.  */
  if (strcmp (h->root.root.string, "_DYNAMIC") == 0
      || strcmp (h->root.root.string, "__DYNAMIC") == 0
      || strcmp (h->root.root.string, "_GLOBAL_OFFSET_TABLE_") == 0)
    sym->st_shndx = SHN_ABS;

  return TRUE;
}

#define GET_SYMBOL_OR_SECTION(TAG, SYMBOL, SECTION) \
  case TAG: \
    if (SYMBOL != NULL) \
      { \
	h = elf_link_hash_lookup (elf_hash_table (info), SYMBOL, FALSE, FALSE, TRUE); \
      } \
    else if (SECTION != NULL) \
      { \
	s = bfd_get_section_by_name (output_bfd, SECTION); \
	BFD_ASSERT (s != NULL); \
	do_it = TRUE; \
      } \
    break;

/* Function :  elf_arc_finish_dynamic_sections
 * Brief    :  Finish up the dynamic sections handling.
 * Args     :  output_bfd :
 *	       info	  :
 *	       h	  :
 *	       sym	  :
 * Returns  : True/False as the return status.
 */
static		bfd_boolean
elf_arc_finish_dynamic_sections (bfd * output_bfd, struct bfd_link_info *info)
{
  struct dynamic_sections ds = arc_create_dynamic_sections (output_bfd, info);
  bfd		 *dynobj = (elf_hash_table (info))->dynobj;

  if (ds.sdyn)
    {
      Elf32_External_Dyn *dyncon, *dynconend;

      dyncon = (Elf32_External_Dyn *) ds.sdyn->contents;
      dynconend =
	  (Elf32_External_Dyn *) (ds.sdyn->contents + ds.sdyn->size);
      for (; dyncon < dynconend; dyncon++)
	{
	  Elf_Internal_Dyn internal_dyn;
	  bfd_boolean	  do_it = FALSE;

	  struct elf_link_hash_entry *h = NULL;
	  asection	 *s = NULL;

	  bfd_elf32_swap_dyn_in (dynobj, dyncon, &internal_dyn);

	  switch (internal_dyn.d_tag)
	    {
	      GET_SYMBOL_OR_SECTION (DT_INIT, "_init", NULL)
	      GET_SYMBOL_OR_SECTION (DT_FINI, "_fini", NULL)
	      GET_SYMBOL_OR_SECTION (DT_PLTGOT, NULL, ".plt")
	      GET_SYMBOL_OR_SECTION (DT_JMPREL, NULL, ".rela.plt")
	      GET_SYMBOL_OR_SECTION (DT_PLTRELSZ, NULL, ".rela.plt")
	      GET_SYMBOL_OR_SECTION (DT_RELASZ, NULL, ".rela.plt")
	      default:
		break;
	    }

	  /* In case the dynamic symbols should be updated with a
	   * symbol */
	  if (h != NULL
	      && (h->root.type == bfd_link_hash_defined
		  || h->root.type == bfd_link_hash_defweak)
	      )
	    {
	      asection	     *asec_ptr;
	      internal_dyn.d_un.d_val = h->root.u.def.value;
	      asec_ptr = h->root.u.def.section;
	      if (asec_ptr->output_section != NULL)
		{
		  internal_dyn.d_un.d_val +=
		    (asec_ptr->output_section->vma +
		     asec_ptr->output_offset);
		}
	      else
		{
		  /* The symbol is imported from another
		   * shared library and does not apply to this
		   * one.  */
		  internal_dyn.d_un.d_val = 0;
		}
	      do_it = TRUE;
	    }
	  /* ElsIf with a section information */
	  else if (s != NULL)
	    {
	      switch (internal_dyn.d_tag)
		{
		  case DT_PLTGOT:
		  case DT_JMPREL:
		    internal_dyn.d_un.d_ptr = s->vma;
		    do_it = TRUE;
		    break;

		  case DT_PLTRELSZ:
		    internal_dyn.d_un.d_val = s->size;
		    do_it = TRUE;
		    break;

		  case DT_RELASZ:
		    internal_dyn.d_un.d_val -= s->size;
		    do_it = TRUE;
		    break;

		  default:
		    break;
		}
	    }

	  if (do_it == TRUE)
	    bfd_elf32_swap_dyn_out (output_bfd, &internal_dyn, dyncon);
	}

      if (ds.splt->size > 0)
	{
	  relocate_plt_for_entry (output_bfd, info);
	}

      elf_section_data (ds.srelplt->output_section)->this_hdr.sh_entsize = 0xc;
  }

  /* Fill in the first three entries in the global offset table.  */
  if (ds.sgot)
    {
      if (ds.sgot->size > 0 || ds.sgotplt->size > 0)
	{
	  if (ds.sdyn == NULL)
	    bfd_put_32 (output_bfd, (bfd_vma) 0,
			ds.sgotplt->contents);
	  else
	    bfd_put_32 (output_bfd,
			ds.sdyn->output_section->vma + ds.sdyn->output_offset,
			ds.sgotplt->contents);
	  bfd_put_32 (output_bfd, (bfd_vma) 0, ds.sgotplt->contents + 4);
	  bfd_put_32 (output_bfd, (bfd_vma) 0, ds.sgotplt->contents + 8);

	  elf_section_data (ds.sgot->output_section)->this_hdr.sh_entsize = 4;
	}
    }

  if (ds.srelgot)
    {
      // TODO: Make it work even if I remove this.
      elf_section_data (ds.srelgot->output_section)->this_hdr.sh_entsize = 0xc;
    }

  return TRUE;
}

#define ADD_DYNAMIC_SYMBOL(NAME, TAG) \
  h =  elf_link_hash_lookup (elf_hash_table (info), NAME, FALSE, FALSE, FALSE); \
  if ((h != NULL && (h->ref_regular || h->def_regular))) \
    if (! _bfd_elf_add_dynamic_entry (info, TAG, 0)) \
      return FALSE;

/* Set the sizes of the dynamic sections.  */
static		bfd_boolean
elf_arc_size_dynamic_sections (bfd * output_bfd, struct bfd_link_info *info)
{
  bfd		 *dynobj;
  asection	 *s;
  bfd_boolean	  relocs_exist;
  bfd_boolean	  reltext_exist;

  struct dynamic_sections ds = arc_create_dynamic_sections (output_bfd, info);

  dynobj = (elf_hash_table (info))->dynobj;
  BFD_ASSERT (dynobj != NULL);

  if ((elf_hash_table (info))->dynamic_sections_created)
    {
      struct elf_link_hash_entry *h;

      /* Set the contents of the .interp section to the interpreter.  */
      if (!bfd_link_pic (info))
	{
	  s = bfd_get_section_by_name (dynobj, ".interp");
	  BFD_ASSERT (s != NULL);
	  s->size = sizeof ELF_DYNAMIC_INTERPRETER;
	  s->contents = (unsigned char *) ELF_DYNAMIC_INTERPRETER;
	}

      /* Add some entries to the .dynamic section.  We fill in some of the
       * values later, in elf_bfd_final_link, but we must add the entries
       * now so that we know the final size of the .dynamic section.  */
      /* Checking if the .init section is present. We also create DT_INIT
       * / DT_FINI entries if the init_str has been changed by the user */

		ADD_DYNAMIC_SYMBOL ("init", DT_INIT);
		ADD_DYNAMIC_SYMBOL ("fini", DT_FINI);
    }
  else
    {
      /* We may have created entries in the .rela.got section. However, if
       * we are not creating the dynamic sections, we will not actually
       * use these entries.  Reset the size of .rela.got, which will cause
       * it to get stripped from the output file below.  */

      ds.srelgot->size = 0;
    }

  for (s = dynobj->sections; s != NULL; s = s->next)
    {
	bfd_boolean	is_dynamic_section = FALSE;

	/* Skip any non dynamic section */
	if (strstr (s->name, ".plt") != NULL
	    || strstr (s->name, ".got") != NULL
	    || strstr (s->name, ".rel") != NULL)
	  is_dynamic_section = TRUE;

      /* Allocate memory for the section contents.  */
      if (!is_dynamic_section)
	continue;

      s->contents = (bfd_byte *) bfd_alloc (dynobj, s->size);
      if (s->contents == NULL && s->size != 0)
	  return FALSE;

      if (s->size == 0 && strcmp(s->name, ".rela.plt") != 0) 
	{
	  s->flags |= SEC_EXCLUDE;
	  continue;
	}

      if (strcmp (s->name, ".rela.plt") != 0)
	{
	  const char *outname = bfd_get_section_name (output_bfd,
						      s->output_section);
	  asection *target = bfd_get_section_by_name (output_bfd,
						      outname + 4);

	  relocs_exist = TRUE;
	  if (target != NULL && target->size != 0
	      && (target->flags & SEC_READONLY) != 0
	      && (target->flags & SEC_ALLOC) != 0)
	    reltext_exist = TRUE;
	}

    }

  if (ds.sdyn)
    {

      // TODO: Check if this is needed
      //if (!bfd_link_pic (info))
      //	if (!_bfd_elf_add_dynamic_entry (info, DT_DEBUG, 0))
      //		return FALSE;

      if (ds.splt && ds.splt->size != 0)
	if (!_bfd_elf_add_dynamic_entry (info, DT_PLTGOT, 0)
	    || !_bfd_elf_add_dynamic_entry (info, DT_PLTRELSZ, 0)
	    || !_bfd_elf_add_dynamic_entry (info, DT_PLTREL, DT_RELA)
	    || !_bfd_elf_add_dynamic_entry (info, DT_JMPREL, 0)
	   )
	  return FALSE;

      if (relocs_exist == TRUE)
	if (!_bfd_elf_add_dynamic_entry (info, DT_RELA, 0)
	    || !_bfd_elf_add_dynamic_entry (info, DT_RELASZ, 0)
	    || !_bfd_elf_add_dynamic_entry (info, DT_RELENT,
					    sizeof (Elf32_External_Rela))
	   )
	  return FALSE;

      if (reltext_exist == TRUE)
	if (!_bfd_elf_add_dynamic_entry (info, DT_TEXTREL, 0))
	  return FALSE;
  }

  return TRUE;
}

#define TARGET_LITTLE_SYM   arc_elf32_le_vec
#define TARGET_LITTLE_NAME  "elf32-littlearc"
#define TARGET_BIG_SYM	    arc_elf32_be_vec
#define TARGET_BIG_NAME     "elf32-bigarc"
#define ELF_ARCH	    bfd_arch_arc
#define ELF_MACHINE_CODE    EM_ARCV2
#define ELF_MAXPAGESIZE     0x2000

#define elf_info_to_howto_rel		     arc_info_to_howto_rel
#define elf_backend_object_p		     arc_elf_object_p
#define elf_backend_final_write_processing   arc_elf_final_write_processing

#define elf_backend_relocate_section	     elf_arc_relocate_section
#define elf_backend_check_relocs	     elf_arc_check_relocs
#define elf_backend_create_dynamic_sections  _bfd_elf_create_dynamic_sections

#define elf_backend_adjust_dynamic_symbol    elf_arc_adjust_dynamic_symbol
#define elf_backend_finish_dynamic_symbol    elf_arc_finish_dynamic_symbol

#define elf_backend_finish_dynamic_sections  elf_arc_finish_dynamic_sections
#define elf_backend_size_dynamic_sections    elf_arc_size_dynamic_sections

#define elf_backend_can_gc_sections	1
#define elf_backend_want_got_plt	1
#define elf_backend_plt_readonly	1
#define elf_backend_rela_plts_and_copies_p 1
#define elf_backend_want_plt_sym	0
#define elf_backend_got_header_size	12

#define elf_backend_may_use_rel_p	0
#define elf_backend_may_use_rela_p	1
#define elf_backend_default_use_rela_p	1

#include "elf32-target.h"
