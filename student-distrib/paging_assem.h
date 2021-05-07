/* paging_assem.h - Enable paging
 */

#ifndef _PAGING_ASSEM
#define _PAGING_ASSEM

#include "paging.h"

/*
 * enable_paging
 *   DESCRIPTION: Enable paging in the OS by setting up the control register values
 *   INPUTS: none
 *   OUTPUTS: none
 *   RETURN VALUE: none
 *   SIDE EFFECTS: enables paging
 */
extern void enable_paging(page_directory_entry_t* pointer);

#endif

