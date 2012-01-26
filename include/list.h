/*******************************************************************************

  LLDP Agent Daemon (LLDPAD) Software
  Copyright(c) 2007-2012 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  open-lldp Mailing List <lldp-devel@open-lldp.org>

*******************************************************************************/

#ifndef _LIST_H
#define _LIST_H
#include <sys/queue.h>

typedef enum {
	ls_ok = 0,
	ls_failed = -1,
	ls_exists = -2
} list_rvals;

/* define a pointer of type y and initialize to the value of the list entry */
#define	LV_PTR(x, y, z) y *x = (z)?((y *)z->value):(NULL);


struct ls_entry {
	char *key;  /* NULL terminated string */
	void *value;
	LIST_ENTRY(ls_entry) entries;
};

typedef struct ls_entry * lsp;

LIST_HEAD(lshead, ls_entry);

struct ls_entry *ls_find(struct lshead *, char *);;
list_rvals ls_insert(struct lshead *, char *, void *);
void ls_erase(struct lshead *, char *);
void ls_remove_list(struct lshead *);

#endif /* _LIST_H */
