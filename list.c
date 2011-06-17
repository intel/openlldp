/*******************************************************************************

  LLDP Agent Daemon (LLDPAD) Software
  Copyright(c) 2007-2010 Intel Corporation.

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

#include <stdlib.h>
#include <sys/queue.h>
#include <string.h>
#include "list.h"

struct ls_entry *ls_find(struct lshead *head, char *key)
{
	struct ls_entry *p = NULL;
	for (p = head->lh_first; p != NULL; p = p->entries.le_next)
		if (!strcmp(p->key, key))
			return p;
	return p;
}

list_rvals ls_insert(struct lshead *head, char *key, void *value)
{
	struct ls_entry *entry;
	entry = (struct ls_entry *)malloc(sizeof(struct ls_entry));
	if (!entry)
		return ls_failed;
	entry->key = key;
	entry->value = value;
	LIST_INSERT_HEAD(head, entry, entries);
	return ls_ok;
}

void ls_erase(struct lshead *head, char *key)
{
	struct ls_entry *p;
	p = ls_find(head, key);
	if (p)
		LIST_REMOVE(p, entries);
}

void ls_remove_list(struct lshead *head)
{
	while (head->lh_first != NULL)
		LIST_REMOVE(head->lh_first, entries);
}
