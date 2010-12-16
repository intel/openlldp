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
  e1000-eedc Mailing List <e1000-eedc@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#ifndef LLDPAD_SHM_H
#define LLDPAD_SHM_H

#include <unistd.h>
#include "lldpad.h"
#include "lldp_rtnl.h"

#define LLDPAD_SHM_KEY ((('l'<<24) | ('l'<<16) | ('d'<<8) | ('p')) + 'a' + 'd' + 1)
#define LLDPAD_SHM_SIZE 4096

/* PID value used to indicate pid field is uninitialized */
#define PID_NOT_SET 0

/* PID used to indicate that -k option has already run */
#define DONT_KILL_PID 1

void mark_lldpad_shm_for_removal();
pid_t lldpad_shm_getpid();
int lldpad_shm_setpid(pid_t pid);
int lldpad_shm_get_msap(const char *device_name, int type, char *info, size_t *len);
int lldpad_shm_set_msap(const char *device_name, int type, char *info, size_t len);

#define SHM_CHASSISID_LEN 32
#define SHM_PORTID_LEN 32

struct lldpad_shm_entry {
	char ifname[IFNAMSIZ+1];
	char chassisid[SHM_CHASSISID_LEN];
	int chassisid_len;
	char portid[SHM_PORTID_LEN];
	int portid_len;
	dcbx_state st;
};

#define MAX_LLDPAD_SHM_ENTRIES (LLDPAD_SHM_SIZE/sizeof(struct lldpad_shm_entry) - 1)

struct lldpad_shm_tbl {
	pid_t pid;
	u32 num_entries;
	struct lldpad_shm_entry ent[MAX_LLDPAD_SHM_ENTRIES];
};

#endif
