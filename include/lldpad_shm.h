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
int lldpad_shm_get_dcbx(const char *device_name);
int lldpad_shm_set_dcbx(const char *device_name, int dcbx_mode);

#define SHM_CHASSISID_LEN 32
#define SHM_PORTID_LEN 32

#define DCBX_AUTO 0	/* start DCBX in IEEE DCBX mode */
#define DCBX_LEGACY 1	/* start DCBX in legacy DCBX mode */

struct lldpad_shm_entry {
	char ifname[IFNAMSIZ+1];
	char chassisid[SHM_CHASSISID_LEN];
	int chassisid_len;
	char portid[SHM_PORTID_LEN];
	int portid_len;
	dcbx_state st;
	u8 dcbx_mode; /* added to version 1 */
};

/* Version 0 of the SHM entry structure */
struct lldpad_shm_entry_ver0 {
	char ifname[IFNAMSIZ+1];
	char chassisid[SHM_CHASSISID_LEN];
	int chassisid_len;
	char portid[SHM_PORTID_LEN];
	int portid_len;
	dcbx_state st;
};

#define MAX_LLDPAD_SHM_ENTRIES_VER0 \
	(LLDPAD_SHM_SIZE/sizeof(struct lldpad_shm_entry_ver0) - 1)

#define MAX_LLDPAD_SHM_ENTRIES \
	(LLDPAD_SHM_SIZE/sizeof(struct lldpad_shm_entry) - 1)

#define SHM_NUM_ENT_MASK 0x0ffff
#define SHM_VER_MASK 0x0ffff0000
#define SHM_VER_SHIFT 16

struct lldpad_shm_tbl {
	pid_t pid;
	u32 num_entries;	/* High order 16 bits used as a version # */
	struct lldpad_shm_entry ent[MAX_LLDPAD_SHM_ENTRIES];
};

struct lldpad_shm_tbl_ver0 {
	pid_t pid;
	u32 num_entries;	/* High order 16 bits used as a version # */
	struct lldpad_shm_entry_ver0 ent[MAX_LLDPAD_SHM_ENTRIES];
};

#endif
