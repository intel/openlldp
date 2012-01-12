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
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include "dcb_protocol.h"
#include "lldpad_shm.h"
#include "lldp.h"

void mark_lldpad_shm_for_removal()
{
	int shmid;
	struct shmid_ds shminfo;

	shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE, 0);

	if (shmid < 0)
		return;

	if (shmctl(shmid, IPC_RMID, &shminfo) < 0)
		return;
}

/* return: 1 = success, 0 = failed */
void lldpad_shm_ver0_to_ver1(struct lldpad_shm_tbl_ver0 *shmold,
			    int num_old_entries)
{
	unsigned i;
	unsigned num_entries;
	struct lldpad_shm_entry new_ent[MAX_LLDPAD_SHM_ENTRIES];

	num_entries = num_old_entries;
	if (num_entries > MAX_LLDPAD_SHM_ENTRIES)
		num_entries = MAX_LLDPAD_SHM_ENTRIES;

	shmold->num_entries = (num_entries & SHM_NUM_ENT_MASK) |
				(1 << SHM_VER_SHIFT);

	for (i = 0; i < num_entries; i++) {
		memcpy(new_ent[i].ifname,
		       shmold->ent[i].ifname,
		       sizeof(new_ent[i].ifname));
		memcpy(&new_ent[i].chassisid[0],
		       &shmold->ent[i].chassisid[0],
		       SHM_CHASSISID_LEN);

		new_ent[i].chassisid_len = shmold->ent[i].chassisid_len;

		memcpy(&new_ent[i].portid[0],
		       &shmold->ent[i].portid[0],
		       SHM_PORTID_LEN);

		new_ent[i].portid_len = shmold->ent[i].portid_len;
		memcpy((void *)&new_ent[i].st, (void *)&shmold->ent[i].st,
			sizeof(dcbx_state));
		new_ent[i].dcbx_mode = 0;
	}

	memcpy((void *)&shmold->ent[0], (void *)&new_ent[0],
		sizeof(struct lldpad_shm_entry) * num_entries);
}

/* return: 1 = success, 0 = failed */
int lldpad_shm_get_msap(const char *device_name, int type, char *info, size_t *len)
{
	char *p;
	int shmid;
	struct lldpad_shm_tbl *shmaddr=NULL;
	pid_t rval = 0;
	unsigned i;
	unsigned num_entries;
	int version;

	shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE, 0);
	if (shmid < 0 && errno == ENOENT)
		shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE,
			IPC_CREAT | IPC_EXCL | 0x180);

	if (shmid < 0)
		return rval;

	shmaddr = (struct lldpad_shm_tbl *)shmat(shmid, NULL, 0);
	if ((long) shmaddr == -1)
		return rval;

	version = (shmaddr->num_entries & SHM_VER_MASK) >> SHM_VER_SHIFT;

	if (version == 0)
		lldpad_shm_ver0_to_ver1((struct lldpad_shm_tbl_ver0 *) shmaddr,
				shmaddr->num_entries & SHM_NUM_ENT_MASK);

	num_entries = shmaddr->num_entries & SHM_NUM_ENT_MASK;

	/* check for invalid number of shm table entries */
	if (num_entries > MAX_LLDPAD_SHM_ENTRIES)
		goto done;

	/* search for existing entry */
	for (i = 0; i < num_entries; i++)
		if (strcmp(shmaddr->ent[i].ifname, device_name) == 0)
			break;

	if (i == shmaddr->num_entries)
		goto done;

	if (type == CHASSIS_ID_TLV) {
		p = &shmaddr->ent[i].chassisid[0];
		*len = shmaddr->ent[i].chassisid_len;
	} else if (type == PORT_ID_TLV) {
		p = &shmaddr->ent[i].portid[0];
		*len = shmaddr->ent[i].portid_len;
	} else
		goto done;

	if (*len) {
		memcpy(info, p, *len);
		rval = 1;
	}
done:
	shmdt(shmaddr);

	return rval;
}

/* return: 1 = success, 0 = failed */
int lldpad_shm_set_msap(const char *device_name, int type, char *info, size_t len)
{
	int shmid;
	struct lldpad_shm_tbl *shmaddr=NULL;
	pid_t rval = 0;
	unsigned i;
	int version;
	unsigned num_entries;

	shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE, 0);
	if (shmid < 0 && errno == ENOENT)
		shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE,
			IPC_CREAT | IPC_EXCL | 0x180);

	if (shmid < 0)
		return rval;

	shmaddr = (struct lldpad_shm_tbl *)shmat(shmid, NULL, 0);
	if ((long) shmaddr == -1)
		return rval;

	version = (shmaddr->num_entries & SHM_VER_MASK) >> SHM_VER_SHIFT;

	if (version == 0)
		lldpad_shm_ver0_to_ver1((struct lldpad_shm_tbl_ver0 *) shmaddr,
				shmaddr->num_entries & SHM_NUM_ENT_MASK);
	num_entries = shmaddr->num_entries & SHM_NUM_ENT_MASK;

	/* check for invalid number of shm table entries */
	if (num_entries > MAX_LLDPAD_SHM_ENTRIES)
		goto done;

	/* search for existing entry */
	for (i = 0; i < num_entries; i++)
		if (strcmp(shmaddr->ent[i].ifname, device_name) == 0)
			break;

	if (i < MAX_LLDPAD_SHM_ENTRIES) {
		if (type == CHASSIS_ID_TLV && len <= SHM_CHASSISID_LEN) {
			memset(&shmaddr->ent[i].chassisid[0], 0, SHM_CHASSISID_LEN);
			memcpy(&shmaddr->ent[i].chassisid[0], info, len);
			shmaddr->ent[i].chassisid_len = len;
		} else if (type == PORT_ID_TLV && len <= SHM_PORTID_LEN) {
			memset(&shmaddr->ent[i].portid[0], 0, SHM_PORTID_LEN);
			memcpy(&shmaddr->ent[i].portid[0], info, len);
			shmaddr->ent[i].portid_len = len;
		} else
			goto done;

		if (i == num_entries) {
			shmaddr->num_entries++;
			sprintf(shmaddr->ent[i].ifname, "%.*s",
				IFNAMSIZ, device_name);
		}

		rval = 1;
	}

done:
	shmdt(shmaddr);

	return rval;
}

int lldpad_shm_get_dcbx(const char *device_name)
{
	int shmid;
	struct lldpad_shm_tbl *shmaddr = NULL;
	pid_t rval = 0;  /* zero is default DCBX auto mode */
	unsigned i;
	unsigned num_entries;
	int version;

	shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE, 0);
	if (shmid < 0 && errno == ENOENT)
		shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE,
			IPC_CREAT | IPC_EXCL | 0x180);

	if (shmid < 0)
		return rval;

	shmaddr = (struct lldpad_shm_tbl *)shmat(shmid, NULL, 0);
	if ((long) shmaddr == -1)
		return rval;

	version = (shmaddr->num_entries & SHM_VER_MASK) >> SHM_VER_SHIFT;

	if (version == 0)
		goto done;

	num_entries = shmaddr->num_entries & SHM_NUM_ENT_MASK;

	/* check for invalid number of shm table entries */
	if (num_entries > MAX_LLDPAD_SHM_ENTRIES)
		goto done;

	/* search for existing entry */
	for (i = 0; i < num_entries; i++) {
		if (strcmp(shmaddr->ent[i].ifname, device_name) == 0) {
			switch (shmaddr->ent[i].dcbx_mode) {
			case dcbx_subtype1:
			case dcbx_subtype2:
				rval = shmaddr->ent[i].dcbx_mode;
				break;
			default:
				;
			}
		}
	}

done:
	shmdt(shmaddr);

	return rval;
}

/* return: 1 = success, 0 = failed */
int lldpad_shm_set_dcbx(const char *device_name, int dcbx_mode)
{
	int shmid;
	struct lldpad_shm_tbl *shmaddr = NULL;
	pid_t rval = 0;
	unsigned i;
	unsigned num_entries;
	int version;

	shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE, 0);
	if (shmid < 0 && errno == ENOENT)
		shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE,
			IPC_CREAT | IPC_EXCL | 0x180);

	if (shmid < 0)
		return rval;

	shmaddr = (struct lldpad_shm_tbl *)shmat(shmid, NULL, 0);
	if ((long) shmaddr == -1)
		return rval;

	version = (shmaddr->num_entries & SHM_VER_MASK) >> SHM_VER_SHIFT;

	if (version == 0)
		lldpad_shm_ver0_to_ver1((struct lldpad_shm_tbl_ver0 *) shmaddr,
				shmaddr->num_entries & SHM_NUM_ENT_MASK);

	num_entries = shmaddr->num_entries & SHM_NUM_ENT_MASK;

	/* check for invalid number of shm table entries */
	if (num_entries > MAX_LLDPAD_SHM_ENTRIES)
		goto done;

	if ((dcbx_mode != dcbx_subtype0) && (dcbx_mode != dcbx_subtype1) &&
	    (dcbx_mode != dcbx_subtype2))
		goto done;

	/* search for existing entry */
	for (i = 0; i < num_entries; i++) {
		if (strcmp(shmaddr->ent[i].ifname, device_name) == 0) {
			shmaddr->ent[i].dcbx_mode = dcbx_mode;
			rval = 1;
			break;
		}
	}

	/* make a new entry if no existing entry */
	if ((i == num_entries) && (i < MAX_LLDPAD_SHM_ENTRIES)) {
		shmaddr->num_entries++;
		sprintf(shmaddr->ent[i].ifname, "%.*s", IFNAMSIZ, device_name);
		memset(&shmaddr->ent[i].chassisid[0], 0, SHM_CHASSISID_LEN);
		shmaddr->ent[i].chassisid_len = 0;
		memset(&shmaddr->ent[i].portid[0], 0, SHM_PORTID_LEN);
		shmaddr->ent[i].portid_len = 0;
		memset((void *)&shmaddr->ent[i].st, 0, sizeof(dcbx_state));
		shmaddr->ent[i].dcbx_mode = dcbx_mode;
		rval = 1;
	}

done:
	shmdt(shmaddr);

	return rval;
}

/* return: -1 = failed, >=0 = success
 * Should always be called first by lldpad.  This is the
 * only routine which creates the shared memory segment.
 */
pid_t lldpad_shm_getpid()
{
	int shmid;
	struct lldpad_shm_tbl *shmaddr=NULL;
	pid_t rval = -1;
	int version;

	shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE, 0);
	if (shmid < 0 && errno == ENOENT)
		shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE,
			IPC_CREAT | IPC_EXCL | 0x180);

	if (shmid < 0)
		return rval;

	shmaddr = (struct lldpad_shm_tbl *)shmat(shmid, NULL, 0);
	if ((long) shmaddr == -1)
		return rval;

	version = (shmaddr->num_entries & SHM_VER_MASK) >> SHM_VER_SHIFT;

	if (version == 0)
		lldpad_shm_ver0_to_ver1((struct lldpad_shm_tbl_ver0 *) shmaddr,
				shmaddr->num_entries & SHM_NUM_ENT_MASK);

	rval = shmaddr->pid;

	shmdt(shmaddr);

	return rval;
}

/* return: 1 = success, 0 = failed */
int lldpad_shm_setpid(pid_t pid)
{
	int shmid;
	struct lldpad_shm_tbl *shmaddr=NULL;
	pid_t rval = 0;
	int version;

	shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE, 0);

	if (shmid < 0)
		return rval;

	shmaddr = (struct lldpad_shm_tbl *)shmat(shmid, NULL, 0);
	if ((long) shmaddr == -1)
		return rval;

	version = (shmaddr->num_entries & SHM_VER_MASK) >> SHM_VER_SHIFT;

	if (version == 0)
		lldpad_shm_ver0_to_ver1((struct lldpad_shm_tbl_ver0 *) shmaddr,
				shmaddr->num_entries & SHM_NUM_ENT_MASK);

	shmaddr->pid = pid;

	shmdt(shmaddr);

	return 1;
}

/* return: 1 = success, 0 = failed */
int clear_dcbx_state()
{
	int shmid;
	struct lldpad_shm_tbl *shmaddr=NULL;
	unsigned i;
	int version;
	unsigned num_entries;

	shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE, 0);

	if (shmid < 0)
		return 0;

	shmaddr = (struct lldpad_shm_tbl *)shmat(shmid, NULL, 0);
	if ((long) shmaddr == -1)
		return 0;

	version = (shmaddr->num_entries & SHM_VER_MASK) >> SHM_VER_SHIFT;

	if (version == 0)
		lldpad_shm_ver0_to_ver1((struct lldpad_shm_tbl_ver0 *) shmaddr,
				shmaddr->num_entries & SHM_NUM_ENT_MASK);
	num_entries = shmaddr->num_entries & SHM_NUM_ENT_MASK;

	/* check for invalid number of shm table entries */
	if (num_entries > MAX_LLDPAD_SHM_ENTRIES)
		goto done;

	/* clear out dcbx_state for all entries */
	for (i = 0; i < num_entries; i++)
		if (strlen(shmaddr->ent[i].ifname))
			memset((void *)&shmaddr->ent[i].st, 0,
				sizeof(dcbx_state));

done:
	shmdt(shmaddr);
	return 1;
}

/* return: 1 = success, 0 = failed */
int set_dcbx_state(const char *device_name, dcbx_state *state)
{
	int shmid;
	struct lldpad_shm_tbl *shmaddr=NULL;
	unsigned i;
	int rval = 0;
	int version;
	unsigned num_entries;

	shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE, 0);

	if (shmid < 0)
		return rval;

	shmaddr = (struct lldpad_shm_tbl *)shmat(shmid, NULL, 0);
	if ((long) shmaddr == -1)
		return rval;

	version = (shmaddr->num_entries & SHM_VER_MASK) >> SHM_VER_SHIFT;

	if (version == 0)
		lldpad_shm_ver0_to_ver1((struct lldpad_shm_tbl_ver0 *) shmaddr,
				shmaddr->num_entries & SHM_NUM_ENT_MASK);
	num_entries = shmaddr->num_entries & SHM_NUM_ENT_MASK;

	/* check for invalid number of shm table entries */
	if (num_entries > MAX_LLDPAD_SHM_ENTRIES)
		goto done;

	/* search for existing entry */
	for (i = 0; i < num_entries; i++)
		if (strcmp(shmaddr->ent[i].ifname, device_name) == 0)
			break;

	if (i < MAX_LLDPAD_SHM_ENTRIES) {
		if (i == num_entries) {
			shmaddr->num_entries++;
			sprintf(shmaddr->ent[i].ifname, "%.*s",
				IFNAMSIZ, device_name);
		}
		memcpy((void *)&shmaddr->ent[i].st, state, sizeof(dcbx_state));
		rval = 1;
	}

done:
	shmdt(shmaddr);

	return rval;
}

/* find and return a dcbx_state for the given device_name.
 * clear the dcbx_state entry after getting it - it's only valid
 * for the first read.
 * return: 1 = success, 0 = failed */
int get_dcbx_state(const char *device_name, dcbx_state *state)
{
	int shmid;
	struct lldpad_shm_tbl *shmaddr=NULL;
	unsigned i;
	int rval = 0;
	int version;
	unsigned num_entries;

	shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE, 0);

	if (shmid < 0)
		return rval;

	shmaddr = (struct lldpad_shm_tbl *)shmat(shmid, NULL, 0);
	if ((long) shmaddr == -1)
		return rval;

	version = (shmaddr->num_entries & SHM_VER_MASK) >> SHM_VER_SHIFT;

	if (version == 0)
		lldpad_shm_ver0_to_ver1((struct lldpad_shm_tbl_ver0 *) shmaddr,
				shmaddr->num_entries & SHM_NUM_ENT_MASK);
	num_entries = shmaddr->num_entries & SHM_NUM_ENT_MASK;

	/* check for invalid number of shm table entries */
	if (num_entries > MAX_LLDPAD_SHM_ENTRIES)
		goto done;

	/* search for existing entry */
	for (i = 0; i < num_entries; i++)
		if (strcmp(shmaddr->ent[i].ifname, device_name) == 0) {
			memcpy(state, (void *)&shmaddr->ent[i].st,
				sizeof(dcbx_state));
			memset((void *)&shmaddr->ent[i].st, 0,
				sizeof(dcbx_state));
			rval = 1;
			break;
		}

done:
	shmdt(shmaddr);

	return rval;
}


#ifdef SHM_UTL
/* compile utility to print out lldpad shared memory segment as follows:
 *    gcc -o lldpad_shm -I. -Iinclude -DSHM_UTL lldpad_shm.c
*/

int print_lldpad_shm()
{
	int shmid;
	struct lldpad_shm_tbl_ver0 *shmaddr_ver0 = NULL;
	struct lldpad_shm_tbl *shmaddr=NULL;
	unsigned i;
	int j;
	int rval = 0;
	int version;
	unsigned num_entries;
	unsigned max_entries;
	int ent_size;
	struct lldpad_shm_entry *entry_ptr = NULL;

	shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE, 0);

	if (shmid < 0) {
		printf("failed to shmget\n");
		return rval;
	}

	shmaddr = (struct lldpad_shm_tbl *)shmat(shmid, NULL, 0);
	shmaddr_ver0 = (struct lldpad_shm_tbl_ver0 *)shmaddr;
	if ((long) shmaddr == -1) {
		printf("failed to shmat\n");
		return rval;
	}

	version = (shmaddr->num_entries & SHM_VER_MASK) >> SHM_VER_SHIFT;
	if (version == 0) {
		max_entries = MAX_LLDPAD_SHM_ENTRIES_VER0;
		ent_size = sizeof(struct lldpad_shm_entry_ver0);
	} else {
		max_entries = MAX_LLDPAD_SHM_ENTRIES;
		ent_size = sizeof(struct lldpad_shm_entry);
	}
	num_entries = shmaddr->num_entries & SHM_NUM_ENT_MASK;
	printf("pid = %d\n", shmaddr->pid);
	printf("version = %d\n", version);
	printf("num_entries = %d\n", num_entries);
	printf("max num_entries = %d\n", max_entries);

	/* check for invalid number of shm table entries */
	if (num_entries > max_entries)
		goto done;

	for (i = 0; i < num_entries; i++) {
		if (version == 0)
			entry_ptr = (struct lldpad_shm_entry *)&shmaddr_ver0->ent[i];
		else
			entry_ptr = &shmaddr->ent[i];

		printf("ifname:     %s\n", entry_ptr->ifname);
		printf("chassisid:  ");
		for (j = 0; j < entry_ptr->chassisid_len; j++)
			printf("%02x", (unsigned char)entry_ptr->chassisid[j]);
		printf("\n");
		printf("portid:     ");
		for (j = 0; j < entry_ptr->portid_len; j++)
			printf("%02x", (unsigned char)entry_ptr->portid[j]);
		printf("\n");
		printf("SeqNo:       %d\n", entry_ptr->st.SeqNo);
		printf("AckNo:       %d\n", entry_ptr->st.AckNo);
		printf("FCoEenable:  %d\n", entry_ptr->st.FCoEenable);
		printf("iSCSIenable: %d\n", entry_ptr->st.iSCSIenable);
		if (version) {
			printf("DCBX mode: ");
			switch (entry_ptr->dcbx_mode) {
			case dcbx_subtype0:
				printf("Auto (IEEE)\n");
				break;
			case dcbx_subtype1:
				printf("CIN\n");
				break;
			case dcbx_subtype2:
				printf("CEE\n");
				break;
			default:
				printf("unknown\n");
			}
		}
	}
	rval = 1;

done:
	shmdt(shmaddr);

	return rval;
}

static void usage(void)
{
        fprintf(stderr,
                "\n"
                "usage: lldpad_shm [-r]"
                "\n"
                "options:\n"
                "   -r  dump lldpad shared memory in raw format\n");

        exit(1);
}

main()
{
	print_lldpad_shm();
}
#endif
