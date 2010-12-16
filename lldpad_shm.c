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

/* return: 1 = success, 0 = failed */
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
int lldpad_shm_get_msap(const char *device_name, int type, char *info, size_t *len)
{
	char *p;
	int shmid;
	struct lldpad_shm_tbl *shmaddr=NULL;
	pid_t rval = 0;
	int i;

	shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE, 0);
	if (shmid < 0 && errno == ENOENT)
		shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE,
			IPC_CREAT | IPC_EXCL | 0x180);

	if (shmid < 0)
		return rval;

	shmaddr = (struct lldpad_shm_tbl *)shmat(shmid, NULL, 0);
	if ((long) shmaddr == -1)
		return rval;

	/* check for invalid number of shm table entries */
	if (shmaddr->num_entries < 0 ||
		shmaddr->num_entries > MAX_LLDPAD_SHM_ENTRIES)
		goto done;

	/* search for existing entry */
	for (i = 0; i < shmaddr->num_entries; i++)
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
	char *p;
	int shmid;
	struct lldpad_shm_tbl *shmaddr=NULL;
	pid_t rval = 0;
	int i;

	shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE, 0);
	if (shmid < 0 && errno == ENOENT)
		shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE,
			IPC_CREAT | IPC_EXCL | 0x180);

	if (shmid < 0)
		return rval;

	shmaddr = (struct lldpad_shm_tbl *)shmat(shmid, NULL, 0);
	if ((long) shmaddr == -1)
		return rval;

	/* check for invalid number of shm table entries */
	if (shmaddr->num_entries < 0 ||
		shmaddr->num_entries > MAX_LLDPAD_SHM_ENTRIES)
		goto done;

	/* search for existing entry */
	for (i = 0; i < shmaddr->num_entries; i++)
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

		if (i == shmaddr->num_entries) {
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

/* return: -1 = failed, >=0 = success
 * Should always be called first by lldpad.  This is the
 * only routine which creates the shared memory segment.
 */
pid_t lldpad_shm_getpid()
{
	int shmid;
	struct lldpad_shm_tbl *shmaddr=NULL;
	pid_t rval = -1;

	shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE, 0);
	if (shmid < 0 && errno == ENOENT)
		shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE,
			IPC_CREAT | IPC_EXCL | 0x180);

	if (shmid < 0)
		return rval;

	shmaddr = (struct lldpad_shm_tbl *)shmat(shmid, NULL, 0);
	if ((long) shmaddr == -1)
		return rval;

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

	shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE, 0);

	if (shmid < 0)
		return rval;

	shmaddr = (struct lldpad_shm_tbl *)shmat(shmid, NULL, 0);
	if ((long) shmaddr == -1)
		return rval;

	shmaddr->pid = pid;

	shmdt(shmaddr);

	return 1;
}

/* return: 1 = success, 0 = failed */
int clear_dcbx_state()
{
	int shmid;
	struct lldpad_shm_tbl *shmaddr=NULL;
	int i;

	shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE, 0);

	if (shmid < 0)
		return 0;

	shmaddr = (struct lldpad_shm_tbl *)shmat(shmid, NULL, 0);
	if ((long) shmaddr == -1)
		return 0;

	/* check for invalid number of shm table entries */
	if (shmaddr->num_entries < 0 ||
		shmaddr->num_entries > MAX_LLDPAD_SHM_ENTRIES)
		goto done;

	/* clear out dcbx_state for all entries */
	for (i = 0; i < shmaddr->num_entries; i++)
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
	int i;
	int rval = 0;

	shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE, 0);

	if (shmid < 0)
		return rval;

	shmaddr = (struct lldpad_shm_tbl *)shmat(shmid, NULL, 0);
	if ((long) shmaddr == -1)
		return rval;

	/* check for invalid number of shm table entries */
	if (shmaddr->num_entries < 0 ||
		shmaddr->num_entries > MAX_LLDPAD_SHM_ENTRIES)
		goto done;

	/* search for existing entry */
	for (i = 0; i < shmaddr->num_entries; i++)
		if (strcmp(shmaddr->ent[i].ifname, device_name) == 0)
			break;

	if (i < MAX_LLDPAD_SHM_ENTRIES) {
		if (i == shmaddr->num_entries) {
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
	int i;
	int rval = 0;

	shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE, 0);

	if (shmid < 0)
		return rval;

	shmaddr = (struct lldpad_shm_tbl *)shmat(shmid, NULL, 0);
	if ((long) shmaddr == -1)
		return rval;

	/* check for invalid number of shm table entries */
	if (shmaddr->num_entries <= 0 ||
		shmaddr->num_entries > MAX_LLDPAD_SHM_ENTRIES)
		goto done;

	/* search for existing entry */
	for (i = 0; i < shmaddr->num_entries; i++)
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
	struct lldpad_shm_tbl *shmaddr=NULL;
	int i;
	int j;
	int rval = 0;

	shmid = shmget(LLDPAD_SHM_KEY, LLDPAD_SHM_SIZE, 0);

	if (shmid < 0) {
		printf("failed to shmget\n");
		return rval;
	}

	shmaddr = (struct lldpad_shm_tbl *)shmat(shmid, NULL, 0);
	if ((long) shmaddr == -1) {
		printf("failed to shmat\n");
		return rval;
	}

	printf("pid = %d\n", shmaddr->pid);
	printf("num_entries = %d\n", shmaddr->num_entries);
	printf("max num_entries = %d\n", MAX_LLDPAD_SHM_ENTRIES);

	/* check for invalid number of shm table entries */
	if (shmaddr->num_entries <= 0 ||
		shmaddr->num_entries > MAX_LLDPAD_SHM_ENTRIES)
		goto done;

	for (i = 0; i < shmaddr->num_entries; i++) {
		printf("ifname:     %s\n", shmaddr->ent[i].ifname);
		printf("chassisid:  ");
		for (j = 0; j < shmaddr->ent[i].chassisid_len; j++)
			printf("%02x", (unsigned char)shmaddr->ent[i].chassisid[j]);
		printf("\n");
		printf("portid:     ");
		for (j = 0; j < shmaddr->ent[i].portid_len; j++)
			printf("%02x", (unsigned char)shmaddr->ent[i].portid[j]);
		printf("\n");
		printf("SeqNo:       %d\n", shmaddr->ent[i].st.SeqNo);
		printf("AckNo:       %d\n", shmaddr->ent[i].st.AckNo);
		printf("FCoEenable:  %d\n", shmaddr->ent[i].st.FCoEenable);
		printf("iSCSIenable: %d\n", shmaddr->ent[i].st.iSCSIenable);
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
