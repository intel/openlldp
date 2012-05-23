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
#include <assert.h>
#include <stdbool.h>
#include <sys/queue.h>
#include "lldp/ports.h"
#include "dcb_types.h"
#include "dcb_protocol.h"
#include "dcb_driver_interface.h"
#include "dcb_persist_store.h"
#include "dcb_rule_chk.h"
#include "dcb_events.h"
#include "messages.h"
#include "lldp.h"
#include "tlv_dcbx.h"
#include "lldp_rtnl.h"
#include "lldpad_shm.h"
#include "linux/if.h"
#include "linux/dcbnl.h"

static void handle_opermode_true(char *device_name);
u8        gdcbx_subtype = dcbx_subtype2;

int set_configuration(char *device_name, u32 EventFlag);

int pg_not_initted = true;
struct pg_store1 {
	char ifname[MAX_DESCRIPTION_LEN];
	pg_attribs *second;
	LIST_ENTRY(pg_store1) entries;
};
typedef struct pg_store1 * pg_it;
LIST_HEAD(pghead, pg_store1) pg, peer_pg, oper_pg;

/*todo: check  MAX_DESCRIPTION_LEN?*/
struct pg_store1 *pg_find(struct pghead *head, char *ifname)
{
	struct pg_store1 *p = NULL;

	for (p = head->lh_first; p != NULL; p = p->entries.le_next)
		if (!strcmp(p->ifname, ifname))
			return p;
	return p;
}

void pg_insert(struct pghead *head, char *ifname, pg_attribs *store)
{
	struct pg_store1 *entry = NULL;
	entry = (struct pg_store1 *)malloc(sizeof(struct pg_store1));
	if (!entry)
		return;
	strncpy(entry->ifname, ifname, sizeof(entry->ifname));
	entry->second = store;
	LIST_INSERT_HEAD(head, entry, entries);
}

void pg_erase(pg_it *p)
{
	/* save the reserved memory here so we can free
	 * it since erase wipes out the it structure
	 * (but does not free the memory) */
	void *itp = (void *)(*p)->second;
	/* this line frees the param of this function! */
	LIST_REMOVE(*p, entries);
	if (itp) {
		free (itp);
		itp = NULL;
	}

	free(*p);
	*p = NULL;
}

int pfc_not_initted = true;
struct pfc_store {
	char ifname[MAX_DESCRIPTION_LEN];
	pfc_attribs *second;
	LIST_ENTRY(pfc_store) entries;
};
typedef struct pfc_store * pfc_it;
LIST_HEAD(pfchead, pfc_store) pfc, peer_pfc, oper_pfc;

struct pfc_store *pfc_find(struct pfchead *head, char *ifname)
{
	struct pfc_store *p = NULL;
	for (p = head->lh_first; p != NULL; p = p->entries.le_next)
		if (!strcmp(p->ifname, ifname))
			return p;
	return p;
}
void pfc_insert(struct pfchead *head, char *ifname, pfc_attribs *store)
{
	struct pfc_store *entry;
	entry = (struct pfc_store *) malloc(sizeof(struct pfc_store));
	if (!entry)
		return;
	strcpy(entry->ifname, ifname);
	entry->second = store;
	LIST_INSERT_HEAD(head, entry, entries);
}

void pfc_erase(pfc_it *p)
{
	void *itp = (void *)(*p)->second;

	LIST_REMOVE(*p, entries);
	if (itp) {
		free(itp);
		itp = NULL;
	}

	free(*p);
	*p = NULL;
}

int pgdesc_not_initted = true;
struct pg_desc_store {
	char ifname[MAX_DESCRIPTION_LEN];
	pg_info *second;
	LIST_ENTRY(pg_desc_store) entries;
};
typedef struct pg_desc_store * pg_desc_it;
LIST_HEAD(pgdesc_head, pg_desc_store) pg_desc;

struct pg_desc_store *pgdesc_find(struct pgdesc_head *head, char *ifname)
{
	struct pg_desc_store *p = NULL;
	for (p = head->lh_first; p != NULL; p = p->entries.le_next)
		if (!strcmp(p->ifname, ifname))
			return p;
	return p;
}
void pgdesc_insert(struct pgdesc_head *head, char *ifname, pg_info *store)
{
	struct pg_desc_store *entry;
	entry = (struct pg_desc_store *) malloc(sizeof(struct pg_desc_store));
	if (!entry)
		return;
	strcpy(entry->ifname, ifname);
	entry->second = store;
	LIST_INSERT_HEAD(head, entry, entries);
}

void pgdesc_erase(pg_desc_it *p)
{
	void *itp = (void *)(*p)->second;
	LIST_REMOVE(*p, entries);
	if (itp) {
		free(itp);
		itp = NULL;
	}

	free(*p);
	*p = NULL;
}

int app_not_initted = true;
struct app_store {
	char ifname[MAX_DESCRIPTION_LEN];
	u32 app_subtype;
	app_attribs *second;
	LIST_ENTRY(app_store) entries;
};
typedef struct app_store * app_it;
LIST_HEAD(apphead, app_store) apptlv, peer_apptlv, oper_apptlv;

struct app_store *apptlv_find(struct apphead *head, char *ifname, u32 subtype)
{
	struct app_store *p = NULL;
	for (p = head->lh_first; p != NULL; p = p->entries.le_next)
		if (!strcmp(p->ifname, ifname) && (p->app_subtype == subtype))
			return p;
	return p;
}

void apptlv_insert(struct apphead *head, char *ifname, u32 subtype,
			app_attribs *store)
{
	struct app_store *entry;
	entry = (struct app_store *) malloc(sizeof(struct app_store));
	if (!entry)
		return;
	strcpy(entry->ifname, ifname);
	entry->second = store;
	entry->app_subtype = subtype;
	LIST_INSERT_HEAD(head, entry, entries);
}

void apptlv_erase(app_it *p)
{
	void *itp = (void *)(*p)->second;
	LIST_REMOVE(*p, entries);
	if (itp) {
		free (itp);
		itp = NULL;
	}

	free(*p);
	*p = NULL;
}


int llink_not_initted = true;
struct llink_store {
	char ifname[MAX_DESCRIPTION_LEN];
	u32 llink_subtype;
	llink_attribs *second;
	LIST_ENTRY(llink_store) entries;
};
typedef struct llink_store * llink_it;
LIST_HEAD(llinkhead, llink_store) llink, peer_llink, oper_llink;

struct llink_store *llink_find(struct llinkhead *head, char *ifname,
				u32 subtype)
{
	struct llink_store *p = NULL;
	for (p = head->lh_first; p != NULL; p = p->entries.le_next)
		if (!strcmp(p->ifname, ifname) && p->llink_subtype == subtype)
			return p;
	return p;
}
void llink_insert(struct llinkhead *head, char *ifname, llink_attribs *store,
			u32 subtype)
{
	struct llink_store *entry;
	entry = (struct llink_store *) malloc(sizeof(struct llink_store));
	if (!entry)
		return;
	strcpy(entry->ifname, ifname);
	entry->second = store;
	entry->llink_subtype = subtype;
	LIST_INSERT_HEAD(head, entry, entries);
}

void llink_erase(llink_it *p)
{
	void *itp = (void *)(*p)->second;
	LIST_REMOVE(*p, entries);
	if (itp) {
		free(itp);
		itp = NULL;
	}

	free(*p);
	*p = NULL;
}

int ctrl_not_initted = true;
struct dcb_control_protocol {
	char ifname[MAX_DESCRIPTION_LEN];
	control_protocol_attribs *second;
	LIST_ENTRY(dcb_control_protocol) entries;
};
typedef struct dcb_control_protocol * control_prot_it;
LIST_HEAD(control_prot_head, dcb_control_protocol)\
		dcb_control_prot, dcb_peer_control_prot;

struct dcb_control_protocol *ctrl_prot_find(struct control_prot_head *head,
						const char *ifname)
{
	struct dcb_control_protocol *p = NULL;
	for (p = head->lh_first; p != NULL; p = p->entries.le_next)
		if (!strcmp(p->ifname, ifname))
			return p;
	return p;
}
void ctrl_prot_insert(struct control_prot_head *head, char *ifname,
			control_protocol_attribs *store)
{
	struct dcb_control_protocol *entry;
	entry = (struct dcb_control_protocol *)
			malloc(sizeof(struct dcb_control_protocol));
	if (!entry)
		return;
	strcpy(entry->ifname, ifname);
	entry->second = store;
	LIST_INSERT_HEAD(head, entry, entries);
}

void ctrl_prot_erase(control_prot_it *p)
{
	void *itp = (void *)(*p)->second;
	LIST_REMOVE(*p, entries);
	if (itp) {
		free(itp);
		itp = NULL;
	}

	free(*p);
	*p = NULL;
}

int feature_not_initted = true;
struct features_store {
	char ifname[MAX_DESCRIPTION_LEN];
	feature_support *second;
	LIST_ENTRY(features_store) entries;
};
typedef struct features_store * features_it;
LIST_HEAD(featurehead, features_store) feature_struct;

struct features_store *features_find(struct featurehead *head, char *ifname)
{
	struct features_store *p = NULL;
	for (p = head->lh_first; p != NULL; p = p->entries.le_next)
		if (!strcmp(p->ifname, ifname))
			return p;
	return p;
}
void features_insert(struct featurehead *head, char *ifname,
			feature_support *store)
{
	struct features_store *entry;
	entry = (struct features_store *)malloc(sizeof(struct features_store));
	if (!entry)
		return;
	strcpy(entry->ifname, ifname);
	entry->second = store;
	LIST_INSERT_HEAD(head, entry, entries);
}

void features_erase(features_it *p)
{
	void *itp = (void *)(*p)->second;
	LIST_REMOVE(*p, entries);

	if (itp) {
		free(itp);
		itp = NULL;
	}

	free(*p);
	*p = NULL;
}

/* Add the store pointer to init_pg, i.e. memset store to 0,
 * then copy attribs to store
 */
void init_pg(pg_attribs *Attrib, pg_attribs *Store)
{
	memset(Store,0,sizeof(*Store));

	Attrib->protocol.Max_version = DCB_PG_MAX_VERSION;
	Attrib->protocol.State = DCB_INIT;
	Attrib->protocol.Advertise_prev = false;
	Attrib->protocol.tlv_sent = false;
	Attrib->protocol.dcbx_st = gdcbx_subtype & MASK_DCBX_FORCE;
	memcpy(Store, Attrib, sizeof (*Attrib));
}

/* pass in the pointer to attrib */
bool add_pg(char *device_name, pg_attribs *Attrib)
{
	pg_it it = pg_find(&pg, device_name);
	if (it == NULL) {
		/* Device not present: add */
		pg_attribs *store =
			(pg_attribs*) malloc(sizeof(*store));
		if (!store)
			return false;

		init_pg(Attrib, store);
		pg_insert(&pg, device_name, store);
	} else {  /* already in data store, just update it */
		it->second->protocol.Advertise_prev =
				(*it).second->protocol.Advertise;
		it->second->protocol.Advertise = Attrib->protocol.Advertise;
		it->second->protocol.Enable = Attrib->protocol.Enable;
		it->second->protocol.Willing = Attrib->protocol.Willing;

		memcpy(&(it->second->rx), &(Attrib->rx), sizeof(Attrib->rx));
		memcpy(&(it->second->tx), &(Attrib->tx), sizeof(Attrib->tx));
	}
	return true;
}

void init_oper_pg(pg_attribs *Attrib)
{
	char sTmp[MAX_DESCRIPTION_LEN];

	memset(Attrib,0,sizeof(*Attrib));
	snprintf(sTmp, MAX_DESCRIPTION_LEN, DEF_CFG_STORE);
	pg_it itpg = pg_find(&pg, sTmp);

	if (itpg == NULL)
		return;

	memcpy(&(Attrib->rx), &(itpg->second->rx), sizeof(Attrib->rx));
	memcpy(&(Attrib->tx), &(itpg->second->tx), sizeof(Attrib->tx));
}

bool add_oper_pg(char *device_name)
{
	pg_it it = pg_find(&oper_pg, device_name);
	if (it == NULL) {
		/* Device not present: add */
		pg_attribs *store =
			(pg_attribs*) malloc(sizeof(*store));

		if (!store)
			return false;

		init_oper_pg( store);
		pg_insert(&oper_pg, device_name, store);
	}
	return true;
}

void init_peer_pg(pg_attribs *Attrib)
{
	memset(Attrib,0,sizeof(*Attrib));
	Attrib->protocol.TLVPresent =  false;
}

bool add_peer_pg(char *device_name)
{
	pg_it it = pg_find(&peer_pg, device_name);
	if (it == NULL) {
		/* Device not present: add */
		pg_attribs *store = (pg_attribs*) malloc(sizeof(*store));

		if (!store)
			return false;

		init_peer_pg( store);
		pg_insert(&peer_pg, device_name, store);
	}
	return true;
}

void init_apptlv(app_attribs *Attrib, app_attribs *Store)
{
	memset(Store,0,sizeof(*Store));
	Attrib->protocol.Max_version     = DCB_APPTLV_MAX_VERSION;
	Attrib->protocol.State           = DCB_INIT;
	Attrib->protocol.Advertise_prev  = false;
	Attrib->protocol.tlv_sent        = false;
	Attrib->protocol.dcbx_st         = gdcbx_subtype & MASK_DCBX_FORCE;
	memcpy(Store, Attrib, sizeof (*Attrib));
}

bool valid_subtype(dcbx_state *state, u32 Subtype)
{

	if (state == NULL)
		return 0;

	switch (Subtype) {

	case APP_FCOE_STYPE:
		return state->FCoEenable;
	case APP_ISCSI_STYPE:
		return state->iSCSIenable;
	case APP_FIP_STYPE:
		return state->FIPenable;
	default:
		return 0;

	}
}

bool add_apptlv(char *device_name, app_attribs *Attrib, u32 Subtype,
	dcbx_state *state)
{
	full_dcb_attrib_ptrs  attr_ptr;

	/* If FCoE is enabled in the DCBX state record,
	 * then enable the FCoE App object and persist the change.
	*/
	if (valid_subtype(state, Subtype) && !Attrib->protocol.Enable) {
		Attrib->protocol.Enable = true;
		memset(&attr_ptr, 0, sizeof(attr_ptr));
		attr_ptr.app = Attrib;
		attr_ptr.app_subtype = (u8)Subtype;
		if (set_persistent(device_name, &attr_ptr) !=
			cmd_success) {
			LLDPAD_DBG("Set persistent failed in add_apptlv, "
				   " subtype: %d\n", Subtype);
			return false;
		}
	}

	app_it it = apptlv_find(&apptlv, device_name, Subtype);
	if (it == NULL) {
		/* Device not present: add */
		app_attribs *store = (app_attribs*)malloc(sizeof(*store));
		if (!store)
			return false;

		init_apptlv(Attrib, store);
		apptlv_insert(&apptlv, device_name, Subtype, store);
	}
	else {  /* already in data store, just update it */
		it->second->protocol.Advertise_prev =
			it->second->protocol.Advertise;
		it->second->protocol.Advertise = Attrib->protocol.Advertise;
		it->second->protocol.Enable = Attrib->protocol.Enable;
		it->second->protocol.Willing = Attrib->protocol.Willing;
		it->second->Length = Attrib->Length;
		memcpy(it->second->AppData, Attrib->AppData, Attrib->Length);
	}
	return true;
}

void init_oper_apptlv(app_attribs *Store, u32 Subtype)
{
	memset(Store,0,sizeof(*Store));

	app_it itapp = apptlv_find(&oper_apptlv, DEF_CFG_STORE, Subtype);
	if (itapp == NULL) {
		return;
	}
	Store->Length =itapp->second->Length;
	memcpy(&(Store->AppData), &(itapp->second->AppData),
			sizeof(Store->Length));
}

bool add_oper_apptlv(char *device_name, u32 Subtype)
{
	app_it it = apptlv_find(&oper_apptlv, device_name, Subtype);
	if (it == NULL) {
		/* Device not present: add */
		app_attribs *store = (app_attribs*)malloc(sizeof(*store));
		if (!store)
			return false;
		init_oper_apptlv(store, Subtype);
		apptlv_insert(&oper_apptlv, device_name, Subtype, store);
	}
	return true;
}

void init_peer_apptlv(app_attribs *Store)
{
	memset(Store,0,sizeof(*Store));
}

bool add_peer_apptlv(char *device_name, u32 Subtype)
{
	app_it it = apptlv_find(&peer_apptlv, device_name, Subtype);
	if (it == NULL) {
		/* Device not present: add */
		app_attribs *store = (app_attribs*)malloc(sizeof(*store));
		if (!store)
			return false;

		init_peer_apptlv(store);
		apptlv_insert(&peer_apptlv, device_name, Subtype, store);
	}
	return true;
}

void init_control_prot(control_protocol_attribs *Attrib, dcbx_state *state)
{
	memset(Attrib,0,sizeof(*Attrib));
	Attrib->State = DCB_INIT;
	Attrib->Max_version = DCB_MAX_VERSION;
	Attrib->SeqNo = state->SeqNo;
	Attrib->AckNo = state->AckNo;
	Attrib->MyAckNo = state->SeqNo;
}

bool add_control_protocol(char *device_name, dcbx_state *state)
{
	control_prot_it it = ctrl_prot_find(&dcb_control_prot, device_name);
	if (it == NULL) {
		/* Device not present: add */
		control_protocol_attribs *store =
			(control_protocol_attribs*)malloc(sizeof(*store));

		if (!store)
			return false;

		init_control_prot(store, state);
		ctrl_prot_insert(&dcb_control_prot, device_name, store);
	} else if (get_operstate(device_name) == IF_OPER_DORMANT) {
		init_control_prot(it->second, state);
	}

	return true;
}

void init_peer_control_prot(control_protocol_attribs *Attrib)
{
	memset(Attrib,0,sizeof(*Attrib));
	Attrib->Oper_version = DCB_MAX_VERSION;
	Attrib->Max_version = DCB_MAX_VERSION;
	Attrib->RxDCBTLVState = DCB_PEER_NONE;
}

bool add_peer_control_protocol(char *device_name)
{
	control_prot_it it = ctrl_prot_find(&dcb_peer_control_prot,
						device_name);
	if (it == NULL) {
		/* Device not present: add */
		control_protocol_attribs *store =
			(control_protocol_attribs*)malloc(sizeof(*store));

		if (!store)
			return false;

		init_peer_control_prot( store);
		ctrl_prot_insert(&dcb_peer_control_prot, device_name, store);
	}
	return true;
}

void init_pfc(pfc_attribs *Attrib, pfc_attribs *Store)
{
	memset(Store,0,sizeof(*Store));
	Attrib->protocol.Max_version = DCB_PFC_MAX_VERSION;
	Attrib->protocol.State = DCB_INIT;
	Attrib->protocol.Advertise_prev = false;
	Attrib->protocol.tlv_sent = false;
	Attrib->protocol.dcbx_st = gdcbx_subtype & MASK_DCBX_FORCE;
	memcpy(Store, Attrib, sizeof(*Attrib));
}

bool add_pfc(char *device_name, pfc_attribs *Attrib)
{
	pfc_it it = pfc_find(&pfc, device_name);
	if (it == NULL) {
		/* Device not present: add */
		pfc_attribs *store =
			(pfc_attribs*)malloc(sizeof(*store));
		if (!store)
			return false;

		init_pfc(Attrib, store);
		pfc_insert(&pfc, device_name, store);
	} else {  /* already present in store, just update */
		it->second->protocol.Advertise_prev =
			it->second->protocol.Advertise;
		it->second->protocol.Advertise = Attrib->protocol.Advertise;
		it->second->protocol.Enable = Attrib->protocol.Enable;
		it->second->protocol.Willing = Attrib->protocol.Willing;
		memcpy(it->second->admin, Attrib->admin,
			sizeof(Attrib->admin));
	}
	return true;
}

void init_oper_pfc(pfc_attribs *Attrib)
{
	char sTmp[MAX_DESCRIPTION_LEN];

	memset(Attrib,0,sizeof(*Attrib));
	snprintf(sTmp, MAX_DESCRIPTION_LEN, DEF_CFG_STORE);
	pfc_it itpfc = pfc_find(&oper_pfc, sTmp);

	if (itpfc == NULL)
		return;

	memcpy(&(Attrib->admin), &(itpfc->second->admin), sizeof(Attrib->admin));
}

bool add_oper_pfc(char *device_name)
{
	pfc_it it = pfc_find(&oper_pfc, device_name);
	if (it == NULL) {
		/* Device not present: add */
		pfc_attribs *store = (pfc_attribs*)malloc(sizeof(*store));

		if (!store)
			return false;

		init_oper_pfc(store);
		pfc_insert(&oper_pfc, device_name, store);
	}

	return true;
}

void init_peer_pfc(pfc_attribs *Attrib)
{
	memset(Attrib,0,sizeof(*Attrib));
	Attrib->protocol.TLVPresent =  false;
}

bool add_peer_pfc(char *device_name)
{
	pfc_it it = pfc_find(&peer_pfc, device_name);
	if (it == NULL) {
		/* Device not present: add */
		pfc_attribs *store = (pfc_attribs*)malloc(sizeof(*store));

		if (!store)
			return false;

		init_peer_pfc(store);
		pfc_insert(&peer_pfc, device_name, store);
	}
	return true;
}

void init_bwg_desc(pg_info *Attrib, pg_info *Store)
{
	memset(Store,0,sizeof(*Store));
	memcpy(Store, Attrib, sizeof(*Attrib));
}

bool add_bwg_desc(char *device_name, pg_info *Attrib)
{
	pg_desc_it it = pgdesc_find(&pg_desc, device_name);
	if (it == NULL) {
		/* Device not present: add */
		pg_info *store = (pg_info*)malloc(sizeof(*store));

		if (!store)
			return false;

		init_bwg_desc(Attrib, store);
		store->max_pgid_desc = 8;
		pgdesc_insert(&pg_desc, device_name, store);
	}
	return true;
}

/* Logical Link */
void init_llink(llink_attribs *Attrib, llink_attribs *Store)
{
	memset(Store,0,sizeof(*Store));
	Attrib->protocol.Max_version = DCB_LLINK_MAX_VERSION;
	Attrib->protocol.State = DCB_INIT;
	Attrib->protocol.Advertise_prev = false;
	Attrib->protocol.tlv_sent = false;
	Attrib->protocol.dcbx_st = gdcbx_subtype & MASK_DCBX_FORCE;
	memcpy(Store, Attrib, sizeof(*Attrib));
}

bool add_llink(char *device_name, llink_attribs *Attrib, u32 subtype)
{
	llink_it it = llink_find(&llink, device_name, subtype);
	if (it == NULL) {
		/* Device not present: add */
		llink_attribs *store = (llink_attribs*)malloc(sizeof(*store));
		if (!store)
			return false;

		init_llink(Attrib, store);
		llink_insert(&llink, device_name, store, subtype);
	} else {  /* already present in store, just update */
		it->second->protocol.Advertise_prev =
			it->second->protocol.Advertise;
		it->second->protocol.Advertise = Attrib->protocol.Advertise;
		it->second->protocol.Enable = Attrib->protocol.Enable;
		it->second->protocol.Willing = Attrib->protocol.Willing;

		memcpy(&(it->second->llink), &(Attrib->llink),
			sizeof(Attrib->llink));
	}
	return true;
}

void init_oper_llink(llink_attribs *Attrib, u32 subtype)
{
	memset(Attrib,0,sizeof(*Attrib));

	llink_it itllink = llink_find(&oper_llink, DEF_CFG_STORE, subtype);
	if (itllink == NULL)
		return;

	memcpy(&(Attrib->llink), &(itllink->second->llink),
			sizeof(Attrib->llink));
}

bool add_oper_llink(char *device_name, u32 subtype)
{
	llink_it it = llink_find(&oper_llink, device_name, subtype);
	if (it == NULL) {
		/* Device not present: add */
		llink_attribs *store = (llink_attribs*)malloc(sizeof(*store));
		if (!store)
			return false;

		init_oper_llink(store, subtype);
		llink_insert(&oper_llink, device_name, store, subtype);
	}
	return true;
}

void init_peer_llink(llink_attribs *Attrib)
{
	memset(Attrib,0,sizeof(*Attrib));
	Attrib->protocol.TLVPresent =  false;
}

bool add_peer_llink(char *device_name, u32 subtype)
{
	llink_it it = llink_find(&peer_llink, device_name, subtype);
	if (it == NULL) {
		/* Device not present: add */
		llink_attribs *store = (llink_attribs*)malloc(sizeof(*store));
		if (!store)
			return false;

		init_peer_llink(store);
		llink_insert(&peer_llink, device_name, store, subtype);
	}
	return true;
}

bool init_dcb_support(char *device_name, full_dcb_attribs *attrib)
{
	feature_support dcb_support;

	memset(&dcb_support, 0, sizeof(feature_support));
	if (get_dcb_capabilities(device_name, &dcb_support) != 0)
		return false;

	/*if (!dcb_support.pg) {
	 *    attrib->pg.protocol.Enable = false;
	 *    attrib->pg.protocol.Advertise = false;
	 *}
	 *if (!dcb_support.pfc) {
	 *    attrib->pfc.protocol.Enable = false;
	 *    attrib->pfc.protocol.Advertise = false;
	 *}
	 */

	if (get_dcb_numtcs(device_name, &attrib->pg.num_tcs,
		&attrib->pfc.num_tcs) != 0) {
		return false;
	}

	features_it it = features_find(&feature_struct, device_name);
	if (it == NULL) {
		/* Device not present: add */
		feature_support *store = (feature_support*)
						malloc(sizeof(*store));
		if (!store)
			return false;

		memcpy(store, (void *)&dcb_support, sizeof(*store));
		features_insert(&feature_struct, device_name, store);
	}
	return true;
}

cmd_status get_dcb_support(char *device_name,  feature_support *dcb_support)
{
	cmd_status          result = cmd_success;
	feature_support     features;
	full_dcb_attribs    attribs;

	memset(&attribs, 0, sizeof(attribs));
	memset(&features, 0, sizeof(feature_support));

	if (!dcb_support)
		return cmd_bad_params;

	features_it it = features_find(&feature_struct, device_name);
	if (it != NULL) {
		memcpy(dcb_support, it->second, sizeof(*dcb_support));
	} else {
		if (get_persistent(device_name, &attribs) != cmd_success) {
			result = cmd_device_not_found;
			goto Exit;
		}
		if (!init_dcb_support(device_name, &attribs)) {
			result = cmd_device_not_found;
			goto Exit;
		}
		/*todo: this was called twice?*/
		memset(&features, 0, sizeof(feature_support));
		features_it it = features_find(&feature_struct, device_name);
		if (it != NULL) {
			memcpy(dcb_support, it->second, sizeof(*dcb_support));
		} else {
			result = cmd_device_not_found;
		}
	}
Exit:
	return result;
}

void remove_dcb_support(void)
{
	while (feature_struct.lh_first != NULL)     /* Delete. */
		features_erase(&feature_struct.lh_first);
}

int dcbx_add_adapter(char *device_name)
{
	u32 EventFlag = 0;
	full_dcb_attrib_ptrs attr_ptr;
	full_dcb_attribs attribs;
	feature_support dcb_support = { .pg = 0 };
	cmd_status sResult = cmd_success;
	dcbx_state state;
	int i = 0;

	memset(&attribs, 0, sizeof(attribs));

	sResult = get_persistent(device_name, &attribs);
	if (sResult != cmd_success) {
		LLDPAD_DBG("get_persistent returned error %d\n", sResult);
		sResult = cmd_failed;
		goto add_adapter_error;
	}

	LLDPAD_DBG("  dcbx subtype = %d\n", gdcbx_subtype);

	memset (&attr_ptr, 0, sizeof(attr_ptr));
	attr_ptr.pg = &(attribs.pg);
	attr_ptr.pfc = &(attribs.pfc);

	memset(&state, 0, sizeof(state));
	get_dcbx_state(device_name, &state);

	/* Create data stores for the device. */
	if (!init_dcb_support(device_name, &attribs)) {
		sResult = cmd_failed;
		goto add_adapter_error;
	}

	sResult = dcb_check_config(&attr_ptr);
	if (sResult != cmd_success)
		LLDPAD_WARN("Rule checker returned error %d\n", sResult);

	if (!add_pg(device_name, &attribs.pg)) {
		LLDPAD_DBG("add_pg error.\n");
		sResult = cmd_failed;
		goto add_adapter_error;
	}
	if (!add_pfc(device_name, &attribs.pfc)) {
		LLDPAD_DBG("add_pfc error.\n");
		sResult = cmd_failed;
		goto add_adapter_error;
	}
	if (!add_bwg_desc(device_name, &attribs.descript)) {
		LLDPAD_DBG("add_bwg_desc error.\n");
		sResult = cmd_failed;
		goto add_adapter_error;
	}
	if (!add_control_protocol(device_name, &state)) {
		LLDPAD_DBG("add_control_protocol error.\n");
		sResult = cmd_failed;
		goto add_adapter_error;
	}
	if (!add_peer_pg(device_name)) {
		LLDPAD_DBG("add_peer_pg error.\n");
		sResult = cmd_failed;
		goto add_adapter_error;
	}
	if (!add_peer_pfc(device_name)) {
		LLDPAD_DBG("add_peer_pfc error.\n");
		sResult = cmd_failed;
		goto add_adapter_error;
	}
	if (!add_peer_control_protocol(device_name)) {
		LLDPAD_DBG("add_peer_control_protocol error.\n");
		sResult = cmd_failed;
		goto add_adapter_error;
	}
	if (!add_oper_pg(device_name)) {
		LLDPAD_DBG("add_oper_pg error.\n");
		sResult = cmd_failed;
		goto add_adapter_error;
	}
	if (!add_oper_pfc(device_name)) {
		LLDPAD_DBG("add_oper_pfc error.\n");
		sResult = cmd_failed;
		goto add_adapter_error;
	}
	/* Add APPTLV for supported Subtypes. */
	for (i = 0; i < DCB_MAX_APPTLV; i++) {
		if (!add_apptlv(device_name,
			&attribs.app[i], i, &state)) {
			LLDPAD_DBG("add_apptlv error.\n");
			sResult = cmd_failed;
			goto add_adapter_error;
		}
		if (!add_oper_apptlv(device_name, i)) {
			LLDPAD_DBG("add_oper_apptlv error.\n");
			sResult = cmd_failed;
			goto add_adapter_error;
		}
		if (!add_peer_apptlv(device_name, i)) {
			LLDPAD_DBG("add_peer_apptlv error.\n");
			sResult = cmd_failed;
			goto add_adapter_error;
		}
	}
	for (i = 0; i < DCB_MAX_LLKTLV; i++) {
		if (!add_llink(device_name, &attribs.llink[i], i)) {
			LLDPAD_DBG("%s add_llink error.\n",
				    device_name);
			sResult = cmd_failed;
			goto add_adapter_error;
		}
		if (!add_oper_llink(device_name, i)) {
			LLDPAD_DBG("add_oper_llink error.\n");
			sResult = cmd_failed;
			goto add_adapter_error;
		}
		if (!add_peer_llink(device_name, i)) {
			LLDPAD_DBG("add_peer_llink error.\n");
			sResult = cmd_failed;
			goto add_adapter_error;
		}
	}

	if (get_dcb_support(device_name, &dcb_support) != cmd_success) {
		sResult = cmd_failed;
		goto add_adapter_error;
	}


	/* Initialize features state machines for PG and PFC and
	 * APPTLVs. */
	if (run_feature_protocol(device_name,
		DCB_LOCAL_CHANGE_PG, SUBTYPE_DEFAULT) !=
		cmd_success) {
		LLDPAD_DBG("run_feature_protocol error (PG)\n");
		sResult = cmd_failed;
		goto add_adapter_error;
	}
	if (run_feature_protocol(device_name,
		DCB_LOCAL_CHANGE_PFC, SUBTYPE_DEFAULT) != cmd_success) {
		LLDPAD_DBG("run_feature_protocol error (PFC)\n");
		sResult = cmd_failed;
		goto add_adapter_error;
	}
	/* If APPTLV subtypes are supported then run the
	 * feat_prot for those supported subtypes. */
	for (i = 0; i < DCB_MAX_APPTLV ; i++) {
		if (run_feature_protocol(device_name,
			DCB_LOCAL_CHANGE_APPTLV(i), i) !=
			cmd_success) {
			LLDPAD_DBG("run_feature_protocol error (APP)\n");
			sResult = cmd_failed;
			goto add_adapter_error;
		}
	}
	for (i = 0; i < DCB_MAX_LLKTLV ; i++) {
		if (run_feature_protocol(device_name,
			DCB_LOCAL_CHANGE_LLINK, i) != cmd_success) {
			LLDPAD_DBG("run_feature_protocol error (LLINK)\n");
			sResult = cmd_failed;
			goto add_adapter_error;
		}
	}

	EventFlag = 0;
	DCB_SET_FLAGS(EventFlag, DCB_LOCAL_CHANGE_PG |
	DCB_LOCAL_CHANGE_PFC | DCB_LOCAL_CHANGE_LLINK);
	for (i = 0; i < DCB_MAX_APPTLV; i++)
		DCB_SET_FLAGS(EventFlag, DCB_LOCAL_CHANGE_APPTLV(i));
	/* Initialize control state machine */
	if (run_control_protocol(device_name, EventFlag) !=
		cmd_success) {
		LLDPAD_DBG("run_control_protocol error.\n");
		sResult = cmd_failed;
		goto add_adapter_error;
	}



add_adapter_error:
	if (sResult != cmd_success) {
		LLDPAD_DBG("add_adapter: Service unable to use network adapter\n");
		return false;
	}

	return true;
}

int dcbx_remove_adapter(char *device_name)
{
	char devName[MAX_DEVICE_NAME_LEN];
	void *itp = NULL;
	int not_default = 1;

	int i = 0;
	assert(device_name);
	not_default = memcmp(DEF_CFG_STORE, device_name,
		strlen(DEF_CFG_STORE));
	strncpy (devName, device_name, MAX_DEVICE_NAME_LEN);

	if (not_default)
		handle_opermode_true(device_name);

	features_it itfeat = features_find(&feature_struct, devName);
	if (itfeat != NULL) {
		LLDPAD_DBG("free: dcb support %p\n", itp);
		features_erase(&itfeat);

	} else {
		LLDPAD_DBG("remove_adapter: dcb support not found\n");
	}

	pg_it itpg = pg_find(&pg, devName);
	if (itpg != NULL) {
		/* this line frees the param of this function! */
		pg_erase(&itpg);
	} else {
		LLDPAD_DBG("remove_adapter: pg not found\n");
	}

	pfc_it itpfc = pfc_find(&pfc,devName);
	if (itpfc != NULL) {
		pfc_erase(&itpfc);
	} else {
		LLDPAD_DBG("remove_adapter: pfc not found\n");
	}

	pg_desc_it itbwg = pgdesc_find(&pg_desc, devName);
	if (itbwg != NULL) {
		pgdesc_erase(&itbwg);
	} else if (not_default) {
		LLDPAD_DBG("remove_adapter: pgid not found\n");
	}

	control_prot_it itcp = ctrl_prot_find(&dcb_control_prot, devName);
	if (itcp != NULL) {
		ctrl_prot_erase(&itcp);
	} else if (not_default) {
		LLDPAD_DBG("remove_adapter: ctrl not found\n");
	}

	pg_it itprpg = pg_find(&peer_pg, devName);
	if (itprpg != NULL) {
		pg_erase(&itprpg);
	} else if (not_default) {
		LLDPAD_DBG("remove_adapter: peer pg not found\n");
	}

	pfc_it itprpfc = pfc_find(&peer_pfc, devName);
	if (itprpfc != NULL) {
		pfc_erase(&itprpfc);
	} else if (not_default) {
		LLDPAD_DBG("remove_adapter: peer pfc not found\n");
	}

	control_prot_it itpcp = ctrl_prot_find(&dcb_peer_control_prot, devName);
	if (itpcp != NULL) {
		ctrl_prot_erase(&itpcp);
	} else if (not_default) {
		LLDPAD_DBG("remove_adapter: peer ctrl not found\n");
	}

	pg_it itopg = pg_find(&oper_pg, devName);
	if (itopg != NULL) {
		pg_erase(&itopg);
	} else if (not_default) {
		LLDPAD_DBG("remove_adapter: oper pg not found\n");
	}

	pfc_it itopfc = pfc_find(&oper_pfc, devName);
	if (itopfc != NULL) {
		pfc_erase(&itopfc);
	} else if (not_default) {
		LLDPAD_DBG("remove_adapter: oper pfc not found\n");
	}

	/* Get the APP TLV  and erase. */
	for (i = 0; i < DCB_MAX_APPTLV ; i++) {
		app_it itapp = apptlv_find(&apptlv, devName, i);
		if (itapp != NULL)
			apptlv_erase(&itapp);

		itapp = apptlv_find(&oper_apptlv, devName, i);
		if (itapp != NULL)
			apptlv_erase(&itapp);

		itapp = apptlv_find(&peer_apptlv, devName, i);
		if (itapp != NULL)
			apptlv_erase(&itapp);
	}
	for (i = 0; i < DCB_MAX_LLKTLV ; i++) {
		/* Release LLINK data store */
		llink_it itllink = llink_find(&llink, devName, i);
		if (itllink != NULL)
			llink_erase(&itllink);
		else
			LLDPAD_DBG("remove_adapter: llink not found\n");

		llink_it itprllink = llink_find(&peer_llink, devName, i);
		if (itprllink != NULL)
			llink_erase(&itprllink);
		else if (not_default)
			LLDPAD_DBG("remove_adapter: peer llink not found\n");

		llink_it itollink = llink_find(&oper_llink, devName, i);
		if (itollink != NULL)
			llink_erase(&itollink);
		else if (not_default)
			LLDPAD_DBG("remove_adapter: oper llink not found\n");
	}

	lldpad_shm_set_dcbx(device_name, dcbx_subtype0);
	return true;
}

cmd_status save_dcbx_state(const char *device_name)
{
	dcbx_state state;
	app_attribs app_data;

	control_prot_it ctrl_prot = ctrl_prot_find(&dcb_control_prot,
							device_name);

	if (ctrl_prot == NULL)
		return cmd_device_not_found;

	state.SeqNo = ctrl_prot->second->SeqNo;
	state.AckNo = ctrl_prot->second->AckNo;

	if (get_app((char *)device_name, 0, &app_data) == cmd_success)
		state.FCoEenable = app_data.protocol.Enable;
	else
		return cmd_bad_params;
	if (get_app((char *)device_name, 1, &app_data) == cmd_success)
		state.iSCSIenable = app_data.protocol.Enable;
	else
		return cmd_bad_params;

	if (set_dcbx_state(device_name, &state))
		return cmd_success;
	else
		return cmd_failed;
}

static int dcbx_free_app_config(char *device_name)
{
	app_it Oper, Local;
	appgroup_attribs app_data;

	/* Free FCoE APP data */
	Oper = apptlv_find(&oper_apptlv, device_name, APP_FCOE_STYPE);
	Local = apptlv_find(&apptlv, device_name, APP_FCOE_STYPE);
	if (Oper || Local) {
		app_data.dcb_app_idtype = DCB_APP_IDTYPE_ETHTYPE;
		app_data.dcb_app_id = APP_FCOE_ETHTYPE;
		app_data.dcb_app_priority = 0;
		set_hw_app(device_name, &app_data);
	}

	/* Free iSCSI APP data */
	Oper = apptlv_find(&oper_apptlv, device_name, APP_ISCSI_STYPE);
	Local = apptlv_find(&apptlv, device_name, APP_ISCSI_STYPE);
	if (Oper || Local) {
		app_data.dcb_app_idtype = DCB_APP_IDTYPE_PORTNUM;
		app_data.dcb_app_id = APP_ISCSI_PORT;
		app_data.dcb_app_priority = 0;

		set_hw_app(device_name, &app_data);
	}

	/* Free FIP APP data */
	Oper = apptlv_find(&oper_apptlv, device_name, APP_FIP_STYPE);
	Local = apptlv_find(&apptlv, device_name, APP_FIP_STYPE);
	if (Oper || Local) {
		app_data.dcb_app_idtype = DCB_APP_IDTYPE_ETHTYPE;
		app_data.dcb_app_id = APP_FIP_ETHTYPE;
		app_data.dcb_app_priority = 0;

		set_hw_app(device_name, &app_data);
	}

	return 0;
}

int dcbx_remove_all(void)
{
	pg_it it;

	clear_dcbx_state();

	for (it = pg.lh_first; it != NULL; it = it->entries.le_next) {
		if (!memcmp(DEF_CFG_STORE, it->ifname,
			strlen(DEF_CFG_STORE))) {
			continue;
		}

		save_dcbx_state(it->ifname);

		/* Remove kernel APP entries */
		dcbx_free_app_config(it->ifname);
	}

	return 0;
}

bool add_pg_defaults()
{
	pg_attribs pg_data;
	char sTmp[MAX_DESCRIPTION_LEN];
	bool result = true;
	int index, portion, rmndr, temp;

	/* todo:  - must be a better way and place to do this */
	if (pg_not_initted) {
		LIST_INIT(&pg);
		LIST_INIT(&oper_pg);
		LIST_INIT(&peer_pg);
		pg_not_initted = false;
	}

	memset(&pg_data, 0, sizeof(pg_attribs));

	pg_data.protocol.Enable = 1;
	pg_data.protocol.Willing = 1;
	pg_data.protocol.Advertise = 1;

	portion = BW_PERCENT/MAX_BANDWIDTH_GROUPS;
	rmndr   = BW_PERCENT % MAX_BANDWIDTH_GROUPS;

	temp = rmndr;
	for (index=0; index < MAX_BANDWIDTH_GROUPS; index++) {
		pg_data.tx.pg_percent[index] = (u8)portion;
		if (temp >0) {
			pg_data.tx.pg_percent[index] += 1;
			temp--;
		}
	}
	for (index=0; index < MAX_USER_PRIORITIES; index++) {
		pg_data.tx.up[index].pgid = (u8)(index);
		pg_data.tx.up[index].bwgid = (u8)index;
		pg_data.tx.up[index].percent_of_pg_cap = BW_PERCENT;
		pg_data.tx.up[index].strict_priority = dcb_none;
	}
	temp = rmndr;
	for (index=0; index < MAX_BANDWIDTH_GROUPS; index++) {
		pg_data.rx.pg_percent[index] = (u8)portion;
		if (temp >0) {
			pg_data.rx.pg_percent[index]++;
			temp--;
		}
	}
	for (index=0; index < MAX_USER_PRIORITIES; index++) {
		pg_data.rx.up[index].pgid = (u8)(index);
		pg_data.rx.up[index].bwgid = (u8)index;
		pg_data.rx.up[index].percent_of_pg_cap = BW_PERCENT;
		pg_data.rx.up[index].strict_priority = dcb_none;
	}

	snprintf(sTmp, MAX_DESCRIPTION_LEN, DEF_CFG_STORE);

	/* Create pg default data store for the device. */
	if (!add_pg(sTmp, &pg_data))
		result = false;

	return result;
}

bool add_pfc_defaults()
{
	pfc_attribs pfc_data;
	char        sTmp[MAX_DESCRIPTION_LEN];
	bool   result = true;
	int         index;

	/* todo:  - must be a better way and place to do this */
	if (pfc_not_initted) {
		LIST_INIT(&pfc);
		LIST_INIT(&oper_pfc);
		LIST_INIT(&peer_pfc);
		pfc_not_initted = false;
	}

	memset (&pfc_data, 0, sizeof(pfc_attribs));

	pfc_data.protocol.Enable = 1;
	pfc_data.protocol.Willing = 1;
	pfc_data.protocol.Advertise = 1;

	for (index=0; index < MAX_TRAFFIC_CLASSES; index++)
		pfc_data.admin[index] = pfc_disabled;

	snprintf(sTmp, MAX_DESCRIPTION_LEN, DEF_CFG_STORE);
	/* Create pfc default data store for the device. */
	if (!add_pfc(sTmp, &pfc_data))
		result = false;

	return result;
}

bool add_app_defaults(u32 subtype)
{
	app_attribs app_data;
	char        sTmp[MAX_DESCRIPTION_LEN];
	bool   result = true;

	/* todo:  - must be a better way and place to do this */
	if (app_not_initted) {
		LIST_INIT(&apptlv);
		LIST_INIT(&oper_apptlv);
		LIST_INIT(&peer_apptlv);
		app_not_initted = false;
	}

	memset(&app_data, 0, sizeof(app_attribs));

	app_data.protocol.Enable = 1;
	app_data.protocol.Willing = 1;
	app_data.protocol.Advertise = 1;

	snprintf(sTmp, MAX_DESCRIPTION_LEN, DEF_CFG_STORE);

	switch (subtype) {
	case APP_FCOE_STYPE:  /* FCoE subtype */
		app_data.Length = 1;
		app_data.AppData[0] = APP_FCOE_DEFAULT_DATA;
		break;
	case APP_ISCSI_STYPE:  /* iSCSI subtype */
		app_data.Length = 1;
		app_data.AppData[0] = APP_ISCSI_DEFAULT_DATA;
		break;
	case APP_FIP_STYPE:  /* FIP subtype */
		app_data.Length = 1;
		app_data.AppData[0] = APP_FIP_DEFAULT_DATA;
	default:
		break;
	}

	/* Create app default data store for the device and app subtype. */
	if (!add_apptlv(sTmp, &app_data, subtype, NULL))
		result = false;

	return result;
}

bool add_llink_defaults(u32 subtype)
{
	llink_attribs llink_data;
	char sTmp[MAX_DESCRIPTION_LEN];
	bool result = true;

	/* todo:  - must be a better way and place to do this */
	if (llink_not_initted) {
		LIST_INIT(&llink);
		LIST_INIT(&oper_llink);
		LIST_INIT(&peer_llink);
		llink_not_initted = false;
	}

	memset(&llink_data, 0, sizeof(llink_attribs));

	llink_data.protocol.Enable = 1;
	llink_data.protocol.Willing = 1;
	llink_data.protocol.Advertise = 1;
	llink_data.llink.llink_status = 0;

	snprintf(sTmp, MAX_DESCRIPTION_LEN, DEF_CFG_STORE);
	/* Create llink default data store for the device. */
	if (!add_llink(sTmp, &llink_data, subtype))
		result = false;

	return result;
}

cmd_status get_pg(char *device_name,  pg_attribs *pg_data)
{
	cmd_status result = cmd_success;
	full_dcb_attribs attribs;

	if (!pg_data)
		return cmd_bad_params;
	memset(&attribs, 0, sizeof(attribs));

	pg_it it = pg_find(&pg, device_name);
	if (it != NULL) {
		memcpy(pg_data, it->second, sizeof(*pg_data));
	} else {
		result = get_persistent(device_name, &attribs);
		if (result == cmd_success)
			memcpy(pg_data, &attribs.pg, sizeof(*pg_data));
		else
			result = cmd_device_not_found;
	}
	return result;
}

cmd_status get_oper_pg(char *device_name,  pg_attribs *pg_data)
{
	cmd_status result = cmd_success;

	if (!pg_data)
		return cmd_bad_params;
	pg_it it = pg_find(&oper_pg, device_name);
	if (it != NULL)
		memcpy(pg_data, it->second, sizeof(*pg_data));
	else
		result = cmd_device_not_found;
	return result;
}

cmd_status get_peer_pg(char *device_name,  pg_attribs *pg_data)
{
	cmd_status result = cmd_success;

	if (!pg_data)
		return cmd_bad_params;

	pg_it it = pg_find(&peer_pg, device_name);

	if (it != NULL)
		memcpy(pg_data, it->second, sizeof(*pg_data));
	else
		result = cmd_device_not_found;

	return result;
}

void mark_pg_sent(char *device_name)
{
	pg_it it = pg_find(&pg, device_name);
	if (it != NULL)
		it->second->protocol.tlv_sent = true;
}

void mark_pfc_sent(char *device_name)
{
	pfc_it it = pfc_find(&pfc, device_name);
	if (it != NULL)
		it->second->protocol.tlv_sent = true;
}

void mark_app_sent(char *device_name)
{
	app_it it;
	int i;

	for (i = 0; i < DCB_MAX_APPTLV; i++) {
		it = apptlv_find(&apptlv, device_name, i);
		if (it != NULL)
			it->second->protocol.tlv_sent = true;
	}
}

void mark_llink_sent(char *device_name, u32 subtype)
{
	llink_it it = llink_find(&llink, device_name, subtype);
	if (it != NULL)
		it->second->protocol.tlv_sent = true;
}

cmd_status put_pg(char *device_name, pg_attribs *pg_data, pfc_attribs *pfc_data)
{
	full_dcb_attribs 	attribs;
	full_dcb_attrib_ptrs	attr_ptr;
	u32 			EventFlag = 0;
	cmd_status		result = cmd_success;

	if (!pg_data)
		return cmd_bad_params;

	memset(&attribs, 0, sizeof(attribs));
	pg_it it = pg_find(&pg, device_name);
	if (it != NULL) {
		/* Lock the data first */

		/* detect no config change */
		if (memcmp(it->second, pg_data, sizeof(*pg_data)) == 0)
			goto Exit;

		/* Check the rules */
		memset(&attr_ptr, 0, sizeof(attr_ptr));
		attr_ptr.pg = pg_data;
		attr_ptr.pfc = pfc_data;

		if (dcb_check_config(&attr_ptr) != cmd_success) {
			LLDPAD_DBG("Rule checking failed in put_pg()\n");
			result = cmd_bad_params;
			goto Exit;
		}
		if (set_persistent(device_name, &attr_ptr) != cmd_success) {
			LLDPAD_DBG("Set persistent failed put_pg()\n");
			result = cmd_device_not_found;
			goto Exit;
		}
		/* Copy the writable protocol * variables */
		feature_protocol_attribs *dStore = &(it->second->protocol);

		if (dStore->Enable && !(pg_data->protocol.Enable))
			LLDPAD_INFO("%s PG disabled", device_name);
		else if (!(dStore->Enable) && pg_data->protocol.Enable)
			LLDPAD_INFO("%s PG enabled", device_name);

		dStore->Advertise_prev  = dStore->Advertise;
		dStore->Advertise       = pg_data->protocol.Advertise;
		dStore->Enable          = pg_data->protocol.Enable;
		dStore->Willing         = pg_data->protocol.Willing;
		dStore->tlv_sent        = false;

		memcpy(&(it->second->rx), &(pg_data->rx), sizeof(pg_data->rx));
		memcpy(&(it->second->tx), &(pg_data->tx), sizeof(pg_data->tx));
		if (it->second->protocol.dcbx_st == dcbx_subtype2)
			it->second->num_tcs = pg_data->num_tcs;

		DCB_SET_FLAGS(EventFlag, DCB_LOCAL_CHANGE_PG);

		/* Run the protocol */
		result = run_dcb_protocol(device_name, EventFlag,
					  SUBTYPE_DEFAULT);
	} else {
		/* Not in DCB data store, so store in persistent storage */
		if (get_persistent(device_name, &attribs) == cmd_success) {
			memset(&attr_ptr, 0, sizeof(attr_ptr));
			attr_ptr.pg = pg_data;
			attr_ptr.pgid = &attribs.descript;
			if (set_persistent(device_name, &attr_ptr) !=
					cmd_success) {
				LLDPAD_DBG("Set persistent failed in put_pg()\n");
				result = cmd_device_not_found;
			}
		} else {
			result = cmd_device_not_found;
		}
	}
Exit:
	return result;
}

cmd_status put_peer_pg(char *device_name,  pg_attribs *peer_pg_data)
{
	/* this function relies on the caller to acquire the DCB lock */
	cmd_status result = cmd_success;
	feature_protocol_attribs *dStore;

	if (!peer_pg_data)
		return cmd_bad_params;
	pg_it peer_it = pg_find(&peer_pg, device_name);
	if (peer_it == NULL) {
		LLDPAD_DBG("could not find peer_pg data for %s\n", device_name);
		result = cmd_device_not_found;
		goto Exit;
	}

	if (peer_pg_data->protocol.dcbx_st == dcbx_subtype2)
		rebalance_uppcts(peer_pg_data);

	/* detect config change */
	if (memcmp(peer_it->second, peer_pg_data, sizeof(*peer_pg_data)) == 0)
		goto Exit;

	/* Copy the writable protocol variables. */
	dStore = &(peer_it->second->protocol);
	dStore->Advertise_prev = dStore->Advertise;
	dStore->Advertise      = peer_pg_data->protocol.Advertise;
	dStore->Enable         = peer_pg_data->protocol.Enable;
	dStore->Willing        = peer_pg_data->protocol.Willing;
	dStore->Oper_version   = peer_pg_data->protocol.Oper_version;
	dStore->Max_version    = peer_pg_data->protocol.Max_version;
	dStore->TLVPresent     = peer_pg_data->protocol.TLVPresent;
	dStore->Error          = peer_pg_data->protocol.Error;
	dStore->dcbx_st        = peer_pg_data->protocol.dcbx_st;
	dStore->Error_Flag     = peer_pg_data->protocol.Error_Flag;

	memcpy(&(peer_it->second->rx), &(peer_pg_data->rx),
		sizeof(peer_pg_data->rx));
	memcpy(&(peer_it->second->tx), &(peer_pg_data->tx),
		sizeof(peer_pg_data->tx));
	if (peer_it->second->protocol.dcbx_st == dcbx_subtype2)
		peer_it->second->num_tcs = peer_pg_data->num_tcs;
Exit:
	return result;
}


cmd_status get_pfc(char *device_name, pfc_attribs *pfc_data)
{
	cmd_status result = cmd_success;
	full_dcb_attribs attribs;

	memset(&attribs, 0, sizeof(attribs));
	if (!pfc_data)
		return cmd_bad_params;
	pfc_it it = pfc_find(&pfc, device_name);
	if (it != NULL) {
		memcpy(pfc_data, it->second, sizeof(*pfc_data));
	} else {
		result = get_persistent(device_name, &attribs);
		if (result == cmd_success)
			memcpy(pfc_data, &attribs.pfc, sizeof(*pfc_data));
		else
			result = cmd_device_not_found;
	}
	return result;
}

cmd_status get_oper_pfc(char *device_name, pfc_attribs *pfc_data)
{
	cmd_status result = cmd_success;

	if (!pfc_data)
		return cmd_bad_params;
	pfc_it it = pfc_find(&oper_pfc, device_name);
	if (it != NULL)
		memcpy(pfc_data, it->second, sizeof(*pfc_data));
	else
		result = cmd_device_not_found;

	return result;
}

cmd_status get_peer_pfc(char *device_name, pfc_attribs *pfc_data)
{
	cmd_status result = cmd_success;

	if (!pfc_data)
		return cmd_bad_params;
	pfc_it it = pfc_find(&peer_pfc, device_name);
	if (it != NULL)
		memcpy(pfc_data, it->second, sizeof(*pfc_data));
	else
		result = cmd_device_not_found;

	return result;
}

cmd_status put_pfc(char *device_name, pfc_attribs *pfc_data)
{
	u32              EventFlag = 0;
	cmd_status       result = cmd_success;
	full_dcb_attribs attribs;
	bool        bChange = false;
	full_dcb_attrib_ptrs attr_ptr;

	if (!pfc_data)
		return cmd_bad_params;

	memset(&attribs, 0, sizeof(attribs));
	pfc_it it = pfc_find(&pfc, device_name);
	if (it != NULL) {
		/* detect no config change */
		if (memcmp(it->second, pfc_data, sizeof(*pfc_data)) == 0)
			goto Exit;

		bChange = true;
		memset(&attr_ptr, 0, sizeof(attr_ptr));
		attr_ptr.pfc = pfc_data;
		if (set_persistent(device_name, &attr_ptr) != cmd_success) {
			LLDPAD_DBG("Set persistent failed in put_pfc()\n");
			result = cmd_device_not_found;
			goto Exit;
		}

		feature_protocol_attribs *dStore = &(it->second->protocol);

		if (dStore->Enable && !(pfc_data->protocol.Enable))
			LLDPAD_INFO("%s PFC disabled", device_name);
		else if (!(dStore->Enable) && pfc_data->protocol.Enable)
			LLDPAD_INFO("%s PFC enabled", device_name);

		dStore->Advertise_prev  = dStore->Advertise;
		dStore->Advertise       = pfc_data->protocol.Advertise;
		dStore->Enable          = pfc_data->protocol.Enable;
		dStore->Willing         = pfc_data->protocol.Willing;
		dStore->tlv_sent        = false;

		memcpy(it->second->admin, pfc_data->admin,
			sizeof(pfc_data->admin));
		if (it->second->protocol.dcbx_st == dcbx_subtype2)
			it->second->num_tcs = pfc_data->num_tcs;

		/* Run the protocol */
		DCB_SET_FLAGS(EventFlag, DCB_LOCAL_CHANGE_PFC);
		if (bChange) 
			result = run_dcb_protocol(device_name, EventFlag,
							SUBTYPE_DEFAULT);
	} else {
		/* Store in persistent storage - not in DCB data store */
		if (get_persistent(device_name, &attribs) == cmd_success) {
			memset(&attr_ptr, 0, sizeof(attr_ptr));
			attr_ptr.pfc = pfc_data;
			attr_ptr.pgid = &attribs.descript;
			if (set_persistent(device_name, &attr_ptr) !=
					cmd_success) {
				result = cmd_device_not_found;
			}
		} else
			result = cmd_device_not_found;
	}
Exit:
	return result;
}

cmd_status put_peer_pfc(char *device_name, pfc_attribs *peer_pfc_data)
{
	/* this function relies on the caller to acquire the DCB lock */
	cmd_status result = cmd_success;
	feature_protocol_attribs *dStore;

	if (!peer_pfc_data)
		return cmd_bad_params;
	pfc_it peer_it = pfc_find(&peer_pfc, device_name);
	if (peer_it == NULL){
		LLDPAD_DBG("putting peer_pfc data - bad device name\n");
		result = cmd_device_not_found;
		goto Exit;
	}

	/* detect config change */
	if (memcmp(peer_it->second, peer_pfc_data, sizeof(*peer_pfc_data)) == 0)
		goto Exit;

	dStore = &(peer_it->second->protocol);
	dStore->Advertise_prev  = dStore->Advertise;
	dStore->Advertise       = peer_pfc_data->protocol.Advertise;
	dStore->Enable          = peer_pfc_data->protocol.Enable;
	dStore->Willing         = peer_pfc_data->protocol.Willing;
	dStore->Oper_version    = peer_pfc_data->protocol.Oper_version;
	dStore->Max_version     = peer_pfc_data->protocol.Max_version;
	dStore->TLVPresent      = peer_pfc_data->protocol.TLVPresent;
	dStore->Error           = peer_pfc_data->protocol.Error;
	dStore->dcbx_st         = peer_pfc_data->protocol.dcbx_st;
	dStore->Error_Flag      = peer_pfc_data->protocol.Error_Flag;

	memcpy(peer_it->second->admin, &peer_pfc_data->admin,
		sizeof(peer_pfc_data->admin));
	if (peer_it->second->protocol.dcbx_st == dcbx_subtype2)
		peer_it->second->num_tcs = peer_pfc_data->num_tcs;
Exit:
	return result;
}

cmd_status get_app(char *device_name, u32 subtype, app_attribs *app_data)
{
	cmd_status result = cmd_success;
	full_dcb_attribs attribs;

	memset(&attribs, 0, sizeof(attribs));

	app_it it = apptlv_find(&apptlv, device_name, subtype);

	if (it != NULL) {
		memcpy(app_data, it->second, sizeof(*app_data));
	} else {
		result = get_persistent(device_name, &attribs);
		if (result == cmd_success) {
			memcpy(app_data, &attribs.app[subtype],
			sizeof(*app_data));
		} else
			result = cmd_device_not_found;
	}
	return result;
}

cmd_status get_oper_app(char *device_name, u32 subtype, app_attribs *app_data)
{
	cmd_status result = cmd_success;

	app_it it = apptlv_find(&oper_apptlv, device_name, subtype);
	if (it != NULL)
		memcpy(app_data, it->second, sizeof(*app_data));
	else
		result = cmd_device_not_found;

	return result;
}

cmd_status get_peer_app(char *device_name, u32 subtype, app_attribs *app_data)
{
	cmd_status result = cmd_success;

	app_it it = apptlv_find(&peer_apptlv, device_name, subtype);
	if (it != NULL)
		memcpy(app_data, it->second, sizeof(*app_data));
	else
		result = cmd_device_not_found;

	return result;
}

cmd_status put_app(char *device_name, u32 subtype, app_attribs *app_data)
{
	full_dcb_attribs attribs;
	full_dcb_attrib_ptrs attr_ptr;
	u32              EventFlag = 0;
	cmd_status       result = cmd_success;
	unsigned i;

	if (!app_data)
		return cmd_bad_params;

	memset(&attribs, 0, sizeof(attribs));
	app_it it = apptlv_find(&apptlv, device_name, subtype);
	if (it != NULL) {
		/* detect no config change */
		if (memcmp(it->second, app_data,
			sizeof(*app_data)) == 0) {
			goto Exit;
		}
		/* Store in persistent storage */
		memset(&attr_ptr, 0, sizeof(attr_ptr));
		attr_ptr.app = app_data;
		attr_ptr.app_subtype = (u8)subtype;
		if (set_persistent(device_name, &attr_ptr) != cmd_success) {
			LLDPAD_DBG("Set persistent failed in put_app()\n");
			return cmd_device_not_found;
		}

		for (i = 0; i < DCB_MAX_APPTLV; i++) {
			if (i == subtype)
				continue;
			app_it ait = apptlv_find(&apptlv, device_name, i);
			memset(&attr_ptr, 0, sizeof(attr_ptr));
			attr_ptr.app = ait->second;
			attr_ptr.app->protocol.Enable = app_data->protocol.Enable;
			attr_ptr.app->protocol.Willing = app_data->protocol.Willing;
			attr_ptr.app_subtype = i;
			if (set_persistent(device_name, &attr_ptr) != cmd_success) {
				LLDPAD_DBG("Set persistent failed put_app()\n");
				return cmd_device_not_found;
			}
		}

		feature_protocol_attribs *dStore = &(it->second->protocol);
		if (dStore->Enable && !(app_data->protocol.Enable))
			LLDPAD_INFO("%s APP disabled", device_name);
		else if (!(dStore->Enable) && app_data->protocol.Enable)
			LLDPAD_INFO("%s APP enabled", device_name);
		dStore->Advertise_prev  = dStore->Advertise;
		dStore->Advertise       = app_data->protocol.Advertise;
		dStore->Enable          = app_data->protocol.Enable;
		dStore->Willing         = app_data->protocol.Willing;
		dStore->tlv_sent        = false;

		if (app_data->Length) {
			it->second->Length = app_data->Length;
			memcpy(&(it->second->AppData), &(app_data->AppData),
				app_data->Length);
		}

		DCB_SET_FLAGS(EventFlag, DCB_LOCAL_CHANGE_APPTLV(subtype));
		result = run_dcb_protocol(device_name, EventFlag, subtype);
	} else {
		/* Not in DCB data store, store in persistent storage */
		if (get_persistent(device_name, &attribs) == cmd_success) {
			memset(&attr_ptr, 0, sizeof(attr_ptr));
			attr_ptr.app = app_data;
			attr_ptr.app_subtype = (u8)subtype;
			attr_ptr.pgid = &attribs.descript;
			if (set_persistent(device_name, &attr_ptr) !=
				cmd_success) {
				LLDPAD_DBG("Set persistent failed in put_app()\n");
				result = cmd_device_not_found;
			}
		} else {
			result = cmd_device_not_found;
		}
	}
Exit:
	return result;
}

cmd_status put_peer_app(char *device_name, u32 subtype,
			app_attribs *peer_app_data)
{
	/* this function relies on the caller to acquire the DCB lock */
	feature_protocol_attribs *dStore;
	cmd_status result = cmd_success;

	if (!peer_app_data)
		return cmd_bad_params;
	app_it peer_it = apptlv_find(&peer_apptlv, device_name, subtype);
	if (peer_it == NULL) {
		LLDPAD_DBG("putting peer_app data - bad device name\n");
		result = cmd_device_not_found;
		goto Exit;
	}

	if (memcmp(peer_it->second, peer_app_data, sizeof(*peer_app_data)) == 0)
		goto Exit;

	dStore = &(peer_it->second->protocol);
	dStore->Advertise_prev = dStore->Advertise;
	dStore->Advertise      = peer_app_data->protocol.Advertise;
	dStore->Enable         = peer_app_data->protocol.Enable;
	dStore->Willing        = peer_app_data->protocol.Willing;
	dStore->Oper_version   = peer_app_data->protocol.Oper_version;
	dStore->Max_version    = peer_app_data->protocol.Max_version;
	dStore->TLVPresent     = peer_app_data->protocol.TLVPresent;
	dStore->Error          = peer_app_data->protocol.Error;
	dStore->dcbx_st        = peer_app_data->protocol.dcbx_st;
	dStore->Error_Flag     = peer_app_data->protocol.Error_Flag;

	peer_it->second->Length = peer_app_data->Length;
	memcpy(&(peer_it->second->AppData), &(peer_app_data->AppData),
		peer_app_data->Length);
Exit:
	return result;
}

cmd_status put_llink(char *device_name, u32 subtype, llink_attribs *llink_data)
{
	full_dcb_attrib_ptrs attr_ptr;
	full_dcb_attribs attribs;
	u32              EventFlag = 0;
	cmd_status       result = cmd_success;
	bool        bChange = false;

	if (!llink_data)
		return cmd_bad_params;

	memset(&attribs, 0, sizeof(attribs));
	llink_it it = llink_find(&llink, device_name, subtype);
	if (it != NULL) {
		/* Lock the data first */

		/* detect no config change */
		if (memcmp(it->second, llink_data, sizeof(*llink_data)) == 0)
			goto Exit;

		bChange = true;
		memset(&attr_ptr, 0, sizeof(attr_ptr));
		attr_ptr.llink = llink_data;
		attr_ptr.llink_subtype = LLINK_FCOE_STYPE;
		if (set_persistent(device_name, &attr_ptr) != cmd_success) {
			LLDPAD_DBG("Set persistent failed in put_llink()\n");
			result = cmd_device_not_found;
			goto Exit;
		}
		feature_protocol_attribs *dStore = &(it->second->protocol);
		if (dStore->Enable && !(llink_data->protocol.Enable))
			LLDPAD_INFO("%s LLINK disabled", device_name);
		else if (!(dStore->Enable) && llink_data->protocol.Enable)
			LLDPAD_INFO("%s LLINK enabled", device_name);
		dStore->Advertise_prev  = dStore->Advertise;
		dStore->Advertise       = llink_data->protocol.Advertise;
		dStore->Enable          = llink_data->protocol.Enable;
		dStore->Willing         = llink_data->protocol.Willing;
		dStore->tlv_sent        = false;

		it->second->llink.llink_status = llink_data->llink.llink_status;

		memcpy(&(it->second->llink), &(llink_data->llink),
			sizeof(llink_data->llink));

		/* Run the protocol */
		DCB_SET_FLAGS(EventFlag, DCB_LOCAL_CHANGE_LLINK);
		if (bChange) {
			result = run_dcb_protocol(device_name, EventFlag,
							SUBTYPE_DEFAULT);
		}
	} else {
		/* Store in persistent storage - though not in DCB data store*/
		if (get_persistent(device_name, &attribs) == cmd_success) {
			memset(&attr_ptr, 0, sizeof(attr_ptr));
			attr_ptr.llink = llink_data;
			attr_ptr.llink_subtype = LLINK_FCOE_STYPE;
			attr_ptr.pgid = &attribs.descript;
			if (set_persistent(device_name, &attr_ptr)
				!= cmd_success) {
				result = cmd_device_not_found;
			}
		} else
			result = cmd_device_not_found;
	}
Exit:
	return result;
}

cmd_status put_peer_llink(char *device_name, u32 subtype,
			llink_attribs *peer_llink_data)
{
	/* this function relies on the caller to acquire the DCB lock */
	feature_protocol_attribs *dStore;
	cmd_status result = cmd_success;

	if (!peer_llink_data)
		return cmd_bad_params;
	llink_it peer_it = llink_find(&peer_llink, device_name, subtype);
	if (peer_it == NULL){
		LLDPAD_DBG("putting peer_llink data - bad device name\n");
		result = cmd_device_not_found;
		goto Exit;
	}
	/* detect config change */
	if (memcmp(peer_it->second, peer_llink_data,
		sizeof(*peer_llink_data)) == 0) {
		goto Exit;
	}

	dStore = &(peer_it->second->protocol);
	dStore->Advertise_prev  = dStore->Advertise;
	dStore->Advertise       = peer_llink_data->protocol.Advertise;
	dStore->Enable          = peer_llink_data->protocol.Enable;
	dStore->Willing         = peer_llink_data->protocol.Willing;
	dStore->Oper_version    = peer_llink_data->protocol.Oper_version;
	dStore->Max_version     = peer_llink_data->protocol.Max_version;
	dStore->TLVPresent      = peer_llink_data->protocol.TLVPresent;
	dStore->Error           = peer_llink_data->protocol.Error;
	dStore->dcbx_st         = peer_llink_data->protocol.dcbx_st;
	dStore->Error_Flag      = peer_llink_data->protocol.Error_Flag;

	memcpy(&(peer_it->second->llink), &(peer_llink_data->llink),
		sizeof(peer_llink_data->llink));

Exit:
	return result;
}

cmd_status get_llink(char *device_name, u32 subtype, llink_attribs *llink_data)
{
	full_dcb_attribs attribs;
	cmd_status result = cmd_success;

	memset(&attribs, 0, sizeof(attribs));
	if (!llink_data)
		return cmd_bad_params;
	llink_it it = llink_find(&llink, device_name, subtype);
	if (it != NULL) {
		memcpy(llink_data, it->second, sizeof(*llink_data));
	} else {
		result = get_persistent(device_name, &attribs);
		if (result == cmd_success)
			memcpy(llink_data, &attribs.llink[subtype],
				sizeof(*llink_data));
		else
			result = cmd_device_not_found;
	}

	return result;
}

cmd_status get_oper_llink(char *device_name, u32 subtype,
				llink_attribs *llink_data)
{
	cmd_status result = cmd_success;

	if (!llink_data)
		return cmd_bad_params;
	llink_it it = llink_find(&oper_llink, device_name, subtype);
	if (it != NULL)
		memcpy(llink_data, it->second, sizeof(*llink_data));
	else
		result = cmd_device_not_found;

	return result;

}

cmd_status get_peer_llink(char *device_name, u32 subtype,
				llink_attribs *llink_data)
{
	cmd_status result = cmd_success;

	if (!llink_data)
		return cmd_bad_params;
	llink_it it = llink_find(&peer_llink, device_name, subtype);
	if (it != NULL)
		memcpy(llink_data, it->second, sizeof(*llink_data));
	else
		result = cmd_device_not_found;

	return result;
}

cmd_status get_control(char *device_name,
			control_protocol_attribs *control_data)
{
	cmd_status result = cmd_success;

	if (!control_data)
		return cmd_bad_params;
	control_prot_it it = ctrl_prot_find(&dcb_control_prot, device_name);

	if (it != NULL)
		memcpy( control_data, it->second, sizeof(*control_data));
	else
		result = cmd_device_not_found;

	return result;
}

cmd_status get_peer_control(char *device_name,
				control_protocol_attribs *peer_control_data)
{
	cmd_status result = cmd_success;

	if (!peer_control_data)
		return cmd_bad_params;
	control_prot_it it = ctrl_prot_find(&dcb_peer_control_prot,
						device_name);
	if (it != NULL)
		memcpy(peer_control_data, it->second,
			sizeof(*peer_control_data));
	else
		result = cmd_device_not_found;

	return result;
}


cmd_status put_peer_control(char *device_name,
				control_protocol_attribs *peer_control_data)
{
	/* this function relies on the caller to acquire the DCB lock */
	control_protocol_attribs *dStore = NULL;
	cmd_status result = cmd_success;

	if (!peer_control_data)
		return cmd_bad_params;
	control_prot_it peer_ctrl_prot = ctrl_prot_find(&dcb_peer_control_prot,
								device_name);
	if (peer_ctrl_prot)
		dStore = peer_ctrl_prot->second;
	if (peer_ctrl_prot && 
		((peer_control_data->Error_Flag & DUP_DCBX_TLV_CTRL) ||
		(peer_control_data->Error_Flag & TOO_MANY_NGHBRS))) {
		dStore->Error_Flag      = peer_control_data->Error_Flag;
	} else if (peer_ctrl_prot != NULL) {
		dStore->SeqNo           = peer_control_data->SeqNo;
		dStore->AckNo           = peer_control_data->AckNo;
		dStore->Max_version     = peer_control_data->Max_version;
		dStore->Oper_version    = peer_control_data->Oper_version;
		dStore->RxDCBTLVState   = peer_control_data->RxDCBTLVState;
		dStore->Error_Flag      = peer_control_data->Error_Flag;
	} else {
		result = cmd_device_not_found;
	}

	return result;
}

cmd_status get_bwg_descrpt(char *device_name, u8 bwgid, char **name)
{
	full_dcb_attribs attribs;
	cmd_status result = cmd_success;
	int size;

	if (*name != NULL) {
		free(*name);
		*name = NULL;
	}

	memset(&attribs, 0, sizeof(attribs));
	pg_desc_it it = pgdesc_find(&pg_desc, device_name);

	if ((it != NULL) &&
		(bwgid < it->second->max_pgid_desc)) {
		size = (int)strlen(it->second->pgid_desc[bwgid]) +
			sizeof(char);  /* Localization OK */
		*name = (char*)malloc(size);
		if (*name != NULL) {
			strncpy(*name, it->second->pgid_desc[bwgid],
					size); /* Localization OK */
		} else {
			goto Error;
		}
	} else {
		result = get_persistent(device_name, &attribs);
		if (result == cmd_success) {
			size = (int)strlen(
				attribs.descript.pgid_desc[bwgid]) +
				sizeof(char);
			*name = (char*)malloc(size);
			if (*name != NULL) {
				strncpy(*name,
					attribs.descript.pgid_desc[bwgid],
					size); /* Localization OK */
			} else {
				goto Error;
			}
		} else {
			result = cmd_device_not_found;
		}
	}
	return result;
Error:
	LLDPAD_DBG("get_bwg_descrpt: Failed memory alloc\n");
	return cmd_failed;
}

cmd_status put_bwg_descrpt(char *device_name, u8 bwgid, char *name)
{
	full_dcb_attribs attribs;
	full_dcb_attrib_ptrs attr_ptr;
	cmd_status result = cmd_success;
	unsigned int size;

	if (!name)
		return cmd_bad_params;
	size = (unsigned int)strlen(name);  /* Localization OK */

	memset(&attribs, 0, sizeof(attribs));
	pg_desc_it it = pgdesc_find(&pg_desc, device_name);

	if ((it != NULL) &&
		(bwgid < it->second->max_pgid_desc)) {

		/* Only take as many characters as can be held */
		if (!(size < sizeof(it->second->pgid_desc[bwgid])))
			size = sizeof(it->second->pgid_desc[bwgid])-1;
		memcpy(it->second->pgid_desc[bwgid], name, size);
		/* Put a null at the end incase it was truncated */
		it->second->pgid_desc[bwgid][size] = '\0';
		memset(&attr_ptr, 0, sizeof(attr_ptr));
		attr_ptr.pgid = it->second;
		if (set_persistent(device_name, &attr_ptr) != cmd_success)
			return cmd_device_not_found;
	} else {
		/* Store in persistent storage - though not in
		 * DCB data store */
		if (get_persistent(device_name, &attribs) == cmd_success) {
			if (!(size <
				sizeof(attribs.descript.pgid_desc[bwgid])))
				size = sizeof(
				 attribs.descript.pgid_desc[bwgid]) - 1;
			memcpy(attribs.descript.pgid_desc[bwgid],
				name, size);
			/* Put a null at the end in case it was
			 * truncated */
			attribs.descript.pgid_desc[bwgid][size] = '\0';
			memset(&attr_ptr, 0, sizeof(attr_ptr));
			attr_ptr.pgid = &attribs.descript;
			if (set_persistent(device_name, &attr_ptr)
				!= cmd_success) {
				LLDPAD_DBG("Set persistent failed "
					"in put_bwg_descrpt()\n");
				result = cmd_device_not_found;
			}
		}
		else
			result = cmd_device_not_found;
	}

	return result;
}

/******************************************************************************
**
** Method:      CopyConfigToOper
**
** Description: Function to copy local or peer PG or PFC or APPTLV
**              configurations to oper configuration.
**
** Arguments: char *device_name
**            u32 SrcFlag - Tells where to copy from (local or peer)
**            u32 EventFlag
**            u32 SubType - This is valid only for DCB_LOCAL_CHANGE_APPTLV and
**                          DCB_REMOTE_CHANGE_APPTLV
**
** Returns: true if successful, failure code otherwise.
**
******************************************************************************/
void CopyConfigToOper(char *device_name, u32 SrcFlag, u32 EventFlag,
			u32 Subtype)
{
	int i = 0;

	/* this function relies on the caller to acquire the DCB lock */
	LLDPAD_DBG("  CopyConfigToOper %s\n", device_name);
	if (DCB_TEST_FLAGS(EventFlag, DCB_LOCAL_CHANGE_PG, DCB_LOCAL_CHANGE_PG)
		|| DCB_TEST_FLAGS(EventFlag, DCB_REMOTE_CHANGE_PG,
		DCB_REMOTE_CHANGE_PG)) {

		/* Get the Local or Peer store */
		pg_it Src;
		pg_it localSrc = NULL;

		if (SrcFlag == LOCAL_STORE) {
			Src = localSrc = pg_find(&pg, device_name);
			if (localSrc == NULL)
				return;
		} else if (SrcFlag == PEER_STORE) {
			Src = pg_find(&peer_pg, device_name);
			if (Src == NULL)
				return;

			localSrc = pg_find(&pg, device_name);
			if (localSrc == NULL)
				return;
		} else {
			/* We don't support */
			return;
		}

		/* Get the Oper store */
		pg_it Oper = pg_find(&oper_pg, device_name);
		if (Oper == NULL)
			return;

		/* Copy Src to Oper. */
		for (i = 0; i < MAX_USER_PRIORITIES; i++) {
			Oper->second->tx.up[i].bwgid =
				Src->second->tx.up[i].bwgid;
			Oper->second->rx.up[i].bwgid =
				Src->second->rx.up[i].bwgid;

			Oper->second->tx.up[i].strict_priority =
				Src->second->tx.up[i].strict_priority;
			Oper->second->rx.up[i].strict_priority =
				Src->second->rx.up[i].strict_priority;

			Oper->second->tx.up[i].percent_of_pg_cap =
				Src->second->tx.up[i].percent_of_pg_cap;
			Oper->second->rx.up[i].percent_of_pg_cap =
				Src->second->rx.up[i].percent_of_pg_cap;

			if (SrcFlag == PEER_STORE) {
				Oper->second->tx.up[i].pgid =
					Src->second->tx.up[i].pgid;
				Oper->second->rx.up[i].pgid =
					Src->second->rx.up[i].pgid;
			} else {
				Oper->second->tx.up[i].pgid =
					localSrc->second->tx.up[i].pgid;
				Oper->second->rx.up[i].pgid =
					localSrc->second->rx.up[i].pgid;
			}
		}

		for (i = 0; i < MAX_BANDWIDTH_GROUPS; i++) {
			Oper->second->tx.pg_percent[i] =
				Src->second->tx.pg_percent[i];
			Oper->second->rx.pg_percent[i] =
				Src->second->rx.pg_percent[i];
		}
	} else if (DCB_TEST_FLAGS(EventFlag, DCB_LOCAL_CHANGE_PFC,
		DCB_LOCAL_CHANGE_PFC) ||
		DCB_TEST_FLAGS(EventFlag, DCB_REMOTE_CHANGE_PFC,
		DCB_REMOTE_CHANGE_PFC)) {

		/* Get the Local or Peer store */
		pfc_it Src;
		if (SrcFlag == LOCAL_STORE) {
			Src = pfc_find(&pfc, device_name);
			if (Src == NULL)
				return;
		}
		else if (SrcFlag == PEER_STORE) {
			Src = pfc_find(&peer_pfc, device_name);
			if (Src == NULL)
				return;
		}
		else {
			/* We don't support */
			return;
		}
		/* Get Oper store */
		pfc_it Oper = pfc_find(&oper_pfc, device_name);
		if (Oper == NULL)
			return;

		/* Copy Src to Oper. */
		memcpy(&Oper->second->admin, &Src->second->admin,
			sizeof(Src->second->admin));
	} else if (DCB_TEST_FLAGS(EventFlag, DCB_LOCAL_CHANGE_APPTLV(Subtype),
			DCB_LOCAL_CHANGE_APPTLV(Subtype))||
			DCB_TEST_FLAGS(EventFlag,
				       DCB_REMOTE_CHANGE_APPTLV(Subtype),
				       DCB_REMOTE_CHANGE_APPTLV(Subtype))) {
		/* Get the Local or Peer store */

		app_it Src;
		if (SrcFlag == LOCAL_STORE) {
			Src = apptlv_find(&apptlv, device_name, Subtype);
			if (Src == NULL)
				return;
		} else if (SrcFlag == PEER_STORE) {
			Src = apptlv_find(&peer_apptlv, device_name,
						Subtype);
			if (Src == NULL)
				return;
		} else {
			/* We don't support */
			return;
		}
		/* Get Oper store */
		app_it Oper = apptlv_find(&oper_apptlv, device_name,
						Subtype);
		if (Oper != NULL) {
			/* Copy Src to Oper. */
			LLDPAD_DBG("  Changing app data from %02x to %02x\n",
				Oper->second->AppData[0],
				Src->second->AppData[0]);
			Oper->second->Length = Src->second->Length;
			memcpy(Oper->second->AppData, Src->second->AppData,
				Src->second->Length);
		}
	} else if (DCB_TEST_FLAGS(EventFlag, DCB_LOCAL_CHANGE_LLINK,
		DCB_LOCAL_CHANGE_LLINK) ||
		DCB_TEST_FLAGS(EventFlag, DCB_REMOTE_CHANGE_LLINK,
		DCB_REMOTE_CHANGE_LLINK)) {

		/* Get the Local or Peer store */

		/* Get the Local or Peer store */
		llink_it Src;
		if (SrcFlag == LOCAL_STORE) {
			Src = llink_find(&llink, device_name, Subtype);
			if (Src == NULL)
				return;
		}
		else if (SrcFlag == PEER_STORE) {
			Src = llink_find(&peer_llink, device_name,
						Subtype);
			if (Src == NULL)
				return;
		}
		else {
			/* We don't support */
			return;
		}
		/* Get Oper store */
		llink_it Oper = llink_find(&oper_llink, device_name,
						Subtype);
		if (Oper == NULL) {
			return;
		}

		/* Copy Src to Oper. */
		memset(&Oper->second->llink, 0, sizeof(Oper->second->llink));
		memcpy( &Oper->second->llink, &Src->second->llink,
			sizeof(Src->second->llink));

	}
}

/******************************************************************************
**
** Method:      LocalPeerCompatible
**
** Description: Function to check if local and peer configurations matches.
**
** Arguments: char *device_name
**            ULONG EventFlag
**            ULONG SubType - This is valid only for DCB_LOCAL_CHANGE_APPTLV
**			and DCB_REMOTE_CHANGE_APPTLV
**
** Returns: true if successful, failure code otherwise.
**
******************************************************************************/
bool LocalPeerCompatible(char *device_name, u32 EventFlag, u32 Subtype)
{
	int i = 0;

	if (DCB_TEST_FLAGS(EventFlag, DCB_LOCAL_CHANGE_PG, DCB_LOCAL_CHANGE_PG)
		|| DCB_TEST_FLAGS(EventFlag, DCB_REMOTE_CHANGE_PG,
		DCB_REMOTE_CHANGE_PG)) {

		/* Get the Local and Peer PG store */
		pg_it Local = pg_find(&pg, device_name);
		pg_attribs *lpg;
		pg_attribs *ppg;
		bool match = false;

		if (Local == NULL) {
			goto Error;
		}
		pg_it Peer = pg_find(&peer_pg, device_name);
		if (Peer == NULL) {
			goto Error;
		}
		lpg = Local->second;
		ppg = Peer->second;

		match = true;
		if (ppg->protocol.dcbx_st == dcbx_subtype1) {
			for (i = 0; i < MAX_USER_PRIORITIES; i++) {
				if (lpg->tx.up[i].bwgid !=
					ppg->tx.up[i].bwgid)
					match = false;
				if (lpg->tx.up[i].strict_priority !=
					ppg->tx.up[i].strict_priority)
					match = false;
				if (lpg->tx.up[i].percent_of_pg_cap !=
					ppg->tx.up[i].percent_of_pg_cap)
					match = false;
			}
			for (i = 0; i < MAX_BANDWIDTH_GROUPS; i++) {
				if (lpg->tx.pg_percent[i] !=
					ppg->tx.pg_percent[i])
					match = false;
			}
		}
		if (match) {
			LLDPAD_DBG("  COMPAT PG - passed\n");
			return true;
		}
		LLDPAD_DBG("  COMPAT PG - failed\n");
	} else if (DCB_TEST_FLAGS(EventFlag, DCB_LOCAL_CHANGE_PFC,
			DCB_LOCAL_CHANGE_PFC)||
			DCB_TEST_FLAGS(EventFlag, DCB_REMOTE_CHANGE_PFC,
			DCB_REMOTE_CHANGE_PFC)) {

		/* Get the Local and Peer PFC store */
		pfc_it Local = pfc_find(&pfc, device_name);
		if (Local == NULL) {
			goto Error;
		}
		pfc_it Peer = pfc_find(&peer_pfc, device_name);
		if (Peer == NULL) {
			goto Error;
		}
		if (!memcmp(&Local->second->admin,
			&Peer->second->admin,
			sizeof(Local->second->admin))) {
			LLDPAD_DBG("  COMPAT PFC - passed\n");
			return true;
		}
		LLDPAD_DBG("  COMPAT PFC - failed\n");
	} else if (DCB_TEST_FLAGS(EventFlag, DCB_LOCAL_CHANGE_APPTLV(Subtype),
			DCB_LOCAL_CHANGE_APPTLV(Subtype))||
			DCB_TEST_FLAGS(EventFlag,
				       DCB_REMOTE_CHANGE_APPTLV(Subtype),
				       DCB_REMOTE_CHANGE_APPTLV(Subtype))) {

		/* Get the Local and Peer APPTLV store */

		app_it Local = apptlv_find(&apptlv, device_name, Subtype);

		if (Local == NULL)
			goto Error;

		app_it Peer = apptlv_find(&peer_apptlv, device_name,
						Subtype);
		if (Peer == NULL)
			goto Error;

		if (Local->second->Length == Peer->second->Length) {
			if (!memcmp(Local->second->AppData,
				Peer->second->AppData,
				Local->second->Length)) {
				return true;
			}
		}
		LLDPAD_DBG("  COMPAT APP - failed\n");
	} else if (DCB_TEST_FLAGS(EventFlag, DCB_LOCAL_CHANGE_LLINK,
			DCB_LOCAL_CHANGE_LLINK)||
			DCB_TEST_FLAGS(EventFlag, DCB_REMOTE_CHANGE_LLINK,
			DCB_REMOTE_CHANGE_LLINK)) {

		LLDPAD_DBG("  COMPAT LLINK - failed\n");
		return false;
	}

	return false;
Error:
	LLDPAD_DBG("  LocalPeerCompatible: device not found\n");
	return false;
}

/* returns: 0 on success
 *          1 on failure
*/
int set_configuration(char *device_name, u32 EventFlag)
{
	cmd_status              sResult;
	full_dcb_attrib_ptrs    attr_ptr;

	if (DCB_TEST_FLAGS(EventFlag, DCB_LOCAL_CHANGE_PG, DCB_LOCAL_CHANGE_PG)
		|| DCB_TEST_FLAGS(EventFlag, DCB_REMOTE_CHANGE_PG,
		DCB_REMOTE_CHANGE_PG)) {

		/* Get Oper store */
		pg_it Oper = pg_find(&oper_pg, device_name);
		pg_it Local = pg_find(&pg, device_name);

		if (Oper == NULL || Local == NULL)
			return cmd_failed;

		Oper->second->num_tcs = Local->second->num_tcs;

		pgroup_attribs pg_data;
		if (DCB_TEST_FLAGS(EventFlag, DCB_REMOTE_CHANGE_PG,
			DCB_REMOTE_CHANGE_PG)) {
			pfc_it op_pfc = pfc_find(&oper_pfc, device_name);

			memset(&attr_ptr, 0, sizeof(attr_ptr));
			attr_ptr.pg = (Oper->second);
			attr_ptr.pfc = (op_pfc->second);
			if ((sResult = dcb_check_config(&attr_ptr))
				!= cmd_success) {
				LLDPAD_DBG("  PG rule check returned error %d\n",
					sResult);  /* Localization OK */
				return sResult;
			}
		}
		memcpy(&(pg_data.rx), &(Oper->second->rx), sizeof(pg_data.rx));
		memcpy(&(pg_data.tx), &(Oper->second->tx), sizeof(pg_data.tx));
		return set_hw_pg(device_name, &pg_data,
			Local->second->protocol.OperMode);
	} else if (DCB_TEST_FLAGS(EventFlag, DCB_LOCAL_CHANGE_PFC,
		DCB_LOCAL_CHANGE_PFC) ||
		DCB_TEST_FLAGS(EventFlag, DCB_REMOTE_CHANGE_PFC,
		DCB_REMOTE_CHANGE_PFC)) {

		/* Get Oper store */
		pfc_it Oper = pfc_find(&oper_pfc, device_name);
		pfc_it Local = pfc_find(&pfc, device_name);
		if (Oper == NULL || Local == NULL)
			return cmd_failed;
		return set_hw_pfc(device_name, Oper->second->admin,
			Local->second->protocol.OperMode);
	} else if (DCB_TEST_FLAGS(EventFlag, DCB_LOCAL_CHANGE_LLINK,
		DCB_LOCAL_CHANGE_LLINK) ||
		DCB_TEST_FLAGS(EventFlag, DCB_REMOTE_CHANGE_LLINK,
		DCB_REMOTE_CHANGE_LLINK)) {
		return cmd_success;
	} else if (DCB_TEST_FLAGS(EventFlag,
				  DCB_LOCAL_CHANGE_APPTLV(APP_FCOE_STYPE),
				  DCB_LOCAL_CHANGE_APPTLV(APP_FCOE_STYPE)) ||
		DCB_TEST_FLAGS(EventFlag,
			       DCB_REMOTE_CHANGE_APPTLV(APP_FCOE_STYPE),
			       DCB_REMOTE_CHANGE_APPTLV(APP_FCOE_STYPE))) {
		appgroup_attribs app_data;

		/* Get Oper store */
		app_it Oper = apptlv_find(&oper_apptlv, device_name,
						APP_FCOE_STYPE);
		if (Oper == NULL)
			return cmd_success;

		app_data.dcb_app_idtype = DCB_APP_IDTYPE_ETHTYPE;
		app_data.dcb_app_id = APP_FCOE_ETHTYPE;
		app_data.dcb_app_priority = Oper->second->AppData[0];
		return set_hw_app(device_name, &app_data);
	} else if (DCB_TEST_FLAGS(EventFlag,
				  DCB_LOCAL_CHANGE_APPTLV(APP_FIP_STYPE),
				  DCB_LOCAL_CHANGE_APPTLV(APP_FIP_STYPE)) ||
		DCB_TEST_FLAGS(EventFlag,
			       DCB_REMOTE_CHANGE_APPTLV(APP_FIP_STYPE),
			       DCB_REMOTE_CHANGE_APPTLV(APP_FIP_STYPE))) {
		appgroup_attribs app_data;

		/* Get Oper store */
		app_it Oper = apptlv_find(&oper_apptlv, device_name,
					  APP_FIP_STYPE);

		/* FIP subtype is only sent to kernel if Operational this
		 * way the FCoE stack and applications use the FCoE APP
		 * entry until FIP is operational.
		 */
		if (Oper == NULL ||
		    (Oper->second && Oper->second->protocol.OperMode == false))
			return cmd_success;

		app_data.dcb_app_idtype = DCB_APP_IDTYPE_ETHTYPE;
		app_data.dcb_app_id = APP_FIP_ETHTYPE;
		app_data.dcb_app_priority = Oper->second->AppData[0];
		return set_hw_app(device_name, &app_data);
	} else if (DCB_TEST_FLAGS(EventFlag, DCB_LOCAL_CHANGE_APPTLV(APP_ISCSI_STYPE),
		DCB_LOCAL_CHANGE_APPTLV(APP_ISCSI_STYPE)) ||
		DCB_TEST_FLAGS(EventFlag, DCB_REMOTE_CHANGE_APPTLV(APP_ISCSI_STYPE),
		DCB_REMOTE_CHANGE_APPTLV(APP_ISCSI_STYPE))) {
		appgroup_attribs app_data;

		/* Get Oper store */
		app_it Oper = apptlv_find(&oper_apptlv, device_name,
						APP_ISCSI_STYPE);
		app_it Local = apptlv_find(&apptlv, device_name,
						APP_ISCSI_STYPE);
		if (Oper == NULL || Local == NULL) {
			return cmd_failed;
		}

		app_data.dcb_app_idtype = DCB_APP_IDTYPE_PORTNUM;
		app_data.dcb_app_id = APP_ISCSI_PORT;
		app_data.dcb_app_priority = Oper->second->AppData[0];

		return set_hw_app(device_name, &app_data);
	}
	return cmd_success;
}

/******************************************************************************
**
** Method:      handle_opermode_true
**
** Description: This routine is called by remove_adapter.
**               For any feature whose OperMode is true, send an
**               event since the port is going away - indicating an
**               OperMode change.
**
** Arguments: char *device_name
**
** Returns: cmd_success if successful, failure code otherwise.
**
******************************************************************************/
static void handle_opermode_true(char *device_name)
{
	pg_attribs pg_data;
	pfc_attribs pfc_data;
	app_attribs app_data;
	llink_attribs llink_data;
	int i = 0;

	if (get_pg(device_name, &pg_data) == cmd_success)
		if (pg_data.protocol.OperMode)
			pg_event(device_name, EVENT_OPERMODE);

	if (get_pfc(device_name, &pfc_data) == cmd_success)
		if (pfc_data.protocol.OperMode)
			pfc_event(device_name, EVENT_OPERMODE);

	for (i = 0; i < DCB_MAX_APPTLV ; i++)
		if (get_app(device_name, i, &app_data) == cmd_success)
			if (app_data.protocol.OperMode)
				app_event(device_name, i, EVENT_OPERMODE);

	for (i = 0; i < DCB_MAX_LLKTLV ; i++)
		if (get_llink(device_name, i, &llink_data) == cmd_success)
			if (llink_data.protocol.OperMode)
				llink_event(device_name, i, EVENT_OPERMODE);

}

/******************************************************************************
**
** Method:      run_feature_protocol
**
** Description: This function runs feature state machine for a local or remote
** change.
** The function caller should acquire lock before calling this function.
** Caller must call this function per event.
**
** Arguments: char *device_name
**            u32 EventFlag
**            u32 SubType - This is valid only for DCB_LOCAL_CHANGE_APPTLV and
**                          DCB_REMOTE_CHANGE_APPTLV
**
** Returns: cmd_success if successful, failure code otherwise.
**
******************************************************************************/
cmd_status run_feature_protocol(char *device_name, u32 EventFlag, u32 Subtype)
{
	feature_protocol_attribs *feat_prot      = NULL;
	feature_protocol_attribs *peer_feat_prot = NULL;
	control_prot_it ctrl_prot = NULL;
	control_prot_it peer_ctrl_prot = NULL; 
	bool ErrorChanged  = false;
	bool Err, local_change;
	bool just_added = false;
	pg_attribs old_pg_opcfg;
	int old_pg_opmode = 0;
	u32 pg_events = 0;
	pfc_attribs old_pfc_opcfg;
	int old_pfc_opmode = 0;
	u32 pfc_events = 0;
	app_attribs old_app_opcfg;
	int old_app_opmode = 0;
	u32 app_events = 0;
	llink_attribs old_llink_opcfg;
	int old_llink_opmode = 0;
	u32 llink_events = 0;
	int i, mask;

	if (!dcbx_check_active(device_name))
		return cmd_success;

	memset(&old_pg_opcfg, 0, sizeof(pg_attribs));
	memset(&old_pfc_opcfg, 0, sizeof(pfc_attribs));
	memset(&old_app_opcfg, 0, sizeof(app_attribs));
	memset(&old_llink_opcfg, 0, sizeof(llink_attribs));

	/* Get the protocol store */
	if (DCB_TEST_FLAGS(EventFlag, DCB_EVENT_FLAGS, DCB_LOCAL_CHANGE_PG) ||
		DCB_TEST_FLAGS(EventFlag, DCB_EVENT_FLAGS,
		DCB_REMOTE_CHANGE_PG)) {

		/* Get the local feature protocol */
		pg_it it = pg_find(&pg, device_name);
		if (it != NULL) {
			feat_prot = &it->second->protocol;
			old_pg_opmode = feat_prot->OperMode;
		} else {
			goto ErrNoDevice;
		}

		/* Get the remote feature protocol */
		pg_it it1 = pg_find(&peer_pg, device_name);
		if (it1 != NULL) {
			peer_feat_prot = &it1->second->protocol;
		} else {
			goto ErrNoDevice;
		}
		if ((peer_feat_prot->Error_Flag & DUP_DCBX_TLV_CTRL) ||
			(peer_feat_prot->Error_Flag & DUP_DCBX_TLV_PG)) {
			LLDPAD_DBG("** FLAG: MISSING PG TLV \n");
			feat_prot->Error_Flag |= FEAT_ERR_MULTI_TLV;
		} else {
			feat_prot->Error_Flag &= ~FEAT_ERR_MULTI_TLV;
		}

		pg_it Oper = pg_find(&oper_pg, device_name);
		if (Oper != NULL) {
			memcpy(&(old_pg_opcfg.rx), &(Oper->second->rx),
				sizeof(old_pg_opcfg.rx));
			memcpy(&(old_pg_opcfg.tx), &(Oper->second->tx),
				sizeof(old_pg_opcfg.tx));
		} else {
			goto ErrNoDevice;
		}
	}

	if (DCB_TEST_FLAGS(EventFlag, DCB_EVENT_FLAGS, DCB_LOCAL_CHANGE_PFC) ||
		DCB_TEST_FLAGS(EventFlag, DCB_EVENT_FLAGS,
		DCB_REMOTE_CHANGE_PFC)) {

		/* Get the local feature protocol */
		pfc_it it = pfc_find(&pfc, device_name);
		if (it != NULL) {
			feat_prot = &it->second->protocol;
			old_pfc_opmode = feat_prot->OperMode;
		} else {
			goto ErrNoDevice;
		}

		/* Get the remote feature protocol */
		pfc_it it1 = pfc_find(&peer_pfc, device_name);
		if (it1 != NULL) {
			peer_feat_prot = &it1->second->protocol;
		} else {
			goto ErrNoDevice;
		}
		if ((peer_feat_prot->Error_Flag & DUP_DCBX_TLV_CTRL) ||
			(peer_feat_prot->Error_Flag & DUP_DCBX_TLV_PFC)) {
			LLDPAD_DBG("** FLAG: MISSING PFC TLV \n");
			feat_prot->Error_Flag |= FEAT_ERR_MULTI_TLV;
		} else {
			feat_prot->Error_Flag &= ~FEAT_ERR_MULTI_TLV;
		}

		pfc_it Oper = pfc_find(&oper_pfc, device_name);
		if (Oper != NULL) {
			memcpy(&old_pfc_opcfg.admin, &Oper->second->admin,
				sizeof(old_pfc_opcfg.admin));
		} else {
			goto ErrNoDevice;
		}
	}

	if (DCB_TEST_FLAGS(EventFlag,
			   DCB_EVENT_FLAGS,
			   DCB_LOCAL_CHANGE_APPTLV(Subtype)) ||
	    DCB_TEST_FLAGS(EventFlag,
			   DCB_EVENT_FLAGS,
			   DCB_REMOTE_CHANGE_APPTLV(Subtype))) {
		/* Get the local feature protocol */
		app_it it = apptlv_find(&apptlv, device_name, Subtype);
		if (it != NULL) {
			feat_prot = &it->second->protocol;
			old_app_opmode = feat_prot->OperMode;
		} else {
			goto ErrNoDevice;
		}

		/* Get the remote feature protocol */
		app_it it1 = apptlv_find(&peer_apptlv, device_name, Subtype);
		if (it1 != NULL) {
			peer_feat_prot = &it1->second->protocol;
		} else {
			goto ErrNoDevice;
		}
		if ((peer_feat_prot->Error_Flag & DUP_DCBX_TLV_CTRL) ||
			(peer_feat_prot->Error_Flag & DUP_DCBX_TLV_APP)) {
			LLDPAD_DBG("** FLAG: MISSING APP TLV \n");
			feat_prot->Error_Flag |= FEAT_ERR_MULTI_TLV;
		} else {
			feat_prot->Error_Flag &= ~FEAT_ERR_MULTI_TLV;
		}

		app_it Oper = apptlv_find(&oper_apptlv, device_name, Subtype);
		if (Oper != NULL) {
			old_app_opcfg.Length = Oper->second->Length;
			memcpy(&old_app_opcfg.AppData[0],
				&((*Oper).second->AppData[0]),
				old_app_opcfg.Length);
		} else {
			goto ErrNoDevice;
		}
	}
	if (DCB_TEST_FLAGS(EventFlag, DCB_EVENT_FLAGS, DCB_LOCAL_CHANGE_LLINK)
		|| DCB_TEST_FLAGS(EventFlag, DCB_EVENT_FLAGS,
		DCB_REMOTE_CHANGE_LLINK)) {

		/* Get the local feature protocol */
		llink_it it = llink_find(&llink, device_name, Subtype);
		if (it != NULL) {
			feat_prot = &it->second->protocol;
			old_llink_opmode = feat_prot->OperMode;
		} else {
			goto ErrNoDevice;
		}

		/* Get the remote feature protocol */
		llink_it it1 = llink_find(&peer_llink, device_name, Subtype);
		if (it1 != NULL) {
			peer_feat_prot = &it1->second->protocol;
		} else {
			goto ErrNoDevice;
		}
		if ((peer_feat_prot->Error_Flag & DUP_DCBX_TLV_CTRL) ||
			(peer_feat_prot->Error_Flag & DUP_DCBX_TLV_LLINK)) {
			LLDPAD_DBG("** FLAG: MISSING LLINK TLV \n");
			feat_prot->Error_Flag |= FEAT_ERR_MULTI_TLV;
		} else {
			feat_prot->Error_Flag &= ~FEAT_ERR_MULTI_TLV;
		}

		llink_it Oper = llink_find(&oper_llink, device_name, Subtype);
		if (Oper != NULL) {
			memcpy(&old_llink_opcfg.llink, &Oper->second->llink,
				sizeof(old_llink_opcfg.llink));
		} else {
			goto ErrNoDevice;
		}
	}

	/* Get the local control protocol variables. */
	ctrl_prot = ctrl_prot_find(&dcb_control_prot, device_name);
	if (ctrl_prot == NULL)
		goto ErrNoDevice;
	/* Get the remote control protocol variables. */
	peer_ctrl_prot = ctrl_prot_find(&dcb_peer_control_prot, device_name);
	if (peer_ctrl_prot == NULL)
		goto ErrNoDevice;
	if ((feat_prot == NULL) || (peer_feat_prot == NULL))
		goto ErrNoDevice;
	if (peer_ctrl_prot->second->Error_Flag & TOO_MANY_NGHBRS) {
		peer_feat_prot->TLVPresent = false;
		LLDPAD_DBG("** Set Flag: TOO MANY NEIGHBORS \n");
		feat_prot->Error_Flag |= FEAT_ERR_MULTI_PEER;
	} else {
		feat_prot->Error_Flag &= ~FEAT_ERR_MULTI_PEER;
	}

	if (feat_prot->State == DCB_INIT) {
		feat_prot->Oper_version = feat_prot->Max_version;
		feat_prot->OperMode = false;
		feat_prot->Error = false;

		/* Set the parameters. */
		feat_prot->FeatureSeqNo =
			ctrl_prot->second->SeqNo + 1;
		/* If Syncd false, then control state machine will
		 * TX LLDP message with local config. */
		feat_prot->Syncd = !(feat_prot->Advertise);
		LLDPAD_DBG("Set Syncd to %u [%u]\n", feat_prot->Syncd, __LINE__);
		feat_prot->State = DCB_LISTEN;

		/* Ensure PFC settings are synced up on initialization */
		if (DCB_TEST_FLAGS(EventFlag, DCB_EVENT_FLAGS,
			DCB_LOCAL_CHANGE_PFC))
			just_added = true;
	}
	if (feat_prot->State == DCB_LISTEN) {
		LLDPAD_DBG("Feature state machine (flags %x)\n", EventFlag);
		local_change = false;
		mask = DCB_SET_ALL_FLAGS(LOCAL);
		if (EventFlag & mask) {
			local_change = true;
			LLDPAD_DBG("  Local change*0x%x:", EventFlag);
			LLDPAD_DBG(" %s", (EventFlag & DCB_LOCAL_CHANGE_PG) ?
				"PG" : "");
			LLDPAD_DBG(" %s", (EventFlag & DCB_LOCAL_CHANGE_PFC) ?
				"PFC" : "");
			for (i = 0; i < DCB_MAX_APPTLV; i++)
				if (EventFlag & DCB_LOCAL_CHANGE_APPTLV(i))
					LLDPAD_DBG(" APP%d", i);
			LLDPAD_DBG(" %s", (EventFlag & DCB_LOCAL_CHANGE_LLINK) ?
				"LLINK" : "");
			LLDPAD_DBG("\n");
		}

		/* If local changed and we are already synched... */
		if (local_change && feat_prot->Syncd) {
			LLDPAD_DBG("  Local feature already synced\n");
			/* If we are not synched, we won't be able
			 * to accept new local changes until we get
			 * back remote changes for previous local
			 * change. */

			/* Set the parameters. */
			feat_prot->FeatureSeqNo =
				ctrl_prot->second->SeqNo + 1;
			/* If Syncd false, then control state machine
			 * will TX LLDP message with local config. */
			if ((feat_prot->Advertise == true) ||
				(feat_prot->Advertise_prev == true)) {
				feat_prot->Syncd = false;
				LLDPAD_DBG("  Set Syncd to %u [%u]\n",
					feat_prot->Syncd, __LINE__);
			} else {
				feat_prot->Syncd = true;
				LLDPAD_DBG("  Set Syncd to %u [%u]\n",
					feat_prot->Syncd, __LINE__);
				feat_prot->tlv_sent = true;
			}
		}
		/* F4 If don't advertise, then copy the local config to
		 * Oper config. */
		if (!feat_prot->Advertise) {
			LLDPAD_DBG("  F5 - Advertise mode OFF:");
			LLDPAD_DBG(" %s", (EventFlag&(DCB_LOCAL_CHANGE_PG |
				DCB_REMOTE_CHANGE_PG)) ? "PG" : "");
			LLDPAD_DBG(" %s", (EventFlag&(DCB_LOCAL_CHANGE_PFC |
				DCB_REMOTE_CHANGE_PFC)) ? "PFC" : "");
			if (EventFlag & DCB_LOCAL_CHANGE_APPTLV(Subtype))
				LLDPAD_DBG(" APP%d", Subtype);
			LLDPAD_DBG(" %s", (EventFlag&(DCB_LOCAL_CHANGE_LLINK |
				DCB_REMOTE_CHANGE_LLINK)) ? "LLINK" : "");
			LLDPAD_DBG("\n");

			/* copy the local config to Oper config. */
			CopyConfigToOper(device_name, LOCAL_STORE,
				EventFlag, Subtype);
			/* State already in Listen so don't have to
			 * change. */
			feat_prot->Error = false;

			// maintain TOO_MANY_NGHBRS & FEAT_ERR_MULTI_TLV errors
			Err = feat_prot->Error_Flag;
			feat_prot->Error_Flag = FEAT_ERR_NONE;
			if (Err & FEAT_ERR_MULTI_PEER) {
				feat_prot->Error_Flag |= FEAT_ERR_MULTI_PEER;
			}
			if (Err & FEAT_ERR_MULTI_TLV) {
				feat_prot->Error_Flag |= (Err & FEAT_ERR_MULTI_TLV);
			}

			feat_prot->OperMode = feat_prot->Enable;
			set_configuration(device_name, EventFlag);
			goto OperChange;
		}

		/* On first call from add_port() ensure that the HW
		 * configuration is synced with the DCBX operational state.
		*/
		if (just_added) {
			CopyConfigToOper(device_name, LOCAL_STORE,
				EventFlag, Subtype);
			set_configuration(device_name, EventFlag);
		}

		/* Process remote change. */
		mask = DCB_SET_ALL_FLAGS(REMOTE);
		if (EventFlag & mask) {
			LLDPAD_DBG("  Remote change: ");
			LLDPAD_DBG(" %s", (EventFlag & DCB_REMOTE_CHANGE_PG) ?
				"PG" : "");
			LLDPAD_DBG(" %s", (EventFlag & DCB_REMOTE_CHANGE_PFC) ?
				"PFC" : "");
			if (EventFlag & DCB_REMOTE_CHANGE_APPTLV(Subtype))
				LLDPAD_DBG(" App%d", Subtype);
			LLDPAD_DBG(" %s", (EventFlag & DCB_REMOTE_CHANGE_LLINK) ?
				"LLINK" : "");
			LLDPAD_DBG("\n");

			/* This version check is part of the Control
			 * protocol state machine that must be
			 * complete before proceeding with feature
			 * protocol state machine */
			if (!((ctrl_prot->second->Oper_version ==
				MIN(peer_ctrl_prot->second->Max_version,
				ctrl_prot->second->Max_version)) &&
				(ctrl_prot->second->Oper_version ==
				peer_ctrl_prot->second->Oper_version)
				)) {
				goto ErrBadVersion;
			}

			if (feat_prot->dcbx_st == dcbx_subtype2) {
				/* Handle Peer expiration */
				if (peer_ctrl_prot->second->RxDCBTLVState ==
						DCB_PEER_EXPIRED) {
					LLDPAD_DBG("  F6.2 - Peer DCBX TLV Expired\n");
					CopyConfigToOper(device_name,
						LOCAL_STORE,EventFlag,Subtype);
					feat_prot->OperMode = false;
					feat_prot->Syncd = false;
					feat_prot->Error = true;
					feat_prot->FeatureSeqNo = 1;
					feat_prot->Error_Flag |= FEAT_ERR_NO_TLV;
					set_configuration(device_name,
						EventFlag);
					goto OperChange;
				}
			}

			/* Handle feature TLV not present */
			if (!peer_feat_prot->TLVPresent) {
				LLDPAD_DBG("  F8 - Feature not present\n");
				/* copy the local config to Oper config. */
				CopyConfigToOper(device_name, LOCAL_STORE,
					EventFlag, Subtype);
				feat_prot->OperMode = false;
				feat_prot->Syncd = true;
				LLDPAD_DBG("  Set Syncd to %u [%u]\n",
					feat_prot->Syncd, __LINE__);
				feat_prot->Oper_version =
					feat_prot->Max_version;
				if (feat_prot->dcbx_st == dcbx_subtype2) {
					feat_prot->Error = true;
				} else {
					feat_prot->Error = false;
				}
				feat_prot->Error_Flag |= FEAT_ERR_NO_TLV;
				set_configuration(device_name, EventFlag);
				goto OperChange;
			} else {
				feat_prot->Error_Flag &= ~FEAT_ERR_NO_TLV;
			}
			if (!feat_prot->Syncd &&
				(peer_ctrl_prot->second->AckNo
				!= feat_prot->FeatureSeqNo)) {

				/* Wait for the Peer to synch up. */
				LLDPAD_DBG("  Wait for Peer to synch: "
					"Peer AckNo %d, FeatureSeqNo %d \n",
					peer_ctrl_prot->second->AckNo,
					feat_prot->FeatureSeqNo);
				goto OperChange;
			}

			if (feat_prot->Error_Flag & FEAT_ERR_MULTI_TLV) {
				LLDPAD_DBG("  F9.1 - Rcvd Multiple DCBX TLVs\n");
				/* Copy Local config to Oper config. */
				CopyConfigToOper(device_name, LOCAL_STORE,
					EventFlag, Subtype);
				feat_prot->OperMode = false;
				Err = feat_prot->Error;
				feat_prot->Error = true;
				feat_prot->force_send = true;
				/* Set_configuration to driver. */
				if (set_configuration(device_name, EventFlag))
					feat_prot->Error_Flag |= FEAT_ERR_CFG;
				if (Err != feat_prot->Error) {
					ErrorChanged = true;
				}
				goto ErrProt;
			}

			/* Check for the Oper version */
			if (feat_prot->Oper_version !=
				MIN(peer_feat_prot->Max_version,
				feat_prot->Max_version)) {

				/* Update Oper version and signal LLDP send. */
				feat_prot->Oper_version =
					MIN(peer_feat_prot->Max_version,
					feat_prot->Max_version);
				LLDPAD_DBG("  Update feature oper version to %d "
					"and signal send\n",
					feat_prot->Oper_version);
				feat_prot->Syncd = false;
				LLDPAD_DBG("  Set Syncd to %u [%u]\n",
					feat_prot->Syncd, __LINE__);
				feat_prot->FeatureSeqNo =
					ctrl_prot->second->SeqNo + 1;
				goto OperChange;
			}
			feat_prot->Syncd =  true;
			LLDPAD_DBG("  Set Syncd to %u [%u]\n",
				feat_prot->Syncd, __LINE__);
				/* F13/F14 */

			if (feat_prot->Oper_version !=
				peer_feat_prot->Oper_version ) {
				/* Wait for Peer to synch up with * version */
				LLDPAD_DBG("  Wait for the Peer to synch up ");
				LLDPAD_DBG("with feature version.\n");
				goto OperChange;
			}

			feat_prot->PeerWilling = peer_feat_prot->Willing;
			/* F15 If feature is disabled on any side,
			 * then make Opermode false. */
			if (!feat_prot->Enable || !peer_feat_prot->Enable) {
				LLDPAD_DBG("  F16 - Feature is disabled\n");
				/* Copy Local config to Oper config. */
				CopyConfigToOper(device_name, LOCAL_STORE,
					EventFlag, Subtype);
				feat_prot->OperMode = false;
				feat_prot->Error_Flag = FEAT_ERR_NONE;
				Err = feat_prot->Error;
				/* Set_configuration to driver. */
				if (feat_prot->dcbx_st == dcbx_subtype2) {
					feat_prot->Syncd = !(feat_prot->Error);
					feat_prot->Error = false;
					if (set_configuration(device_name,
						EventFlag))
						feat_prot->Error_Flag
						|= FEAT_ERR_CFG;
				} else {
					feat_prot->Error = (set_configuration(
						device_name, EventFlag) !=
						cmd_success);
					if (feat_prot->Error)
						feat_prot->Error_Flag |=
						FEAT_ERR_CFG;
				}
				if (Err != feat_prot->Error) {
					ErrorChanged = true;
				}
				goto ErrProt;
			}
			/* F17 */
			if (feat_prot->Willing && !feat_prot->PeerWilling) {
				LLDPAD_DBG("  F18 - local willing,  "
					"peer NOT willing\n");

				feat_prot->Error_Flag = FEAT_ERR_NONE;
				Err = feat_prot->Error;

				if (feat_prot->dcbx_st == dcbx_subtype2) {
					feat_prot->OperMode =
						!(peer_feat_prot->Error);
					if (feat_prot->OperMode) {
						/* Copy Peer cfg to Oper cfg */
						CopyConfigToOper(device_name,
							PEER_STORE, EventFlag,
							Subtype);
					} else {
						/* Copy local cfg to Oper cfg*/
						CopyConfigToOper(device_name,
							LOCAL_STORE, EventFlag,
							Subtype);
					}
					feat_prot->Syncd = !(feat_prot->Error);
					feat_prot->Error = false;
					/* Set_configuration to driver. */
					if (set_configuration(device_name,
						EventFlag))
						feat_prot->Error_Flag |=
							FEAT_ERR_CFG;
				} else {
					feat_prot->OperMode = true;
					/* Copy Peer config to Oper config. */
					CopyConfigToOper(device_name,
						PEER_STORE, EventFlag,Subtype);
					/* Set_configuration to driver. */
					feat_prot->Error = (set_configuration(
						device_name, EventFlag) !=
							cmd_success);
					if (feat_prot->Error)
						feat_prot->Error_Flag |=
							FEAT_ERR_CFG;
				}
				if (Err != feat_prot->Error) {
					ErrorChanged = true;
				}
				goto ErrProt;
			}
			/* F19 */
			if (!feat_prot->Willing && feat_prot->PeerWilling) {
				LLDPAD_DBG("  F20 - local NOT willing,  "
					"peer willing\n");

				/* Copy Local config to Oper config. */
				CopyConfigToOper(device_name,
					LOCAL_STORE, EventFlag, Subtype);

				feat_prot->Error_Flag = FEAT_ERR_NONE;
				Err = feat_prot->Error;

				/* Set_configuration to driver. */
				if (feat_prot->dcbx_st == dcbx_subtype2) {
					feat_prot->OperMode =
						!peer_feat_prot->Error;
					feat_prot->Syncd = !(feat_prot->Error);
					feat_prot->Error = false;
					if (set_configuration(device_name,
						EventFlag))
						feat_prot->Error_Flag |=
							FEAT_ERR_CFG;
				} else {
					feat_prot->OperMode = true;
					feat_prot->Error = (set_configuration(
						device_name, EventFlag) !=
						cmd_success);
					if (feat_prot->Error)
						feat_prot->Error_Flag |=
							FEAT_ERR_CFG;
				}
				if (Err != feat_prot->Error)
					ErrorChanged = true;
				goto ErrProt;

			}
			/* F21 */
			if ((feat_prot->Willing == feat_prot->PeerWilling) &&
				(LocalPeerCompatible(device_name,
				EventFlag, Subtype))) {
				LLDPAD_DBG("  F22 - local willing == peer willing\n");

				/* Copy Local config to Oper config. */
				CopyConfigToOper(device_name,
					LOCAL_STORE, EventFlag, Subtype);

				feat_prot->Error_Flag = FEAT_ERR_NONE;
				Err = feat_prot->Error;
				/* Set_configuration to driver. */

				if (feat_prot->dcbx_st == dcbx_subtype2) {
					feat_prot->OperMode =
						!peer_feat_prot->Error;
					feat_prot->Syncd = !(feat_prot->Error);
					feat_prot->Error = false;
					if (set_configuration(device_name,
						EventFlag))
						feat_prot->Error_Flag |=
							FEAT_ERR_CFG;
				} else {
					feat_prot->OperMode = true;
					feat_prot->Error = (set_configuration(
						device_name, EventFlag) !=
							cmd_success);
					if (feat_prot->Error)
						feat_prot->Error_Flag |=
							FEAT_ERR_CFG;
				}
				if (Err != feat_prot->Error)
					ErrorChanged = true;
			} else {
				LLDPAD_DBG("  F23 - Local & Peer config not"
					" compatible\n");
				/* Copy Local config to Oper config. */
				CopyConfigToOper(device_name,
					LOCAL_STORE, EventFlag, Subtype);
				feat_prot->OperMode = false;
				Err = feat_prot->Error;

				/* Set default configuration */
				if (feat_prot->dcbx_st == dcbx_subtype2) {
					feat_prot->Syncd = feat_prot->Error;
					feat_prot->Error = true;
					if (set_configuration(device_name,
						EventFlag))
						feat_prot->Error_Flag |=
							FEAT_ERR_CFG;
				} else {
					feat_prot->Error = true;
					if (set_configuration(device_name,
						EventFlag) != cmd_success)
						feat_prot->Error_Flag |=
							FEAT_ERR_CFG;
				}
				feat_prot->Error_Flag |= FEAT_ERR_MISMATCH;
				if (Err != feat_prot->Error)
					ErrorChanged = true;
			}
ErrProt:
			if (peer_feat_prot->Error)
				feat_prot->Error_Flag |= FEAT_ERR_PEER;

			if (feat_prot->dcbx_st == dcbx_subtype1) {
				if (feat_prot->Error || peer_feat_prot->Error){
					LLDPAD_DBG("  ## FEATURE ERROR: "
						"%d, %d (Error_Flag 0x%x"
						" EventFlag 0x%x)\n",
						feat_prot->Error,
						peer_feat_prot->Error,
						feat_prot->Error_Flag,
						EventFlag);
					if (feat_prot->OperMode) {
						feat_prot->OperMode = false;
						/* Set default configuration */
						set_configuration(device_name,
								EventFlag);
					}
				}
			}
			if (ErrorChanged) {
				LLDPAD_DBG("  ErrorChanged \n");
				if (feat_prot->dcbx_st == dcbx_subtype1) {
					feat_prot->Syncd = false;
					LLDPAD_DBG("  Set Syncd to %u [%u]\n",
						feat_prot->Syncd, __LINE__);
				}
				feat_prot->FeatureSeqNo =
					ctrl_prot->second->SeqNo+ 1;
			}
		}
OperChange:
		if (DCB_TEST_FLAGS(EventFlag, DCB_EVENT_FLAGS,
			DCB_LOCAL_CHANGE_PG) ||
			DCB_TEST_FLAGS(EventFlag, DCB_EVENT_FLAGS,
			DCB_REMOTE_CHANGE_PG)) {

			pg_it Oper = pg_find(&oper_pg, device_name);

			if (Oper == NULL)
				goto ErrNoDevice;

			if (memcmp(&(old_pg_opcfg.tx), &(Oper->second->tx),
				sizeof(old_pg_opcfg.tx)) != 0)
				pg_events = pg_events | EVENT_OPERATTR;
			if (feat_prot->OperMode != old_pg_opmode) {
				pg_events = pg_events | EVENT_OPERMODE;
				if (feat_prot->OperMode) {
					LLDPAD_INFO("%s PG oper mode true",
						device_name);
				} else {
					LLDPAD_INFO("%s PG oper mode false",
						device_name);
				}
			}
		}
		if (DCB_TEST_FLAGS(EventFlag, DCB_EVENT_FLAGS,
			DCB_LOCAL_CHANGE_PFC)||
			DCB_TEST_FLAGS(EventFlag, DCB_EVENT_FLAGS,
			DCB_REMOTE_CHANGE_PFC)) {

			pfc_it Oper = pfc_find(&oper_pfc, device_name);
			if (Oper == NULL)
				goto ErrNoDevice;

			if (memcmp(&(old_pfc_opcfg.admin),
				&(Oper->second->admin),
				sizeof(old_pfc_opcfg.admin)) != 0)
				pfc_events = pfc_events | EVENT_OPERATTR;

			if (feat_prot->OperMode != old_pfc_opmode) {
				pfc_events = pfc_events | EVENT_OPERMODE;
				if (feat_prot->OperMode) {
					LLDPAD_INFO("%s PFC oper mode true",
						device_name);
				} else {
					LLDPAD_INFO("%s PFC oper mode false",
						device_name);
				}
			}
		}
		if (DCB_TEST_FLAGS(EventFlag, DCB_EVENT_FLAGS,
			DCB_LOCAL_CHANGE_APPTLV(Subtype)) ||
			DCB_TEST_FLAGS(EventFlag, DCB_EVENT_FLAGS,
			DCB_REMOTE_CHANGE_APPTLV(Subtype))) {

			app_it Oper = apptlv_find(&oper_apptlv, device_name,
							Subtype);
			if (Oper == NULL)
				goto ErrNoDevice;

			if ((old_app_opcfg.Length != Oper->second->Length)
				|| (old_app_opcfg.Length &&
				(memcmp(old_app_opcfg.AppData,
				Oper->second->AppData,
				old_app_opcfg.Length) != 0))) {
				app_events = app_events | EVENT_OPERATTR;
			}

			if (feat_prot->OperMode != old_app_opmode) {
				app_events = app_events | EVENT_OPERMODE;
				if (feat_prot->OperMode) {
					LLDPAD_INFO("%s APP oper mode true",
						device_name);
				} else {
					LLDPAD_INFO("%s APP oper mode false",
						device_name);
				}
			}
		}
		if (DCB_TEST_FLAGS(EventFlag, DCB_EVENT_FLAGS,
			DCB_LOCAL_CHANGE_LLINK)||
			DCB_TEST_FLAGS(EventFlag, DCB_EVENT_FLAGS,
			DCB_REMOTE_CHANGE_LLINK)) {

			llink_it Oper = llink_find(&oper_llink, device_name,
							Subtype);
			if (Oper == NULL)
				goto ErrNoDevice;

			if (memcmp(&(old_llink_opcfg.llink),
				&(Oper->second->llink),
				sizeof(old_llink_opcfg.llink)) != 0) {
				llink_events = llink_events | EVENT_OPERATTR;
				LLDPAD_DBG("llink opcfg changed \n");
			}

			if (feat_prot->OperMode != old_llink_opmode) {
				llink_events = llink_events | EVENT_OPERMODE;
				if (feat_prot->OperMode) {
					LLDPAD_DBG("llink opmode = true\n");
				} else {
					LLDPAD_DBG("llink opmode = false\n");
				}
			}
		}
	}

	if (pg_events)
		pg_event(device_name, pg_events);
	if (pfc_events)
		pfc_event(device_name, pfc_events);
	if (app_events)
		app_event(device_name, Subtype, app_events);
	if (llink_events)
		llink_event(device_name, Subtype, llink_events);
	return cmd_success;

ErrNoDevice:
	return cmd_device_not_found;

ErrBadVersion:
	LLDPAD_DBG("  Versions not compatible\n");
	return cmd_ctrl_vers_not_compatible;
}

cmd_status GetDCBTLVState(char *device_name, u8 *State)
{
	/* Get the remote control protocol variables. */
	control_prot_it peer_ctrl_prot = ctrl_prot_find(&dcb_peer_control_prot,
							device_name);
	if (peer_ctrl_prot == NULL)
		return cmd_device_not_found;

	*State = (u8)peer_ctrl_prot->second->RxDCBTLVState;

	return cmd_success;
}

bool FeaturesSynched(char *device_name)
{
	int i = 0;
	pg_it it = pg_find(&pg, device_name);
	if (it == NULL)
		return false;
	if (it->second->protocol.State == DCB_LISTEN) {
		if ((it->second->protocol.Syncd == false) ||
			(it->second->protocol.tlv_sent == false))
			return false;
	}

	/* Get the local PFC feature protocol */
	pfc_it it1 = pfc_find(&pfc, device_name);
	if (it1 == NULL)
		return false;
	if (it1->second->protocol.State == DCB_LISTEN) {
		if (it1->second->protocol.Syncd == false ||
		    it1->second->protocol.tlv_sent == false)
			return false;
	}

	/* Get the APP TLV feature protocol. */
	for (i = 0; i < DCB_MAX_APPTLV ; i++) {
		app_it it2 = apptlv_find(&apptlv, device_name, i);
		if (it2 == NULL)
			return false;
		if (it2->second->protocol.State == DCB_LISTEN) {
			if (it2->second->protocol.Syncd == false ||
				it2->second->protocol.tlv_sent ==false)
				return false;
		}
	}

	for (i = 0; i < DCB_MAX_LLKTLV ; i++) {
		/* Get the local LLINK feature protocol */
		llink_it it4 = llink_find(&llink, device_name, i);
		if (it4 == NULL)
			return false;
		if (it4->second->protocol.State == DCB_LISTEN) {
			if (it4->second->protocol.Syncd == false ||
				it4->second->protocol.tlv_sent == false)
				return false;
		}
	}

	return true;
}

/* Set the Syncd value to true for features which are not advertising.
*/
void update_feature_syncd(char *device_name)
{
	int i = 0;

	/* Get the local PG feature protocol */
	pg_it it = pg_find(&pg, device_name);
	if (it != NULL) {
		if (it->second->protocol.Advertise == false)
			it->second->protocol.Syncd = true;
		if (it->second->protocol.force_send == true)
			it->second->protocol.Syncd = true;
	}
	/* Get the local PFC feature protocol */
	pfc_it it1 = pfc_find(&pfc, device_name);
	if (it1 != NULL) {
		if (it1->second->protocol.Advertise == false)
			it1->second->protocol.Syncd = true;
		if (it1->second->protocol.force_send == true)
			it1->second->protocol.Syncd = true;
	}

	/* Get the APP TLV feature protocol. */
	for (i = 0; i < DCB_MAX_APPTLV ; i++) {
		app_it it2 = apptlv_find(&apptlv, device_name, i);
		if (it2 != NULL) {
			if (it2->second->protocol.Advertise == false)
				it2->second->protocol.Syncd = true;
			if (it2->second->protocol.force_send == true)
				it2->second->protocol.Syncd = true;
		}
	}

	for (i = 0; i < DCB_MAX_LLKTLV ; i++) {
		/* Get the local LLINK feature protocol */
		llink_it it4 = llink_find(&llink, device_name, i);
		if (it4 != NULL) {
			if (it4->second->protocol.Advertise == false)
				it4->second->protocol.Syncd = true;
			if (it4->second->protocol.force_send == true)
				it4->second->protocol.Syncd = true;
		}
	}
}

/******************************************************************************
**
** Method:      run_control_protocol
**
** Description: This function runs control state machine for a local or
**		remote change.
** The function caller should acquire lock before calling this function.
** Caller must call this function for local or remote change but not both.
**
** Arguments: char *device_name
**            u32 EventFlag
** Returns: cmd_success if successful, failure code otherwise.
**
*******************************************************************************/
cmd_status run_control_protocol(char *device_name, u32 EventFlag)
{
	pg_attribs pg_dstore;
	int i, mask;

	if (!dcbx_check_active(device_name))
		return cmd_success;

	/* Get the local control protocol variables. */
	control_prot_it ctrl_prot = ctrl_prot_find(&dcb_control_prot,
							device_name);
	if (ctrl_prot == NULL)
		return cmd_device_not_found;

	/* Get the remote control protocol variables. */
	control_prot_it peer_ctrl_prot = ctrl_prot_find(&dcb_peer_control_prot,
							device_name);
	if (peer_ctrl_prot == NULL)
		return cmd_device_not_found;

	if (ctrl_prot->second->State == DCB_INIT) {
		/* Set the parameters. */
		ctrl_prot->second->Oper_version =
					ctrl_prot->second->Max_version;
		ctrl_prot->second->State = DCB_LISTEN;
	}
	if (ctrl_prot->second->State == DCB_LISTEN) {
		LLDPAD_DBG("DCB Ctrl in LISTEN \n");
		/* Process local change if any. */
		mask = DCB_SET_ALL_FLAGS(LOCAL);
		if (EventFlag & mask) {
			LLDPAD_DBG("  Local change detected: ");
			LLDPAD_DBG(" %s", (EventFlag & DCB_LOCAL_CHANGE_PG) ?
				"PG" : "");
			LLDPAD_DBG(" %s", (EventFlag & DCB_LOCAL_CHANGE_PFC) ?
				"PFC" : "");
			for (i = 0; i < DCB_MAX_APPTLV; i++)
				if (EventFlag & DCB_LOCAL_CHANGE_APPTLV(i))
					LLDPAD_DBG(" APP%d", i);
			LLDPAD_DBG(" %s", (EventFlag & DCB_LOCAL_CHANGE_LLINK) ?
				"LLINK" : "");
			LLDPAD_DBG("\n");

			if (ctrl_prot->second->SeqNo ==
				ctrl_prot->second->MyAckNo) {
				LLDPAD_DBG("  Local SeqNo == Local AckNo\n");
				if (!FeaturesSynched(device_name)) {
					update_feature_syncd(device_name);
					ctrl_prot->second->SeqNo++;

					LLDPAD_DBG("  *** Sending packet -- ");
					LLDPAD_DBG("SeqNo = %d \t AckNo =  %d \n",
						ctrl_prot->second->SeqNo,
						ctrl_prot->second->AckNo);

					/* Send new DCB ctrl & feature TLVs */
					somethingChangedLocal(device_name, NEAREST_BRIDGE);
				}
			}
			return cmd_success;
		}
		/* Process remote change if any. */
		mask = DCB_SET_ALL_FLAGS(REMOTE);
		if (EventFlag & mask) {
			bool SendDCBTLV = false;
			LLDPAD_DBG("  Remote change detected(0x%x): ", EventFlag);
			LLDPAD_DBG(" %s", (EventFlag & DCB_REMOTE_CHANGE_PG) ?
				"PG" : "");
			LLDPAD_DBG(" %s", (EventFlag & DCB_REMOTE_CHANGE_PFC) ?
				"PFC" : "");
			for (i = 0; i < DCB_MAX_APPTLV; i++)
				if (EventFlag & DCB_REMOTE_CHANGE_APPTLV(i))
					LLDPAD_DBG(" APP%d", i);
			LLDPAD_DBG(" %s", (EventFlag & DCB_REMOTE_CHANGE_LLINK) ?
				"LLINK" : "");
			LLDPAD_DBG("\n");

			u8 State;
			if (GetDCBTLVState(device_name, &State) ==
				cmd_success) {
				if (State == DCB_PEER_EXPIRED) {
					ctrl_prot->second->SeqNo = 0;
					ctrl_prot->second->AckNo = 0;
					ctrl_prot->second->MyAckNo = 0;
					ctrl_prot->second->Oper_version =
					  ctrl_prot->second->Max_version;
					peer_ctrl_prot->second->RxDCBTLVState =
						DCB_PEER_RESET;

					LLDPAD_DBG(" Ctrl_prot Peer expired\n");
					if (get_pg(device_name, &pg_dstore) !=
						cmd_success) {
						LLDPAD_DBG("unable to get local pg"
						" cfg from data store\n");
						return cmd_device_not_found;
					}
					if (pg_dstore.protocol.dcbx_st ==
						dcbx_subtype2) {
						return cmd_success;
					} else {
						/* Send the updated DCB TLV */
						SendDCBTLV = true;
						goto send;
					}
				}
			}

			if (peer_ctrl_prot->second->Error_Flag &
					DUP_DCBX_TLV_CTRL) {
				LLDPAD_DBG("** HANDLE: DUP CTRL TLVs \n");
				goto send;
			}

			if (ctrl_prot->second->Oper_version !=
				MIN(peer_ctrl_prot->second->Max_version,
				ctrl_prot->second->Max_version)) {

				ctrl_prot->second->Oper_version =
					MIN(peer_ctrl_prot->second->Max_version,
					ctrl_prot->second->Max_version);

				/* Send the updated DCB TLV */
				SendDCBTLV = true;
				LLDPAD_DBG("  Change Oper Version \n");
				goto send;
			}

			if (ctrl_prot->second->Oper_version !=
				peer_ctrl_prot->second->Oper_version) {
				/* Wait for peer to synch up. */
				LLDPAD_DBG("  Wait for Peer to synch \n");
				goto send;
			}
			/* Update MyAck */
			ctrl_prot->second->MyAckNo =
				peer_ctrl_prot->second->AckNo;

			/* If received new Peer TLV, then acknowledge the
			 * Peer TLV
			 * MyAckNo == 0 means peer has started over, so
			 * also acknowledge in this case.
			*/
			if ((ctrl_prot->second->AckNo !=
				peer_ctrl_prot->second->SeqNo) ||
				(ctrl_prot->second->MyAckNo == 0)) {
				if (!(peer_ctrl_prot->second->Error_Flag
					& TOO_MANY_NGHBRS)) {
					ctrl_prot->second->AckNo =
						peer_ctrl_prot->second->SeqNo;
					SendDCBTLV = true;
				}
			}

			/* If changes in feature then send message with latest
			 * DCB and FeatureTLV */
send:
			LLDPAD_DBG("  Current -- SeqNo = %d \t MyAckNo =  %d \n",
				ctrl_prot->second->SeqNo,
				ctrl_prot->second->MyAckNo);
			if ((ctrl_prot->second->SeqNo ==
				ctrl_prot->second->MyAckNo)  &&
				(!FeaturesSynched(device_name))) {
				LLDPAD_DBG("  Features not synced \n");
				update_feature_syncd(device_name);
				/* Send LLDP message. */
				ctrl_prot->second->SeqNo++;
				LLDPAD_DBG("  *** Sending Packet -- ");
				LLDPAD_DBG("SeqNo = %d \t AckNo =  %d \n",
					ctrl_prot->second->SeqNo,
					ctrl_prot->second->AckNo);
				/* Send new DCB control & feature TLVs*/
				somethingChangedLocal(device_name, NEAREST_BRIDGE);
				return cmd_success;
			}

			if (SendDCBTLV) {
				LLDPAD_DBG("  SendDCBTLV is set \n");
				/* if you didn't send LLDP message above then
				 * send one without changing feature TLVs. */
				LLDPAD_DBG("  *** Sending Packet -- ");
				LLDPAD_DBG("SeqNo = %d \t AckNo =  %d \n",
					ctrl_prot->second->SeqNo,
					ctrl_prot->second->AckNo);
				/* Send new DCB TLVs with old feature TLVs. */
				somethingChangedLocal(device_name, NEAREST_BRIDGE);
			}
		}
	}
	return cmd_success;
}

/******************************************************************************
**
** Method:      run_dcb_protocol
**
** Description: This function runs both feature and control state machines
**	for the features that are specified in the event flag. The function
**	caller should acquire lock per port before calling this function.
**	Caller can only club together local  PG*PFC*APPTLV or
**	remote PG*PFC*APPTLV eventflags and call this function.
**
** Arguments: char *device_name
**            u32 EventFlag
**            u32 SubType - This is valid for APPTLV event flags only.
**                          If >= DCB_MAX_APPTLV, then we process all Subtypes
**                          for APPTLV flags.
** Returns: cmd_success if successful, failure code otherwise.
**
*******************************************************************************/
cmd_status run_dcb_protocol(char *device_name, u32 EventFlag, u32 Subtype)
{
	cmd_status result = cmd_success;
	bool LocalChange = false;
	u32 i, SubTypeMin, SubTypeMax;
	struct dcbx_tlvs *tlvs;
	int mask;

	LLDPAD_DBG("running DCB protocol for %s, flags:%04x\n", device_name,
		EventFlag);

	if (!dcbx_check_active(device_name))
		return result;

	/* if valid use SubType param, otherwise process all SubTypes */
	if (Subtype < DCB_MAX_APPTLV) {
		SubTypeMin = Subtype;
		SubTypeMax = Subtype+1;
	} else {
		SubTypeMin = 0;
		SubTypeMax = DCB_MAX_APPTLV;
	}
	/* Run the feature state machines:
	 *
	 * Order is important PFC must be run before PG features to
	 * allow up2tc remappings to account for PFC attributes.
	 */
	if (DCB_TEST_FLAGS(EventFlag, DCB_LOCAL_CHANGE_PFC,
		DCB_LOCAL_CHANGE_PFC)
		&& (result != cmd_ctrl_vers_not_compatible)) {
		result = run_feature_protocol(device_name,
			DCB_LOCAL_CHANGE_PFC, SUBTYPE_DEFAULT);
		LocalChange = true;
	}
	if (DCB_TEST_FLAGS(EventFlag, DCB_LOCAL_CHANGE_PG, DCB_LOCAL_CHANGE_PG)
		&& (result != cmd_ctrl_vers_not_compatible)) {
		result = run_feature_protocol(device_name, DCB_LOCAL_CHANGE_PG,
						SUBTYPE_DEFAULT);
		LocalChange = true;
	}
	mask = 0;
	for (i = 0; i < DCB_MAX_APPTLV; i++)
		mask |= DCB_LOCAL_CHANGE_APPTLV(i);
	if ((EventFlag & mask) && (result != cmd_ctrl_vers_not_compatible)) {
		for (i = SubTypeMin; i < SubTypeMax; i++) {
			result = run_feature_protocol(device_name,
				DCB_LOCAL_CHANGE_APPTLV(i), i);
		}
		LocalChange = true;
	}
	if (DCB_TEST_FLAGS(EventFlag, DCB_LOCAL_CHANGE_LLINK,
		DCB_LOCAL_CHANGE_LLINK)
		&& (result != cmd_ctrl_vers_not_compatible)) {

		result = run_feature_protocol(device_name,
				DCB_LOCAL_CHANGE_LLINK, i);
		LocalChange = true;
	}
	/* Only allow local or remote change at a time:
	 *
	 * Order is important PFC must be run before PG features to
	 * allow up2tc remappings to account for PFC attributes.
	 */
	if (!LocalChange) {
		if (DCB_TEST_FLAGS(EventFlag, DCB_REMOTE_CHANGE_PFC,
			DCB_REMOTE_CHANGE_PFC)
			&& (result != cmd_ctrl_vers_not_compatible)) {
			result = run_feature_protocol(device_name,
				DCB_REMOTE_CHANGE_PFC, SUBTYPE_DEFAULT);
		}
		if (DCB_TEST_FLAGS(EventFlag, DCB_REMOTE_CHANGE_PG,
			DCB_REMOTE_CHANGE_PG)
			&& (result != cmd_ctrl_vers_not_compatible)) {
			result = run_feature_protocol(device_name,
				DCB_REMOTE_CHANGE_PG, SUBTYPE_DEFAULT);
		}
		mask = 0;
		for (i = 0; i < DCB_MAX_APPTLV; i++)
			mask |= DCB_REMOTE_CHANGE_APPTLV(i);
		if ((EventFlag & mask) &&
		    (result != cmd_ctrl_vers_not_compatible)) {
			for (i = SubTypeMin; i < SubTypeMax; i++) {
				result = run_feature_protocol(device_name,
					DCB_REMOTE_CHANGE_APPTLV(i), i);
			}
		}
		if (DCB_TEST_FLAGS(EventFlag, DCB_REMOTE_CHANGE_LLINK,
			DCB_REMOTE_CHANGE_LLINK)
			&& (result != cmd_ctrl_vers_not_compatible)) {
			result = run_feature_protocol(device_name,
				DCB_REMOTE_CHANGE_LLINK, SUBTYPE_DEFAULT);
		}
	}

	/* apply all feature setting to the driver: linux only */
	tlvs = dcbx_data(device_name);
	if (tlvs && tlvs->operup) {
		LLDPAD_DBG("%s: %s: Managed DCB device coming online, program HW\n",
			    __func__, device_name);
		set_hw_all(device_name);
	}

	/* Run the control state machine. */
	result = run_control_protocol(device_name, EventFlag);

	return result;
}
