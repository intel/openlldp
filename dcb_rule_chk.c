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

#include <stdlib.h>
#include <string.h>
#include "dcb_protocol.h"
#include "dcb_rule_chk.h"
#include "messages.h"
#include "dcb_types.h"

/**
 * dcb_fixup_pg - resolves mismatch in number of traffic classes
 * @fixpg: pg attributes or resolve
 *
 * Resolve mismatch in number of traffic classes by
 * grouping traffic types. Requires at minimum at
 * least as many classes as traffic types (e.g. Best
 * Effort, PFC, and link strict).
 *
 * Strategy: This takes two passes over the attribs on
 * the first pass the pg attribs are packed into a
 * matrix with row index equal to pgid (pgid_up_list).
 * This allows identifying user priorities that map
 * to the same traffic class and traffic types.
 *
 * For example
 *
 * pgid:  0 0 3 1 2 0 4 4
 * pfcup: 0 0 1 1 1 0 1 1
 *
 * Maps to an pgid_up_list as follows,
 *
 * ------------------------------------
 *     up0|up1|up2|up3|up4|up5|up6|up7|
 * ------------------------------------
 * pg0| x | x |   |   |   | x |   |   |
 * ------------------------------------
 * pg1|   |   |   | x |   |   |   |   |
 * ------------------------------------
 * pg2|   |   |   |   | x |   |   |   |
 * ------------------------------------
 * pg3|   |   | x |   |   |   |   |   |
 * ------------------------------------
 * pg4|   |   |   |   |   |   | x | x |
 * ------------------------------------
 * pg5|   |   |   |   |   |   |   |   |
 * ------------------------------------
 * pg6|   |   |   |   |   |   |   |   |
 * ------------------------------------
 * pg7|   |   |   |   |   |   |   |   |
 * ------------------------------------
 *
 * Then on the second pass the rows are collapsed onto
 * the correct number of pgid values (result). Finally,
 * the new pgid and bandwidth percents can be tabulated.
 *
 * Above example collapses pg4 onto pg1 as follows.
 *
 * ------------------------------------
 *     up0|up1|up2|up3|up4|up5|up6|up7|
 * ------------------------------------
 * pg0| x | x |   |   |   | x |   |   |
 * ------------------------------------
 * pg1|   |   |   | x |   |   | x | x |
 * ------------------------------------
 * pg2|   |   |   |   | x |   |   |   |
 * ------------------------------------
 * pg3|   |   | x |   |   |   |   |   |
 * ------------------------------------
 *
 * This _should_ happen infrequently so we use up
 * arrays and variables freely. Any simpler suggestions
 * would be welcome.
 */
static int dcb_fixup_pg(struct pg_attribs *fixpg, struct pfc_attribs *fixpfc)
{
	dcb_user_priority_attribs_type * pgid_up_list[8][8] = { {0} };
	dcb_user_priority_attribs_type * result[8][8] = { {0} };
	dcb_user_priority_attribs_type *entry;
	int i, j, pgid;
	int be, pfc, strict, cbe, cpfc, cstrict;
	int tcbw[8] = {0};
	bool pg_done[8] = { 0 };
	int totalbw = 0;

	LLDPAD_INFO("%s : fixup\n", __func__);

	/* Calculate number of pgids used by attributes */
	for (pgid = 0, i = 0; i < MAX_USER_PRIORITIES; i++) {
		if (fixpg->tx.up[i].pgid > pgid)
			pgid = fixpg->tx.up[i].pgid;
	}
	pgid++;

	/* If the PGIDs can be mapped onto the number of existing traffic
	 * classes do it mapping pgs 1:1 with traffic classes via bwgid.
	 */
	if (pgid <= fixpg->num_tcs) {
		for (i = 0; i < MAX_USER_PRIORITIES; i++) {
			fixpg->tx.up[i].bwgid = i;
			fixpg->rx.up[i].bwgid = i;
		}
		return 0;
	}

	/* Build matrix with rows per pgid and columns per user priorities.
	 * Also count type of UP classes for PFC, best effort, and link
	 * strict.
	 */
	for (i = 0; i < MAX_USER_PRIORITIES; i++) {
		pgid = fixpg->tx.up[i].pgid;
		pgid_up_list[pgid][i] = &fixpg->tx.up[i];
	}

	strict = pfc = be = 0;

	for (i = 0; i < MAX_TRAFFIC_CLASS; i++) {
		for (j = 0; j < MAX_USER_PRIORITIES; j++) {
			entry = pgid_up_list[i][j];

			if (!entry)
				continue;

			if (entry->strict_priority == dcb_link)
				strict++;
			else if (fixpfc && fixpfc->admin[j] == pfc_enabled)
				pfc++;
			else
				be++;

			break;
		}
	}

	/* Require at least as many traffic classes as traffic types */
	if (fixpg->num_tcs < (!!be + !!strict + !!pfc))
		return -1;

	/* Map traffic class counts onto devices max number traffic classes */
	if (strict > fixpg->num_tcs - !!be - !!pfc)
		strict = fixpg->num_tcs - !!be - !!pfc;

	if (pfc > fixpg->num_tcs - strict - !!be)
		pfc = fixpg->num_tcs - strict - !!be;

	if (be > fixpg->num_tcs - strict - pfc)
		be = fixpg->num_tcs - strict - pfc;

	cbe = be;
	cstrict = strict;
	cpfc = pfc;

	totalbw = be = strict = pfc = 0;
	LLDPAD_INFO("%s -- tc types pfc %i be %i strict %i\n",
		     __func__, cpfc, cbe, cstrict);

	/* Do REMAPPING into result matrix */
	for (i = 0; i < MAX_TRAFFIC_CLASS; i++) {
		pgid = -1;

		for (j = 0; j < MAX_USER_PRIORITIES; j++) {
			entry = pgid_up_list[i][j];

			if (!entry)
				continue;

			if (pgid < 0) {
				if (entry->strict_priority == dcb_link) {
					pgid = cbe + cpfc + strict;
					strict++;
				} else if (fixpfc &&
					   fixpfc->admin[j] == pfc_enabled) {
					pgid = cbe + pfc;
					pfc++;
				} else {
					pgid = be;
					be++;
				}

				if (pfc == cpfc)
					pfc = 0;
				if (strict == cstrict)
					strict = 0;
				if (be == cbe)
					be = 0;
			}

			if (pg_done[i] == false) {
				tcbw[pgid] += fixpg->tx.pg_percent[i];
				totalbw += fixpg->tx.pg_percent[i];
				pg_done[i] = true;
			}

			/* Do row move from old pgid to new pgid */
			LLDPAD_INFO("%s: matrix: (%i,%i) -> (%i,%i)\n",
				    __func__, i, j, pgid, j);
			result[pgid][j] = entry;
		}
	}

	/* The peer _may_ give some percentage of pgpct to a user
	 * priority that has no pgid mapped to it. This seems like
	 * a poor config by the peer. However add the bandwidth to
	 * the highest priority traffic class (that is not strict).
	 */
	if (totalbw != 100) {
		pgid = fixpg->num_tcs - cstrict - 1;
		tcbw[pgid] += (100 - totalbw);
	}

	/* Traverse result matrix and push values onto entries */
	for (i = 0; i < MAX_TRAFFIC_CLASS; i++) {
		/* First Pass: Calculate TC BW and set pgid */
		for (j = 0; j < MAX_USER_PRIORITIES; j++) {
			entry = result[i][j];

			if (!entry)
				continue;

			LLDPAD_INFO("%s: result: up(%i): map %i->%i\n",
				    __func__,  j, entry->pgid, i);

			fixpg->rx.up[j].pgid = i;
			entry->pgid = i;
		}
	}

	/* Second Pass: Map BWGs 1:1 with priority groups */
	for (i = 0; i < MAX_USER_PRIORITIES; i++) {
		fixpg->tx.up[i].bwgid = i;

		if (fixpg->tx.up[i].strict_priority == dcb_link) {
			fixpg->tx.up[i].percent_of_pg_cap = 0;
			fixpg->rx.up[i].percent_of_pg_cap = 0;
		} else {
			fixpg->tx.up[i].percent_of_pg_cap = 100;
			fixpg->rx.up[i].percent_of_pg_cap = 100;
		}
	}

	/* Final Pass: Distribute TC bandwidth */
	for (i = 0; i < MAX_TRAFFIC_CLASS; i++) {
		fixpg->tx.pg_percent[i] = tcbw[i];
		fixpg->rx.pg_percent[i] = tcbw[i];
	}

	return 0;
}

/******************************************************************************
 * This function checks DCB rules for DCBs settings.
 * The following rules are checked:
 * 1. The sum of bandwidth percentages of all Bandwidth Groups must total 100%.
 * 2. The sum of bandwidth percentages of all Traffic Classes within a Bandwidth
 *	Group must total 100.
 * 3. A Traffic Class should not be set to both Link Strict Priority
 *	and Group Strict Priority. ***** assumed to be already checked
 * 4. Link strict Bandwidth Groups can only have link strict traffic classes
 *      with zero bandwidth.
 * dcb_config - Struct containing DCB settings.
 * return : cmd_status
 *****************************************************************************/
cmd_status
dcb_check_config (full_dcb_attrib_ptrs *attribs)
{
	pg_attribs  *pg;
	u8 i, tx_bw, rx_bw, tx_bw_id, rx_bw_id;
	u8 tx_bw_sum[MAX_BW_GROUP],rx_bw_sum[MAX_BW_GROUP];
	bool tx_link_strict[MAX_BW_GROUP], rx_link_strict[MAX_BW_GROUP];
	u8 link_strict_pgid;

	if (attribs == NULL)
		return cmd_failed;

	if (attribs->pg) {
		int err;

		pg = attribs->pg;
		memset(tx_bw_sum,0,sizeof(tx_bw_sum));
		memset(rx_bw_sum,0,sizeof(rx_bw_sum));
		memset(tx_link_strict,0,sizeof(tx_link_strict));
		memset(rx_link_strict,0,sizeof(rx_link_strict));

		tx_bw = 0, rx_bw = 0;

		err = dcb_fixup_pg(pg, attribs->pfc);
		if (err) {
			LLDPAD_DBG("dcb_fixup_pg returned error %i\n", err);
			return cmd_failed;
		}

		/* Internally in the pg_attribs structure, a link strict PGID is 
		 * maintained as a PGID value (0-7) with a corresponding
		 * strict_priority field value of 'dcb_link'.  Only one link strict
		 * PGID is allowed.
		*/
		link_strict_pgid = LINK_STRICT_PGID;
		/* Check rules for Tx and Rx Bandwidth Groups */
		for (i = 0; i < MAX_BW_GROUP; i++) {
			tx_bw = tx_bw + pg->tx.pg_percent[i];

			/* check for >1 link strict PGID */
			if (pg->tx.up[i].strict_priority == dcb_link) {
				if (link_strict_pgid == LINK_STRICT_PGID) {
					link_strict_pgid = pg->tx.up[i].pgid;
				} else if (pg->tx.up[i].pgid != link_strict_pgid) {
					LLDPAD_INFO("Too many LSP pgid %d\n",
						(int)pg->tx.up[i].pgid);
					return cmd_bad_params;
				}
			}
		}
		/* don't include link strict group %'s */
		if (link_strict_pgid < MAX_BW_GROUP)
			tx_bw = tx_bw - pg->tx.pg_percent[link_strict_pgid];

		if (tx_bw != BW_PERCENT) {
			/* only valid scenario for BWT!=100 is BWT==0 and all BWGs
			 * link strict
			 */
			for (i = 0; i < MAX_BW_GROUP; i++) {
				if ((tx_bw != 0) || (pg->tx.up[i].strict_priority !=
					dcb_link)) {
					LLDPAD_INFO("Invalid tx total BWG %d\n",
							(int)tx_bw);
					return cmd_bad_params;
				}
			}
		}

		link_strict_pgid = LINK_STRICT_PGID;
		for (i = 0; i < MAX_BW_GROUP; i++) {
			rx_bw = rx_bw + pg->rx.pg_percent[i];

			/* check for >1 link strict PGID */
			if (pg->rx.up[i].strict_priority == dcb_link) {
				if (link_strict_pgid == LINK_STRICT_PGID) {
					link_strict_pgid = pg->rx.up[i].pgid;
				} else if (pg->rx.up[i].pgid != link_strict_pgid) {
					LLDPAD_INFO("Too many lsp pgids %d\n",
						    (int)pg->rx.up[i].pgid);
					return cmd_bad_params;
				}
			}
		}
		/* don't include link strict group %'s */
		if (link_strict_pgid < MAX_BW_GROUP)
			rx_bw = rx_bw - pg->rx.pg_percent[link_strict_pgid];

		if (rx_bw != BW_PERCENT) {
			/* only valid scenario for BWT!=100 is BWT==0 and all BWGs
			 * link strict 
			 */
			for (i = 0; i < MAX_BW_GROUP; i++) {
				if ((rx_bw != 0) || (pg->rx.up[i].strict_priority !=
					dcb_link)) {
					LLDPAD_INFO("Invalid RX total BWG %d\n",
							(int)rx_bw);
					return cmd_bad_params;
				}
			}
		}

		/* Go through each traffic class and check rules for Tx and Rx */
		for (i = 0; i < MAX_TRAFFIC_CLASS; i++) {
			
			/* Since we assign strict priority to RX & TX via enumeration,
			 * from the data stores and from the peer. It would be
			 * impossible for both of them to be set.
			 * So that is no longer checked in this function.
			 */

			/* Transmit Check */ 
			tx_bw = 0, tx_bw_id = 0;
			tx_bw = (u8)(pg->tx.up[i].percent_of_pg_cap);
			tx_bw_id = (u8)(pg->tx.up[i].bwgid);

			if (tx_bw_id >= MAX_BW_GROUP) {
				LLDPAD_INFO("Invalid TX BWG idx %d\n",
					(int)tx_bw_id);
				return  cmd_bad_params;
			}
			if (pg->tx.up[i].strict_priority == dcb_link) {
				tx_link_strict[tx_bw_id] = true;
				/* Link strict should have zero bandwidth */
				if (tx_bw){
					LLDPAD_INFO("Non-zero LSP BW %d %d\n",
						i, (int)tx_bw);
					return cmd_bad_params;
				}
			} else if (!tx_bw) {
				LLDPAD_INFO("Zero BW on non LSP tc %i", i);
				/* Non link strict should have non zero bandwidth*/
				return cmd_bad_params;
			}
			/* Receive Check */
			rx_bw = 0, rx_bw_id = 0;
			rx_bw = (u8)(pg->rx.up[i].percent_of_pg_cap);
			rx_bw_id = (u8)(pg->rx.up[i].bwgid);

			if (rx_bw_id >= MAX_BW_GROUP) {
				LLDPAD_INFO("Invalid RX BW %i", rx_bw_id);
				return cmd_bad_params;
			}	   
			if (pg->rx.up[i].strict_priority == dcb_link) {
				rx_link_strict[rx_bw_id] = true;
				/* Link strict class should have zero bandwidth */
				if (rx_bw){
					LLDPAD_INFO("Non-zero LSP BW %d %d\n",
							i, (int)rx_bw);
					return cmd_bad_params;
				}
			} else if (!rx_bw) {
				LLDPAD_INFO("Zero BW on no LSP tc %i", i);
				/* Non link strict class should have non-zero bw */
				return cmd_bad_params; /* DCB_RX_ERR_TC_BW_ZERO; */
			}
			tx_bw_sum[tx_bw_id] = tx_bw_sum[tx_bw_id] + tx_bw;
			rx_bw_sum[rx_bw_id] = rx_bw_sum[rx_bw_id] + rx_bw;

		}

		/* Transmit Check */
		for (i = 0; i < MAX_BW_GROUP; i++) {
			/* sum of bandwidth percentages of all traffic classes within
			 * a Bandwidth Group must total 100 except for link strict
			 * group (zero bandwidth).
			 */
			if (tx_link_strict[i]) {
				if (tx_bw_sum[i] && pg->tx.pg_percent[i]) {
					LLDPAD_INFO("Non-zero LSP BW %d %d\n",
						i, (int)tx_bw_sum[i]);
					/* Link strict group should have zero bw */
					return cmd_bad_params;
				}
			} else if (tx_bw_sum[i] != BW_PERCENT && tx_bw_sum[i] != 0) {
				LLDPAD_INFO("Invalid BW sum on BWG %i %i",
						i, (int)tx_bw_sum[i]);
				return cmd_bad_params;
			}
		}
		/* Receive Check */
		for (i = 0; i < MAX_BW_GROUP; i++) {
			/* sum of bandwidth percentages of all traffic classes
			 * within a Bandwidth Group must total 100 except for
			 * link strict group ( zero bandwidth).
			 */
			if (rx_link_strict[i]) {
				if (rx_bw_sum[i] && pg->rx.pg_percent[i]) {
					LLDPAD_INFO("Non-zero BW on LSP tc "
						"%u %u\n", i, rx_bw_sum[i]);
					/* Link strict group should have zero bw */
					return cmd_bad_params;
				}
			} else if (rx_bw_sum[i] != BW_PERCENT && rx_bw_sum[i] != 0) {
				LLDPAD_INFO("Invalid BW sum on BWG %i %i",
						i, (int)rx_bw_sum[i]);
				return cmd_bad_params;
			}
		}
	}
	return cmd_success;
}


/******************************************************************************
 * This function checks updates the user priority bandwidth percentages
 * of the supplied PG attribute.
 * The user priorities for a given PGID will be assigned an equal share of
 * the PGID's bandwidth and group strict will be turned off.
 *****************************************************************************/

/* index is (number of priorities in PGID - 1)
 * value indicates the number of priorities which need to have the bw
 * incremented by 1 so the total will add to 100.
 * ex:  100/3 == 33   33+33+34 = 100  bw_fixup[2] = 1
*/
static u8 bw_fixup[MAX_USER_PRIORITIES] = { 0, 0, 1, 0, 0, 4, 2, 4 };

void rebalance_uppcts(pg_attribs *pg)
{
	u8 uplist[MAX_USER_PRIORITIES];
	int bwgid;
	int num_found;
	bool link_strict;
	int adjust;
	int value;
	int i;

	for (bwgid = 0; bwgid < MAX_BW_GROUP; bwgid++) {
		num_found = 0;
		link_strict = false;
		memset(uplist, 0xff, sizeof(uplist));
		for (i = 0; i < MAX_USER_PRIORITIES; i++) {
			if (pg->tx.up[i].bwgid == bwgid) {
				uplist[num_found++] = (u8)i;
				if (pg->tx.up[i].strict_priority == dcb_link) {
					link_strict = true;
					pg->tx.up[i].percent_of_pg_cap = 0;
					pg->rx.up[i].percent_of_pg_cap = 0;
				}
			}
		}

		if (num_found && !link_strict) {
			adjust = bw_fixup[num_found-1];
			for (i = 0; i < num_found; i++) {
				value = BW_PERCENT / num_found;
				if (adjust) {
					value++;
					adjust--;
				}
				pg->tx.up[uplist[i]].percent_of_pg_cap = (u8)value;
				pg->rx.up[uplist[i]].percent_of_pg_cap = (u8)value;
				pg->tx.up[uplist[i]].strict_priority = dcb_none;
				pg->rx.up[uplist[i]].strict_priority = dcb_none;
			}
		}
	}
}
