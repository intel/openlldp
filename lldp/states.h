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

#ifndef STATES_H
#define STATES_H

#include "ports.h"

/* Tx Timer States */
enum {
	TX_TIMER_BEGIN,
	TX_TIMER_INITIALIZE,
	TX_TIMER_IDLE,
	TX_TIMER_EXPIRES,
	TX_TICK,
	SIGNAL_TX,
	TX_FAST_START
};

/* Tx States */
enum {
	TX_LLDP_INITIALIZE,
	TX_IDLE,
	TX_SHUTDOWN_FRAME,
	TX_INFO_FRAME 
};

/**
 * The txInitializeLLDP () procedure initializes the LLDP transmit module as
 * defined in 10.1.1.
*/
void txInitializeLLDP(struct lldp_agent *agent);

/**
 * The mibConstrInfoLLDPDU () procedure constructs an information LLDPDU as
 * defined in 10.2.1.1 according to the LLDPDU and associated basic TLV
 * formats as specified in 9.2 and 9.4 plus any optional
 * Organizationally Specific TLVs as specified in 9.6 and their associated
 * individual organizationally defined formats (as, for example, in Annex F
 * and Annex G).
 *
 * NOTE Because selection of which specific TLVs to include in an LLDPDU is a
 * LLDP MIB management function, the transmit state machine does not include a
 * separate procedure for this purpose (see 10.2.1.1).
*/
bool mibConstrInfoLLDPDU(struct port *, struct lldp_agent *);

/**
 * The mibConstrShutdownLLDPDU () procedure constructs a shutdown LLDPDU as
 * defined in 10.2.1.2 and according to the LLDPDU and the associated TLV
 * formats specified in 9.2 and 9.5.
*/ 
bool mibConstrShutdownLLDPDU(struct port *, struct lldp_agent *);

/**
 * The txFrame () procedure prepends the source and destinations addresses
 * and the LLDP Ethertype to each LLDPDU as defined in 10.2.2 before it is
 * sent to the MAC for transmission.
*/ 
u8 txFrame(struct port *port, struct lldp_agent *);

void run_tx_sm(struct port *, struct lldp_agent *);
void process_tx_initialize_sm(struct port *);
void process_tx_idle(struct lldp_agent *);
void process_tx_shutdown_frame(struct port *, struct lldp_agent *);
void process_tx_info_frame(struct port *, struct lldp_agent *);
void update_tx_timers(struct lldp_agent *);
void run_tx_timers_sm(struct port *, struct lldp_agent *);
bool set_tx_state(struct port *, struct lldp_agent *);
void txInitializeTimers(struct lldp_agent *);
void tx_change_state(struct port *, struct lldp_agent *, u8 );

/******************************************************************************/
/* Rx States */
enum {
	LLDP_WAIT_PORT_OPERATIONAL = 4,
	DELETE_AGED_INFO,
	RX_LLDP_INITIALIZE,
	RX_WAIT_FOR_FRAME,
	RX_FRAME,
	DELETE_INFO,
	UPDATE_INFO
};

/**
 * The rxInitializeLLDP () procedure initializes the LLDP receive module
 * as defined in 10.1.2.
*/
void rxInitializeLLDP(struct port *port, struct lldp_agent *);

/**
 * The rxProcessFrame () procedure:
 * a)   Strips the protocol identification fields from the received frame
 *      and validates the TLVs contained in
 *      the LLDPDU as defined in 10.3.1 and 10.3.2.
 * b)   Determines whether or not a MIB update may be required as defined in
 *      10.3.3.
 *       1)   If an update is required and sufficient space is available to
 *            store the LLDPDU information in the LLDP remote systems MIB, the
 *            control variable rxChanges is set to TRUE.
 *       2)   If an update is not required, the control variable rxChanges is
 *            set to FALSE.
 * c)   If sufficient space is not available, determines whether to discard
 *      the incoming LLDPDU from a new neighbor or to delete information from
 *      an existing neighbor that is already in the LLDP remote systems MIB, as
 *      defined in 10.3.4. The tooManyNghbrsTimer and the tooManyNghbrs
 *      flag variable are both set during this process.
 * NOTES
 * 1: The variable badFrame is set to FALSE in the receive state machine state
 *    RX_FRAME before entering the procedure rxProcessFrame(). It is set to
 *    TRUE by rxProcessFrame() if the LLDPDU fails validation (see 10.3.2).
 * 2: The flag variable tooManyNghbrs is automatically reset when the
 *    tooManyNghbrsTimer expires.
*/
void rxReceiveFrame(void *, int ifindex, const u8 *, size_t);
void rxProcessFrame(struct port *, struct lldp_agent *);

/**
 * The mibDeleteObjects () procedure deletes all information in the LLDP
 * remote systems MIB associated with the MSAP identifier if an LLDPDU is
 * received with an rxTTL value of zero (see 10.3.2) or the timing counter
 * rxInfoTTL expires. (see 10.3.6).
*/
u8 mibDeleteObjects(struct port *port, struct lldp_agent *);

/**
 * The mibUpdateObjects () procedure updates the MIB objects corresponding to
 * the TLVs contained in the received LLDPDU for the LLDP remote system
 * indicated by the LLDP remote systems update process defined in 10.3.5.
 * NOTE To avoid a race condition, the flag variable remoteChange
 * is not set to TRUE until after the information in the LLDP remote systems
 * MIB has been updated.
*/
void mibUpdateObjects(struct port *, struct lldp_agent *);

void run_rx_sm(struct port *, struct lldp_agent *);
bool set_rx_state(struct port *, struct lldp_agent *);
void rx_change_state(struct lldp_agent *, u8 );
void process_delete_aged_info(struct port *, struct lldp_agent *);
void process_rx_lldp_initialize(struct port *, struct lldp_agent *);
void process_wait_for_frame(struct lldp_agent *);
void process_rx_frame(struct port *, struct lldp_agent *);
void process_delete_info(struct port *, struct lldp_agent *);
void process_update_info(struct lldp_agent *);
void update_rx_timers(struct lldp_agent *);
void clear_manifest(struct lldp_agent *);
#endif /* STATES_H */
