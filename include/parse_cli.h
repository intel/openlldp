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

#ifndef _PARSE_CLI_H_
#define _PARSE_CLI_H_

#define GOT_ADVERTISE 0x0001
#define GOT_ENABLE    0x0002
#define GOT_WILLING   0x0004
#define GOT_UP2TC     0x0008
#define GOT_PGPCT     0x0010
#define GOT_PGID      0x0020
#define GOT_UPPCT     0x0040
#define GOT_STRICT    0x0080
#define GOT_LLSTATUS  0x0100
#define GOT_APPCFG    0x0200
#define GOT_PFCUP     0x0400

int get_port_len(void);
int *get_up2tc(void);
int *get_pgpct(void);
int *get_pgid(void);
int *get_uppct(void);
int *get_strict(void);
int *get_pfcup(void);
char *get_appcfg(void);
int get_enable(void);
int get_dcb_param(void);
int get_dcbx_param(void);
int get_advertise(void);
int get_willing(void);
int get_cmd(void);
int get_fargs(void);
int get_feature(void);
int get_subtype(void);
int get_desc_id(void);
char *get_desc_str(void);
void free_desc_str(void);
int *get_rp(void);
int *get_bcna(void);
int get_rp_alpha(float *);
int get_rp_beta(float *);
int get_rp_gd(float *);
int get_rp_gi(float *);
int get_rp_tmax(unsigned int *);
int get_rp_td(unsigned int *);
int get_rp_rmin(unsigned int *);
int get_rp_w(unsigned int *);
int get_rp_rd(unsigned int *);
int get_rp_ru(unsigned int *);
int get_rp_wrtt(unsigned int *);
int get_rp_ri(unsigned int *);
int get_llstatus(void);
char *get_port(void);
void free_port(void);
void free_appcfg(void);
char *get_parse_error(void);
void free_parse_error(void);
void init_parse_state(void);
int parse_dcb_cmd(char *buf);

#endif /* _PARSE_CLI_H_ */
