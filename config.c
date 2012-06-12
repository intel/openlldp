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

#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <unistd.h>
#include "eloop.h"
#include "lldpad.h"
#include "lldp.h"
#include "lldp/ports.h"
#include "lldp/agent.h"
#include "lldp/l2_packet.h"
#include "lldp_util.h"
#include "lldp_mod.h"
#include "lldp_mand_clif.h"
#include "lldp_med.h"
#include "dcb_protocol.h"
#include "dcb_persist_store.h"
#include "messages.h"
#include "config.h"
#include "lldpad_status.h"
#include "lldp_mod.h"
#include "event_iface.h"

config_t lldpad_cfg;

/*
 * init_cfg - initialze the global lldpad_cfg via config_init
 *
 * Returns true (1) for succes and false (0) for failed
 *
 * check to see if lldpad_cfs is already initailzied
 */
int init_cfg(void)
{
	const char *p;
	int err = 1;

	config_init(&lldpad_cfg);

	if (check_cfg_file()) {
		err = 0;
		LLDPAD_INFO("%s: failed to create config file\n", __func__);
	} else if (!config_read_file(&lldpad_cfg, cfg_file_name)) {
		err = 0;
		LLDPAD_INFO("%s: config file failed to load\n", __func__);
	} else if (config_lookup_string(&lldpad_cfg, "version", &p)) {
		LLDPAD_INFO("%s: config file version incorrect ", __func__);
		LLDPAD_INFO("rebuild file with correct version.\n");
		destroy_cfg();
		remove(cfg_file_name);
		if (check_cfg_file() ||
		    !config_read_file(&lldpad_cfg, cfg_file_name))
			err = 0;
	}
	return err;
}

/*
 * destroy_cfg - destroy the initialzed global lldpad_cfg
 *
 * Sets the cfgReturn true (1) for succes and false (0) for failed
 *
 * check to see if lldpad_cfg is already initialized
 */
void destroy_cfg(void)
{
	config_destroy(&lldpad_cfg);
}

void scan_port(UNUSED void *eloop_data, UNUSED void *user_ctx)
{
	struct port *port;
	struct if_nameindex *nameidx, *p;

	LLDPAD_INFO("%s: NLMSG dropped, scan ports.\n", __func__);

	nameidx = if_nameindex();
	if (nameidx == NULL) {
		LLDPAD_DBG("if_nameindex error try again later\n");
		goto error_out;
	}
	p = nameidx;

	/* Walk port list looking for devices that are not in if_nameindex.
	 * If the device is in the port list but not in the if_nameindex
	 * list then we missed a RTM_DELLINK event and the device is no
	 * longer available, possibly because the module has been unloaded.
	 * For this case lets remove the device from the ports list if it
	 * comes back online we should receive a RTM_NEWLINK event and can
	 * readd it there.
	 */
	port = porthead;
	while (port != NULL) {
		int found = 0;
		struct port *del;
		p = nameidx;
		while (p->if_index != 0) {
			if (!strncmp(p->if_name, port->ifname,
				     MAX_DEVICE_NAME_LEN)) {
				/* Good device exists continue port walk */
				found = 1;
				break;
			}
			p++;
		}
		del = port;
		port = port->next;
		if (!found)
			remove_port(del->ifname);
	}

	/* Walk port list looking for devices that should have been added
	 * to our port list but have not most likely due to a dropped nlmsg.
	 * At this point we need to add the device and call ops ifup routines.
	 * The port enable state needs to be set to match the real link state
	 * multiple link events and the port state is no longer reliable.
	 * This is required because we currently do not know if we missed
	 * IF_OPER_UP, IF_OPER_DOWN or IF_OPER_DORMANT. 
	 */
	p = nameidx;
	while (p->if_index != 0) {
		struct lldp_module *np;
		const struct lldp_mod_ops *ops;
		char *ifname = p->if_name;
		struct lldp_agent *agent;

		if (!is_valid_lldp_device(ifname)) {
			p++;
			continue;
		}

		port = port_find_by_name(p->if_name);
		if (!port) {
			if (is_bond(p->if_name))
				port = add_bond_port(p->if_name);
			else
				port = add_port(p->if_name);
		}

		if (port && check_link_status(ifname)) {
			set_port_oper_delay(ifname);
			oper_add_device(ifname);
		} else if (port) {
			LIST_FOREACH(agent, &port->agent_head, entry) {
				LLDPAD_DBG("%s: calling ifdown for agent %p.\n",
					   __func__, agent);
				LIST_FOREACH(np, &lldp_head, lldp) {
					ops = np->ops;
					if (ops->lldp_mod_ifdown)
						ops->lldp_mod_ifdown(ifname,
								     agent);
				}
			}
			set_lldp_port_enable(ifname, 0);
		}
		p++;
	}

	if_freenameindex(nameidx);
	return;
error_out:
	eloop_register_timeout(INI_TIMER, 0, scan_port, NULL, NULL);
	return;
}

void create_default_cfg_file(void)
{
	config_write_file(&lldpad_cfg, cfg_file_name);
}

/* check for existence of cfg file.  If it does not exist,
 * create it.
 * input:  cfg_file:  if NULL, use default cfg file name
 *                    else, use passed in name
 * output: 0:         no error
 *         !0:        errno of the call which failed
*/
int check_cfg_file(void)
{
	int fd;
	int retval = 0;

	if (access(cfg_file_name, R_OK | W_OK)) {
		if (access(cfg_file_name, F_OK)) {
			LLDPAD_INFO("config file failed to load, ");
			LLDPAD_INFO("create a new file.\n");
			fd = open(cfg_file_name,
				O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
			if (fd < 0) {
				retval = errno;
				LLDPAD_ERR("error creating %s !\n", cfg_file_name);
			} else {
				close(fd);
				create_default_cfg_file();
			}
		} else {
			retval = errno;
			LLDPAD_ERR("%s is not readable and writeable",
				cfg_file_name);
		}
	}

	return (retval);
}

static bool  check_bool(int bool_setting)
{
	if (bool_setting ==1 || bool_setting==0)
		return true;
	else
		return false;
}

static bool check_percentage(int percentage_setting)
{
	if (percentage_setting < 0 ||percentage_setting > 100)
		return false;
	else
		return true;
}

static bool check_char(int int_setting)
{
	if (int_setting < 0 || int_setting > 255)
		return false;
	else
		return true;
}

static bool check_int(int int_setting)
{
	if (int_setting < 0 || int_setting > 1000000)
		return false;
	else
		return true;
}

static bool check_priority(int priority_setting)
{
	if (priority_setting < dcb_none || priority_setting >= dcb_invalid)
		return false;
	else
		return true;
}

int get_int_config(config_setting_t *s, char *attr, int int_type,
				int *result)
{
	config_setting_t *setting = NULL;
	int rval = false;

	setting = config_setting_get_member(s, attr);
	if (setting) {
		*result = (int)config_setting_get_int(setting);
		switch(int_type) {
		case TYPE_BOOL:
			rval = check_bool(*result);
			break;
		case TYPE_PERCENT:
			rval = check_percentage(*result);
			break;
		case TYPE_CHAR:
			rval = check_char(*result);
			break;
		case TYPE_INT:
			rval = check_int(*result);
			break;
		default:
			break;
		}
	}

	if (!rval)
		LLDPAD_ERR("invalid value for %s", attr);

	return rval;
}

int get_array_config(config_setting_t *s, char *attr, int int_type,
			int *result)
{
	config_setting_t *setting = NULL;
	config_setting_t *setting_value = NULL;
	int rval = false;
	int i;

	setting = config_setting_get_member(s, attr);

	if (setting) {
		for (i = 0; i<config_setting_length(setting); i++) {
			setting_value = config_setting_get_elem(setting, i);
			*(result+i) =
				(char)config_setting_get_int(setting_value);

			switch(int_type) {
			case TYPE_BOOL:
				rval = check_bool(*(result+i));
				break;
			case TYPE_PERCENT:
				rval = check_percentage(*(result+i));
				break;
			case TYPE_CHAR:
				rval = check_char(*(result+i));
				break;
			case TYPE_INT:
				rval = check_int(*(result+i));
				break;
			case TYPE_PRIORITY:
				rval = check_priority(*(result+i));
				break;
			default:
				break;
			}
		}
	}

	if (!rval)
		LLDPAD_ERR("invalid setting for %s", attr);

	return rval;
}

void init_ports(void)
{
	struct lldp_module *np;
	struct if_nameindex *nameidx, *p;
	struct port *port;
	struct lldp_agent *agent;

	nameidx = if_nameindex();
	if (nameidx == NULL) {
		LLDPAD_DBG("error calling if_nameindex()\n");
		return;
	}

	p = nameidx;
	while (p->if_index != 0) {
		int valid = is_valid_lldp_device(p->if_name);

		if (!valid) {
			p++;
			continue;
		}

		if (is_bond(p->if_name))
			port = add_bond_port(p->if_name);
		else
			port = add_port(p->if_name);

		if (port == NULL) {
			LLDPAD_ERR("%s: Error adding device %s\n",
				     __func__, p->if_name);
		} else if (check_link_status(p->if_name)) {
			lldp_add_agent(p->if_name, NEAREST_BRIDGE);
			lldp_add_agent(p->if_name, NEAREST_NONTPMR_BRIDGE);
			lldp_add_agent(p->if_name, NEAREST_CUSTOMER_BRIDGE);

			LIST_FOREACH(agent, &port->agent_head, entry) {
				LLDPAD_DBG("%s: calling ifup for agent %p.\n",
					   __func__, agent);
				LIST_FOREACH(np, &lldp_head, lldp) {
					if (np->ops->lldp_mod_ifup)
						np->ops->lldp_mod_ifup(p->if_name, agent);
				}
			}
			set_lldp_port_enable(p->if_name, 1);
		}
		p++;
	}

	if_freenameindex(nameidx);
}

static int
set_config_value(config_setting_t *setting, union cfg_set v, int type)
{
	config_int_t tmp_int;

	switch (type) {
	case CONFIG_TYPE_INT:
		tmp_int = (config_int_t)*v.pint;
		return config_setting_set_int(setting, tmp_int);
	case CONFIG_TYPE_INT64:
		return config_setting_set_int64(setting, *v.p64);
	case CONFIG_TYPE_FLOAT:
		return config_setting_set_float(setting, *v.pfloat);
	case CONFIG_TYPE_STRING:
		return config_setting_set_string(setting, *v.ppchar);
	case CONFIG_TYPE_BOOL:
		return config_setting_set_bool(setting, *v.pint);
	default:
		return CONFIG_FALSE;
	}
}

static int lookup_config_value(char *path, union cfg_get v, int type)
{
	config_int_t tmp_int;
	int rc;

	switch (type) {
	case CONFIG_TYPE_INT:
		rc = config_lookup_int(&lldpad_cfg, path, &tmp_int);
		*v.pint = (int)tmp_int;
		return rc;
	case CONFIG_TYPE_INT64:
		return config_lookup_int64(&lldpad_cfg, path, v.p64);
	case CONFIG_TYPE_FLOAT:
		return config_lookup_float(&lldpad_cfg, path, v.pfloat);
	case CONFIG_TYPE_STRING:
		return config_lookup_string(&lldpad_cfg, path, v.ppchar);
	case CONFIG_TYPE_BOOL:
		return config_lookup_bool(&lldpad_cfg, path, v.pint);
	default:
		return CONFIG_FALSE;
	}
}


/*
 * get_config_setting - get the setting from the given config file path by type
 * @ifname: interface name
 * @agenttype: type of agent this needs to be retrieved from
 * @path: relative to LLDP_COMMON or ifname section of LLDP configuration.
 * @value: pointer to the value to be retrieved
 * @type: libconfig value types
 *
 * Returns cmd_success(0) for success, otherwise for failure.
 *
 * This function assumes init_cfg() has been called.
 */
int get_config_setting(const char *ifname, int agenttype, char *path,
		       union cfg_get v, int type)
{
	char p[1024];
	int rval = CONFIG_FALSE;
	const char *section = agent_type2section(agenttype);

	/* look for setting in section->ifname area first */
	if (ifname) {
		snprintf(p, sizeof(p), "%s.%s.%s",
			 section, ifname, path);
		rval = lookup_config_value(p, v, type);
	}

	/* if not found look for setting in section->common area */
	if (rval == CONFIG_FALSE) {
		snprintf(p, sizeof(p), "%s.%s.%s",
			 section, LLDP_COMMON, path);
		rval = lookup_config_value(p, v, type);
	}

	return (rval == CONFIG_FALSE) ? cmd_failed : cmd_success;
}

int remove_config_setting(const char *ifname, int agenttype, char *parent,
			  char *name)
{
	char p[1024];
	int rval = CONFIG_FALSE;
	config_setting_t *setting = NULL;
	const char *section = agent_type2section(agenttype);

	/* look for setting in section->ifname area first */
	if (ifname) {
		snprintf(p, sizeof(p), "%s.%s.%s",
			 section, ifname, parent);
		setting = config_lookup(&lldpad_cfg, p);
	}

	/* if not found look for setting in section->common area */
	if (setting == NULL) {
		snprintf(p, sizeof(p), "%s.%s.%s",
			 section, LLDP_COMMON, parent);
		setting = config_lookup(&lldpad_cfg, p);
	}

	if (setting != NULL) {
		rval = config_setting_remove(setting, name);
		if ((rval == CONFIG_TRUE) &&
			!config_write_file(&lldpad_cfg, cfg_file_name)) {
			LLDPAD_DBG("config write failed\n");
			rval = CONFIG_FALSE;
		}
	}

	return (rval == CONFIG_FALSE) ? cmd_failed : cmd_success;
}

/* calling get_config_setting() w/ init_cfg()/destroy_cfg() */
int get_cfg(const char *ifname, int agenttype, char *path, union cfg_get v,
	    int type)
{
	int rval;
	rval = get_config_setting(ifname, agenttype, path, v, type);
	return rval;
}

/* must be initially invoked with a scalar or array type
 * drills down path until it finds a part that exists (or not) and then
 * creates the settings on the way back up
 */
config_setting_t *find_or_create_setting(char *p, int type)
{
	config_setting_t *setting = NULL;
	char *s;
	int i;

	setting = config_lookup(&lldpad_cfg, p);

	/* if setting does not exist, then need to create it */
	if (setting == NULL) {
		for (i = strlen(p); i > 0; i--)
			if (*(p+i) == '.')
				break;
		if (i) {
			*(p+i) = '\0';
			setting = find_or_create_setting(p, CONFIG_TYPE_GROUP);
			*(p+i) = '.';
		} else {
			setting = config_root_setting(&lldpad_cfg);
		}

		if (setting) {
			for (i = strlen(p); i > 0; i--)
				if (*(p+i) == '.')
					break;
			if (i)
				s = p+i+1;
			else
				s = p;
			return config_setting_add(setting, s, type);
		}
	}

	return setting;
}

/*
 * set_config_setting - set the setting to the given config file path by type
 * @ifname: interface name
 * @path: relative to LLDP_COMMON or ifname section of LLDP configuration.
 * @value: pointer to the value to be retrieved
 * @type: libconfig value types
 *
 * Returns cmd_success(0) for success, otherwise for failure.
 *
 * This function assumes init_cfg() has been called.
 */
int set_config_setting(const char *ifname, int agenttype, char *path,
		       union cfg_set v, int type)
{
	config_setting_t *setting = NULL;
	char p[1024];
	int rval = cmd_success;
	const char *section = agent_type2section(agenttype);

	LLDPAD_DBG("%s(%i): \n", __func__, __LINE__);

	if (strlen(ifname))
		snprintf(p, sizeof(p), "%s.%s.%s",
			 section, ifname, path);
	else
		snprintf(p, sizeof(p), "%s.%s.%s",
			 section, LLDP_COMMON, path);
	setting = find_or_create_setting(p, type);

	if (setting) {
		if (!set_config_value(setting, v, type)) {
			rval = cmd_failed;
		} else if (!config_write_file(&lldpad_cfg, cfg_file_name)) {
			LLDPAD_DBG("config write failed\n");
			rval = cmd_failed;
		}
	}
	return rval;
}

int set_cfg(const char *ifname, int agenttype, char *path, union cfg_set v,
	    int type)
{
	int rval = cmd_failed;
	rval = set_config_setting(ifname, agenttype, path, v, type);
	return rval;
}

/* get_config_tlvfield - read one field from the tlvid
 * @ifname: the port name
 * @tlvid: oui + subtype
 * @field: name of the field to query
 * @value: output buffer
 * @size: size in bytes in the output buffer
 * @type: value type
 *
 * Returns 0 on success and -1 on failure
 *
 * Note: must have called init_cfg() before calling this.
 */
int get_config_tlvfield(const char *ifname, int agenttype, u32 tlvid,
			const char *field, union cfg_get v, int type)
{
	char path[256];

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "tlvid%08x.%s", tlvid, field);
	if (get_config_setting(ifname, agenttype, path, v, type))
		return EIO;

	return 0;
}

int get_config_tlvfield_int(const char *ifname, int agenttype, u32 tlvid,
			    const char *field, int *val)
{
	return get_config_tlvfield(ifname, agenttype, tlvid, field, val,
				   CONFIG_TYPE_INT);
}

int get_config_tlvfield_bool(const char *ifname, int agenttype, u32 tlvid,
			     const char *field, int *val)
{
	return get_config_tlvfield(ifname, agenttype, tlvid, field, val,
				   CONFIG_TYPE_BOOL);
}

int get_config_tlvfield_bin(const char *ifname, int agenttype, u32 tlvid,
			    const char *field, void *value, size_t size)
{
	int rc;
	const char *str = NULL;

	rc = get_config_tlvfield(ifname, agenttype, tlvid, field, &str,
				 CONFIG_TYPE_STRING);
	if (rc == 0 && str)
		rc = hexstr2bin(str, value, size);
	return rc;
}

int get_config_tlvfield_str(const char *ifname, int agenttype, u32 tlvid,
			    const char *field, char *value, size_t size)
{
	int rc;
	const char *str = NULL;

	rc = get_config_tlvfield(ifname, agenttype, tlvid, field, &str,
				 CONFIG_TYPE_STRING);
	if (rc == 0 && str)
		strncpy(value, str, size);
	return rc;
}

int get_config_tlvinfo_bin(const char *ifname, int agenttype, u32 tlvid,
			   void *value, size_t size)
{
	return get_config_tlvfield_bin(ifname, agenttype, tlvid, ARG_TLVINFO,
				       value, size);
}

int get_config_tlvinfo_str(const char *ifname, int agenttype, u32 tlvid,
			   char *value, size_t size)
{
	return get_config_tlvfield_str(ifname, agenttype, tlvid, ARG_TLVINFO,
				       value, size);
}

int set_config_tlvfield(const char *ifname, int agenttype, u32 tlvid,
			const char *field, union cfg_set v, int type)
{
	char path[256];

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "tlvid%08x.%s", tlvid, field);
	return set_config_setting(ifname, agenttype, path, v, type);
}

int set_config_tlvfield_str(const char *ifname, int agenttype, u32 tlvid,
			    const char *field, const char *str)
{
	if (!str)
		return EINVAL;
	return set_config_tlvfield(ifname, agenttype, tlvid, field, &str,
				   CONFIG_TYPE_STRING);
}

int set_config_tlvfield_bin(const char *ifname, int agenttype, u32 tlvid,
			    const char *field, void *value, size_t size)
{
	int rc;
	const size_t bsize = size * 2 + 1; /* 2 char per byte + '\0' */
	char str[bsize];
	const char *p;

	if (!value)
		return EINVAL;

	memset(str, 0, bsize);
	rc = bin2hexstr(value, size, str, bsize);
	if (rc)
		goto out;
	str[bsize - 1] = '\0';
	p = str;
	rc = set_config_tlvfield(ifname, agenttype, tlvid, field, &p,
				 CONFIG_TYPE_STRING);
out:
	return rc;
}

int set_config_tlvinfo_bin(const char *ifname, int agenttype, u32 tlvid,
			   void *value, size_t size)
{
	return set_config_tlvfield_bin(ifname, agenttype, tlvid, "info",
				       value, size);
}

int set_config_tlvinfo_str(const char *ifname, int agenttype, u32 tlvid,
			   char *value)
{
	return set_config_tlvfield_str(ifname, agenttype, tlvid, "info", value);
}

int set_config_tlvfield_int(const char *ifname, int agenttype, u32 tlvid,
			    const char *field, int *value)
{
	return set_config_tlvfield(ifname, agenttype, tlvid, field, value,
				   CONFIG_TYPE_INT);
}

int set_config_tlvfield_bool(const char *ifname, int agenttype, u32 tlvid,
			     const char *field, int *value)
{
	return set_config_tlvfield(ifname, agenttype, tlvid, field, value,
				   CONFIG_TYPE_BOOL);
}

int is_tlv_txdisabled(const char *ifname, int agenttype, u32 tlvid)
{
	char arg[64];
	int enabletx = true;

	snprintf(arg, sizeof(arg), "%s%08x.%s", TLVID_PREFIX,
		 tlvid, ARG_TLVTXENABLE);

	get_config_setting(ifname, agenttype, arg, &enabletx, CONFIG_TYPE_BOOL);

	return !enabletx;
}

int is_tlv_txenabled(const char *ifname, int agenttype, u32 tlvid)
{
	char arg[64];
	int enabletx = false;

	snprintf(arg, sizeof(arg), "%s%08x.%s", TLVID_PREFIX,
		 tlvid, ARG_TLVTXENABLE);

	get_config_setting(ifname, agenttype, arg, &enabletx, CONFIG_TYPE_BOOL);

	return enabletx;
}

int tlv_enabletx(const char *ifname, int agenttype, u32 tlvid)
{
	int enabletx = true;
	return set_config_tlvfield_bool(ifname, agenttype, tlvid,
					ARG_TLVTXENABLE, &enabletx);
}

int tlv_disabletx(const char *ifname, int agenttype, u32 tlvid)
{
	int enabletx = false;
	return set_config_tlvfield_bool(ifname, agenttype, tlvid,
					ARG_TLVTXENABLE, &enabletx);
}

void set_med_devtype(const char *ifname, int agenttype, int devtype)
{
	if (LLDP_MED_DEVTYPE_INVALID(devtype))
		return;
	set_config_tlvfield_int(ifname, agenttype, TLVID_MED(LLDP_MED_RESERVED),
				"devtype", &devtype);
}

int get_med_devtype(const char *ifname, int agenttype)
{
	int devtype, err;

	err = get_config_tlvfield_int(ifname, agenttype,
				      TLVID_MED(LLDP_MED_RESERVED),
				      "devtype", &devtype);

	if (err)
		devtype = 0;

	return devtype;
}
