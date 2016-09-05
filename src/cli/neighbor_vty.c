/*
 * Copyright (C) 2000 Kunihiro Ishiguro
 * Copyright (C) 2015-2016 Hewlett Packard Enterprise Development LP
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
/****************************************************************************
 * @ingroup cli/vtysh
 *
 * @file neighbor_vty.c
 *
 * show arp and ipv6 neighbor commands.
 *      show arp
 *      show ipv6 neighbor
 *
 ***************************************************************************/

#include <sys/un.h>
#include <setjmp.h>
#include <sys/wait.h>
#include <pwd.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "vtysh/lib/version.h"
#include "vtysh/command.h"
#include "vtysh/vtysh.h"
#include "vswitch-idl.h"
#include "ovsdb-idl.h"
#include "neighbor_vty.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "vrf-utils.h"
#include "smap.h"

VLOG_DEFINE_THIS_MODULE (vtysh_neighbor_cli);
extern struct ovsdb_idl *idl;

static int
show_arp_info (char* vrf_name)
{
  const struct ovsrec_neighbor *row = NULL;
  const struct ovsrec_vrf *vrf_row = NULL;

  ovsdb_idl_run (idl);

  if (NULL != vrf_name)
  {
      vrf_row = vrf_lookup(idl, vrf_name);
  } else {
      vrf_row = get_default_vrf(idl);
  }

  if (!vrf_row)
  {
       vty_out(vty, "VRF %s not found.%s", vrf_name, VTY_NEWLINE);
       VLOG_DBG("%s VRF \"%s\" is not found.", __func__, vrf_name);
       return CMD_SUCCESS;
  }

  row = ovsrec_neighbor_first (idl);
  if (!row)
    {
      vty_out (vty, "No ARP entries found.%s", VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  vty_out (vty, "ARP IPv4 Entries:%s", VTY_NEWLINE);
  vty_out (vty, "------------------%s", VTY_NEWLINE);
  vty_out (vty, "%-16s %-18s %-16s %-10s%s", "IPv4 Address", "MAC", "Port",
           "State", VTY_NEWLINE);

  /* OPS_TODO: Sort the output on Port (or other attribute) */
  OVSREC_NEIGHBOR_FOR_EACH (row, idl)
    {
     /* If part of different VRF, ignore and move to next record */
      if (row->vrf != vrf_row)
          continue;

      /* non-IPv4 entries, ignore and move to next record */
      if (row->address_family && strcmp (row->address_family, OVSREC_NEIGHBOR_ADDRESS_FAMILY_IPV4))
        continue;

      DISPLAY_NEIGHBOR_IP4_ADDR (vty, row);
      DISPLAY_NEIGHBOR_MAC_ADDR (vty, row);
      DISPLAY_NEIGHBOR_PORT_NAME (vty, row);
      DISPLAY_NEIGHBOR_STATE (vty, row);

      DISPLAY_VTY_NEWLINE (vty);
    }

  return CMD_SUCCESS;
}

/* Handle 'show ipv6 neighbor' command */
static int
show_ipv6_neighbors (char* vrf_name)
{
  const struct ovsrec_neighbor *row = NULL;
  const struct ovsrec_vrf *vrf_row = NULL;
  ovsdb_idl_run (idl);

  if (NULL != vrf_name)
  {
      vrf_row = vrf_lookup(idl, vrf_name);
  } else {
      vrf_row = get_default_vrf(idl);
  }

  if (!vrf_row)
  {
      vty_out(vty, "VRF %s not found.%s", vrf_name, VTY_NEWLINE);
      VLOG_DBG("%s VRF \"%s\" is not found.", __func__, vrf_name);
      return CMD_SUCCESS;
  }

  row = ovsrec_neighbor_first (idl);
  if (!row)
    {
      vty_out (vty, "No IPv6 neighbors found.%s", VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  vty_out (vty, "IPv6 Entries:%s", VTY_NEWLINE);
  vty_out (vty, "------------------%s", VTY_NEWLINE);
  vty_out (vty, "%-46s %-18s %-16s %-10s%s", "IPv6 Address", "MAC", "Port",
           "State", VTY_NEWLINE);

  /* OPS_TODO: Sort the output on Port (or other attribute) */
  OVSREC_NEIGHBOR_FOR_EACH (row, idl)
    {
     /* If part of different VRF, ignore and move to next record */
      if (row->vrf != vrf_row)
         continue;

      /* non-IPv6 entries, ignore and move to next record */
      if (row->address_family && strcmp (row->address_family, OVSREC_NEIGHBOR_ADDRESS_FAMILY_IPV6))
        continue;

      DISPLAY_NEIGHBOR_IP6_ADDR (vty, row);
      DISPLAY_NEIGHBOR_MAC_ADDR (vty, row);
      DISPLAY_NEIGHBOR_PORT_NAME (vty, row);
      DISPLAY_NEIGHBOR_STATE (vty, row);

      DISPLAY_VTY_NEWLINE (vty);
    }

  return CMD_SUCCESS;
}

#ifdef VRF_ENABLE
DEFUN (cli_arp_show,
    cli_arp_show_cmd,
    "show arp { vrf WORD }",
    SHOW_STR
    SHOW_ARP_STR
    "VRF Information\n"
    "VRF name\n")
{
  return show_arp_info((char*) argv[0]);
}
#else
DEFUN (cli_arp_show,
    cli_arp_show_cmd,
    "show arp",
    SHOW_STR
    SHOW_ARP_STR)
{
  return show_arp_info(NULL);
}
#endif

#ifdef VRF_ENABLE
DEFUN (cli_ipv6_show,
    cli_ipv6_neighbors_show_cmd,
    "show ipv6 neighbors {vrf WORD }",
    SHOW_STR
    IPV6_STR
    SHOW_IPV6_NEIGHBOR_STR
    "VRF Information\n"
    "VRF name\n")

{
  return show_ipv6_neighbors((char*) argv[0]);
}
#else
DEFUN (cli_ipv6_show,
    cli_ipv6_neighbors_show_cmd,
    "show ipv6 neighbors",
    SHOW_STR
    IPV6_STR
    SHOW_IPV6_NEIGHBOR_STR)
{
  return show_ipv6_neighbors(NULL);
}
#endif
/*******************************************************************
 * @func        : arpmgr_ovsdb_init
 * @detail      : Add arpmgr related table & columns to ops-cli
 *                idl cache
 *******************************************************************/

static void
arpmgr_ovsdb_init(void)
{
    /* Neighbor table for 'show arp' & 'show ipv6 neighbor' commands. */
    ovsdb_idl_add_table(idl, &ovsrec_table_neighbor);
    ovsdb_idl_add_column(idl, &ovsrec_neighbor_col_address_family);
    ovsdb_idl_add_column(idl, &ovsrec_neighbor_col_mac);
    ovsdb_idl_add_column(idl, &ovsrec_neighbor_col_state);
    ovsdb_idl_add_column(idl, &ovsrec_neighbor_col_ip_address);
    ovsdb_idl_add_column(idl, &ovsrec_neighbor_col_port);
    ovsdb_idl_add_column(idl, &ovsrec_neighbor_col_vrf);
    ovsdb_idl_add_table(idl, &ovsrec_table_vrf);
    ovsdb_idl_add_column(idl, &ovsrec_vrf_col_name);
    return;
}

/* Initialize ops-arpmgrd cli node.
 */
void cli_pre_init(void)
{
   arpmgr_ovsdb_init();
   return;
}

/* Initialize ops-arpmgrd cli element.
 */
void cli_post_init(void)
{
  install_element (ENABLE_NODE, &cli_arp_show_cmd);
  install_element (ENABLE_NODE, &cli_ipv6_neighbors_show_cmd);
  return;
}
