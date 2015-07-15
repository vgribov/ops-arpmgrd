/*
 * Copyright (C) 2015 Hewlett-Packard Development Company, L.P.
 * All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License"); you may
 *   not use this file except in compliance with the License. You may obtain
 *   a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *   License for the specific language governing permissions and limitations
 *   under the License.
 *
 * File: arpmgrd.c
 */

#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <net/if.h>

/* OVSDB Includes */
#include "config.h"
#include "command-line.h"
#include "daemon.h"
#include "dirs.h"
#include "poll-loop.h"
#include "unixctl.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "vswitch-idl.h"
#include "coverage.h"

#include "arpmgrd.h"

VLOG_DEFINE_THIS_MODULE(arpmgrd);
COVERAGE_DEFINE(arpmgrd_reconfigure);
static struct ovsdb_idl *idl;
static unsigned int idl_seqno;
static unixctl_cb_func arpmgrd_unixctl_dump;
static int system_configured = false;
static unixctl_cb_func halon_arpmgrd_exit;
static char *parse_options(int argc, char *argv[], char **unixctl_path);
OVS_NO_RETURN static void usage(void);

int netlink_request_neighbor_dump(int sock);

struct ovsrec_vrf * find_port_vrf(const struct ovsrec_open_vswitch *ovs_row,
                                      const char *port_name);

/* Netlink Globals */
static int nl_neighbor_sock;

/* Netlink functions to read and parse neighbor messages */

int netlink_socket_open(int protocol, int group)
{
    struct sockaddr_nl s_addr;

    int sock = socket(AF_NETLINK, SOCK_RAW, protocol);

    if (sock < 0)
        return sock;

    memset((void *) &s_addr, 0, sizeof(s_addr));
    s_addr.nl_family = AF_NETLINK;
    s_addr.nl_pid = getpid();
    s_addr.nl_groups = group;
    if (bind(sock, (struct sockaddr *) &s_addr, sizeof(s_addr)) < 0)
        return -1;

    netlink_request_neighbor_dump(sock);
    return sock;
}

void close_netlink_socket(int socket)
{
    close(socket);
}

int netlink_request_neighbor_dump(int sock)
{
    struct rtattr *rta;
    int status;
    struct nl_req req;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

    req.n.nlmsg_type = RTM_GETNEIGH;
    req.r.ndm_family = AF_INET;
    req.n.nlmsg_pid = getpid();

    rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.n.nlmsg_len));
    rta->rta_len = RTA_LENGTH(4);

    status = send(sock, &req, req.n.nlmsg_len, 0);
    return status;
}

int add_neighbor(struct rtattr* rta, struct ndmsg* ndm, int rtlen)
{
    char ifname[IF_NAMESIZE];
    struct ovsrec_vrf *vrf = NULL;
    char destip[INET6_ADDRSTRLEN];
    char dstmac[18];
    const struct ovsrec_open_vswitch *ovs = ovsrec_open_vswitch_first(idl);
    const struct ovsrec_neighbor *nbr = NULL;
    struct ovsdb_idl_txn *txn = ovsdb_idl_txn_create(idl);;

    if(ndm->ndm_family != AF_INET && ndm->ndm_family != AF_INET6)
        return -1;

    if_indextoname(ndm->ndm_ifindex, ifname);

    /* Find vrf this interface/port is associated.*/
    vrf = find_port_vrf(ovs, ifname);

    /*
     * If VRF is not found, this is strange.
     * Only L3 ports in VRFs should be getting arp
     * updates
     */
    if(!vrf) {
        VLOG_ERR("Port not part of VRF %s", ifname);
        return 0;
    }

    while (1) {
        if (rta->rta_type == NDA_DST) {
            if(strcmp(ifname, LOOPBACK_INTERFACE_NAME)) {

                bool found = false;

                memset(destip, 0, sizeof(destip));

                if(ndm->ndm_family == AF_INET) {
                    uint32_t addr = ntohl(*(uint32_t *)RTA_DATA(rta));
                    inet_ntop(AF_INET, RTA_DATA(rta), destip, INET_ADDRSTRLEN);
                    /* Ignore multicast addresses */
                    if(ISMULTICAST(addr))
                    {
                        VLOG_INFO("Received multicast addr %s, Ignoring", destip);
                        rta = RTA_NEXT(rta, rtlen);
                        if (RTA_OK(rta, rtlen) != 1)
                        {
                            break;
                        }
                        continue;
                    }
                } else if(ndm->ndm_family == AF_INET6)   {
                    inet_ntop(AF_INET6, RTA_DATA(rta), destip, INET6_ADDRSTRLEN);
                }

                OVSREC_NEIGHBOR_FOR_EACH (nbr, idl) {
                    if(!strcmp(nbr->network_address, destip)) {
                        found = true;
                        break;
                    }
                }

                if(!found) {
                    VLOG_INFO("Adding New Neighbor %s", destip);
                    nbr = ovsrec_neighbor_insert(txn);
                }

                /* Delete the entry if state is NUD_FAILED or NUD_INCOMPLETE */
                if((ndm->ndm_state & NUD_FAILED) || (ndm->ndm_state & NUD_INCOMPLETE)) {
                    VLOG_INFO("Deleting Invalid/Failed Neighbor %s", destip);
                    enum ovsdb_idl_txn_status status;
                    ovsrec_neighbor_delete(nbr);
                    status = ovsdb_idl_txn_commit_block(txn);
                    VLOG_DBG("Delete Txn status: %d", status);
                    ovsdb_idl_txn_destroy(txn);
                    return 1;
                }

            }
        } else if (rta->rta_type == NDA_LLADDR) {
            char *mac = RTA_DATA(rta);
            sprintf(dstmac, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0] & 0xff ,
                    mac[1] & 0xff, mac[2] & 0xff, mac[3] & 0xff, mac[4] & 0xff,
                    mac[5] & 0xff);


        }
        rta = RTA_NEXT(rta, rtlen);
        if (RTA_OK(rta, rtlen) != 1)
        {
            break;
        }
    }

    if(nbr) {
        enum ovsdb_idl_txn_status status;
        ovsrec_neighbor_set_network_address(nbr, destip);
        /* Set  VRF */
        ovsrec_neighbor_set_vrf(nbr, vrf);
        if(ndm->ndm_family == AF_INET) {
            inet_ntop(AF_INET, RTA_DATA(rta), destip, INET_ADDRSTRLEN);
            ovsrec_neighbor_set_address_family(nbr, IPV4_ADDRESS_FAMILY_STRING);
        } else if(ndm->ndm_family == AF_INET6)   {
            inet_ntop(AF_INET6, RTA_DATA(rta), destip, INET6_ADDRSTRLEN);
            ovsrec_neighbor_set_address_family(nbr, IPV6_ADDRESS_FAMILY_STRING);
        }
        /* Set MAC */
        ovsrec_neighbor_set_mac(nbr, dstmac);
        /* Set Interface */
        ovsrec_neighbor_set_interface(nbr, ifname);

        status = ovsdb_idl_txn_commit_block(txn);
        VLOG_DBG("Neighbor add: txn status = %d\n",
                status);
    }
    ovsdb_idl_txn_destroy(txn);
    return 1;
}

int del_neighbor(struct rtattr* rta, struct ndmsg* ndm, int rtlen)
{
    char ifname[IF_NAMESIZE];

    if(ndm->ndm_family != AF_INET && ndm->ndm_family != AF_INET6)
        return -1;

    if_indextoname(ndm->ndm_ifindex, ifname);

    while (1) {
        if (rta->rta_type == NDA_DST) {
            if(strcmp(ifname, LOOPBACK_INTERFACE_NAME)) {
                char destip[INET6_ADDRSTRLEN];
                char dstmac[18];
                const struct ovsrec_neighbor *nbr;
                struct ovsdb_idl_txn *txn;
                bool found = false;

                memset(destip, 0, sizeof(destip));

                if(ndm->ndm_family == AF_INET) {
                    inet_ntop(AF_INET, RTA_DATA(rta), destip, INET_ADDRSTRLEN);
                } else if(ndm->ndm_family == AF_INET6)   {
                    inet_ntop(AF_INET6, RTA_DATA(rta), destip, INET6_ADDRSTRLEN);
                }

                txn = ovsdb_idl_txn_create(idl);
                OVSREC_NEIGHBOR_FOR_EACH (nbr, idl) {
                    if(!strcmp(nbr->network_address, destip)) {
                        found = true;
                        break;
                    }
                }

                if(found) {
                    enum ovsdb_idl_txn_status status;
                    ovsrec_neighbor_delete(nbr);
                    status = ovsdb_idl_txn_commit_block(txn);
                    VLOG_INFO("Neighbor delete: %s, txn status = %d\n",
                            destip, status);
                } else {
                    VLOG_ERR("Unable to find neighbor entry for %s. Cannot delete.", destip);
                }

                ovsdb_idl_txn_destroy(txn);
            }
        }
        rta = RTA_NEXT(rta, rtlen);
        if (RTA_OK(rta, rtlen) != 1)
        {
            break;
        }

    }
}

int receive_neighbor_update(int sock)
{
    int multipart_msg_end = 0;
    while (!multipart_msg_end) {
        struct sockaddr_nl nladdr;
        struct msghdr msg;
        struct iovec iov[2];
        struct nlmsghdr nlh;
        char buffer[RECV_BUFFER_SIZE];
        int ret;
        int i;
        struct ndmsg* ndm;
        struct rtattr* rta;
        int rtlen;

        iov[0].iov_base = (void *)&nlh;
        iov[0].iov_len = sizeof(nlh);
        iov[1].iov_base = (void *)buffer;
        iov[1].iov_len = sizeof(buffer);
        msg.msg_name = (void *)&(nladdr);
        msg.msg_namelen = sizeof(nladdr);
        msg.msg_iov = iov;
        msg.msg_iovlen = sizeof(iov)/sizeof(iov[0]);

        ret = recvmsg(sock, &msg, MSG_DONTWAIT);
        if (ret < 0){
            return ret;
        }

        ndm = (struct ndmsg*) buffer;
        rta = (struct rtattr *) RTM_RTA(ndm);
        rtlen = RTM_PAYLOAD(&nlh);

        switch(nlh.nlmsg_type) {

        case RTM_NEWNEIGH:
            VLOG_DBG("===================");
            VLOG_DBG("Type: New Neighbour");
            VLOG_DBG("===================");
            add_neighbor(rta, ndm, rtlen);
            break;

        case RTM_DELNEIGH:
            VLOG_DBG("======================");
            VLOG_DBG("Type: Delete Neighbour");
            VLOG_DBG("======================");
            del_neighbor(rta, ndm, rtlen);
            break;

        case NLMSG_DONE:
            VLOG_DBG("End of multipart message\n");
            multipart_msg_end++;
            break;

        default:
            break;
        }

        if (!(nlh.nlmsg_flags & NLM_F_MULTI)) {
            VLOG_DBG("end of message. Not a multipart message\n");
            multipart_msg_end++;
        }
    }
    return 0;
}

/* arpmgrd OVSDB functions*/

/*
 * Return VRF which the Port is part of.
 */
struct ovsrec_vrf * find_port_vrf(const struct ovsrec_open_vswitch *ovs_row,
                                      const char *port_name)
{
    size_t i, j, k;
    for (i = 0; i < ovs_row->n_vrfs; i++)
    {
        struct ovsrec_vrf *vrf_cfg = ovs_row->vrfs[i];
        for (j = 0; j < vrf_cfg->n_ports; j++)
        {
            struct ovsrec_port *port_cfg = vrf_cfg->ports[j];
            if (strcmp(port_name, port_cfg->name) == 0)
            {
                return vrf_cfg;
            }
        }
    }
    return NULL;
}

static inline void arpmgrd_chk_for_system_configured(void)
{
    const struct ovsrec_open_vswitch *ovs_vsw = NULL;

    if (system_configured) {
        /* Nothing to do if we're already configured. */
        return;
    }

    ovs_vsw = ovsrec_open_vswitch_first(idl);

    if (ovs_vsw && (ovs_vsw->cur_cfg > (int64_t) 0)) {
        system_configured = true;
        VLOG_INFO("System is now configured (cur_cfg=%d).",
                (int)ovs_vsw->cur_cfg);
    }

} /* lldpd_chk_for_system_configured */

static void
arpmgrd_init(const char *remote)
{
    idl = ovsdb_idl_create(remote, &ovsrec_idl_class, false, true);
    idl_seqno = ovsdb_idl_get_seqno(idl);
    ovsdb_idl_set_lock(idl, "halon_arpmgrd");
    ovsdb_idl_verify_write_only(idl);

    ovsdb_idl_add_table(idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(idl, &ovsrec_open_vswitch_col_cur_cfg);
    ovsdb_idl_add_column(idl, &ovsrec_open_vswitch_col_vrfs);

    ovsdb_idl_add_table(idl, &ovsrec_table_neighbor);
    ovsdb_idl_add_column(idl, &ovsrec_neighbor_col_vrf);
    ovsdb_idl_omit_alert(idl, &ovsrec_neighbor_col_vrf);
    ovsdb_idl_add_column(idl, &ovsrec_neighbor_col_network_address);
    ovsdb_idl_omit_alert(idl, &ovsrec_neighbor_col_network_address);
    ovsdb_idl_add_column(idl, &ovsrec_neighbor_col_address_family);
    ovsdb_idl_omit_alert(idl, &ovsrec_neighbor_col_address_family);
    ovsdb_idl_add_column(idl, &ovsrec_neighbor_col_mac);
    ovsdb_idl_omit_alert(idl, &ovsrec_neighbor_col_mac);
    ovsdb_idl_add_column(idl, &ovsrec_neighbor_col_interface);
    ovsdb_idl_omit_alert(idl, &ovsrec_neighbor_col_interface);

    ovsdb_idl_add_table(idl, &ovsrec_table_vrf);
    ovsdb_idl_add_column(idl, &ovsrec_vrf_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_vrf_col_ports);

    ovsdb_idl_add_table(idl, &ovsrec_table_port);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_name);

    unixctl_command_register("arpmgrd/dump", "", 0, 0,
            arpmgrd_unixctl_dump, NULL);

    nl_neighbor_sock = 0;
}

static void
arpmgrd_exit(void)
{
    close_netlink_socket(nl_neighbor_sock);
    ovsdb_idl_destroy(idl);
}

static void
arpmgrd_run__(void)
{
    /* Receive Neighbor updates over netlink */
    if(nl_neighbor_sock > 0) {
        receive_neighbor_update(nl_neighbor_sock);
    }
}

static void
arpmgrd_reconfigure(struct ovsdb_idl *idl)
{
    // Probably nothing to reconfigure here for now
}

static void
arpmgrd_run(void)
{
    ovsdb_idl_run(idl);

    if (ovsdb_idl_is_lock_contended(idl)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

        VLOG_ERR_RL(&rl, "another halon-arpmgrd process is running, "
                "disabling this process until it goes away");

        return;
    } else if (!ovsdb_idl_has_lock(idl)) {
        return;
    }

    arpmgrd_chk_for_system_configured();
    if (system_configured) {
        arpmgrd_reconfigure(idl);
        arpmgrd_run__();
        daemonize_complete();
        vlog_enable_async();
        VLOG_INFO_ONCE("%s (Halon arpmgrd) %s", program_name, VERSION);
        if(!nl_neighbor_sock)
            nl_neighbor_sock = netlink_socket_open(NETLINK_ROUTE, RTMGRP_NEIGH);
    }
}

static void
neighbor_netlink_recv_wait__()
{
    if(nl_neighbor_sock > 0 && system_configured)
        poll_fd_wait(nl_neighbor_sock , POLLIN);
}
static void
arpmgrd_wait(void)
{
    ovsdb_idl_wait(idl);
    neighbor_netlink_recv_wait__();
    poll_timer_wait(arpmgr_POLL_INTERVAL * 1000);
}

static void
arpmgrd_unixctl_dump(struct unixctl_conn *conn, int argc OVS_UNUSED,
        const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    unixctl_command_reply_error(conn, "Nothing to dump :)");
}

int
main(int argc, char *argv[])
{
    char *unixctl_path = NULL;
    struct unixctl_server *unixctl;
    char *remote;
    bool exiting;
    int retval;

    set_program_name(argv[0]);
    proctitle_init(argc, argv);
    remote = parse_options(argc, argv, &unixctl_path);
    fatal_ignore_sigpipe();

    ovsrec_init();

    daemonize_start();

    retval = unixctl_server_create(unixctl_path, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 0, halon_arpmgrd_exit, &exiting);

    arpmgrd_init(remote);
    free(remote);

    exiting = false;
    while (!exiting) {
        arpmgrd_run();
        unixctl_server_run(unixctl);

        arpmgrd_wait();
        unixctl_server_wait(unixctl);
        if (exiting) {
            poll_immediate_wake();
        }
        poll_block();
    }
    arpmgrd_exit();
    unixctl_server_destroy(unixctl);

    return 0;
}

static char *
parse_options(int argc, char *argv[], char **unixctl_pathp)
{
    enum {
        OPT_UNIXCTL = UCHAR_MAX + 1,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS,
    };

    static const struct option long_options[] = {
            {"help",        no_argument, NULL, 'h'},
            {"version",     no_argument, NULL, 'V'},
            {"unixctl",     required_argument, NULL, OPT_UNIXCTL},
            DAEMON_LONG_OPTIONS,
            VLOG_LONG_OPTIONS,
            {NULL, 0, NULL, 0},
    };

    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);

        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case 'V':
            ovs_print_version(OFP10_VERSION, OFP10_VERSION);
            exit(EXIT_SUCCESS);

        case OPT_UNIXCTL:
            *unixctl_pathp = optarg;
            break;

            VLOG_OPTION_HANDLERS
            DAEMON_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    switch (argc) {
    case 0:
        return xasprintf("unix:%s/db.sock", ovs_rundir());

    case 1:
        return xstrdup(argv[0]);

    default:
        VLOG_FATAL("at most one non-option argument accepted; "
                "use --help for usage");
    }
}

static void
usage(void)
{
    printf("%s: Halon arpmgrd daemon\n"
            "usage: %s [OPTIONS] [DATABASE]\n"
            "where DATABASE is a socket on which ovsdb-server is listening\n"
            "      (default: \"unix:%s/db.sock\").\n",
            program_name, program_name, ovs_rundir());
    stream_usage("DATABASE", true, false, true);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
            "  --unixctl=SOCKET        override default control socket name\n"
            "  -h, --help              display this help message\n"
            "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}

static void
halon_arpmgrd_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
        const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);
}
