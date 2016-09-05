/*
 * (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP.
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
#define _GNU_SOURCE
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <net/if.h>
#include <sched.h>

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
#include "fatal-signal.h"
#include "stream.h"
#include "dynamic-string.h"
#include "arpmgrd.h"
#include "ops-utils.h"

VLOG_DEFINE_THIS_MODULE(arpmgrd);
COVERAGE_DEFINE(arpmgr);

#define MAX_NH_PING_CNT 5
static struct ovsdb_idl *idl;
static unsigned int idl_seqno;
static unixctl_cb_func arpmgrd_unixctl_debug_cnt;
static int system_configured = false;
static unixctl_cb_func arpmgrd_exit_cb;
static char *parse_options(int argc, char *argv[], char **unixctl_path);
OVS_NO_RETURN static void usage(void);
static struct ovsdb_idl_txn *txn = NULL;
static enum ovsdb_idl_txn_status txn_status = TXN_SUCCESS;
static bool ovsdb_commit_required = false;
static bool reinstal_nh_port_up = false;
static bool reinstal_nh = false;
static int port_data_alloc = 0;
static int nbr_alloc_cnt=0;
static int ovsrec_neighbor_alloc_cnt = 0;
static int idl_nbr_force_ins_cnt,ovs_idl_nbr_cnt, idl_nbr_force_del_cnt;
static int nl_dump_res_size;
static int nl_dump_req_cnt, nl_dump_res_nof_multi_cnt, nl_dump_res_cnt, nl_probe_req_cnt, ovsdb_tr_trigger_cnt;
static int all_neighbors_len;
typedef enum sync {
    SYNC_NONE,
    SYNC_REQUESTED,
    SYNC_IN_PROGRESS,
    SYNC_COMPLETE,
    SYNC_FAILED,
} sync_state_e;

typedef enum sync_mode {
    SYNC_WITH_CACHE_RESET,
    SYNC_WITHOUT_CACHE_RESET,
} sync_mode_e;

static sync_mode_e sync_mode = SYNC_WITHOUT_CACHE_RESET;
static sync_state_e sync_state = SYNC_REQUESTED;
static int gbl_nl_pkt_process_cnt_per_iter = 100;
static bool dbg_stop_nh_probe = 0;
/*This change is to for testing only. stop reprobing nh_entry when it goes to stale.
*/
/* Netlink */
struct nl_req {
    struct nlmsghdr     nlh;
    struct ndmsg        ndm;
    char            buf[256];
};

struct vrf {
    char *name;                 /* User-specified arbitrary name. */
    const struct ovsrec_vrf *cfg;
    /* VRF ports. */
    struct shash ports;          /* "struct port"s indexed by name. */
    int nl_sock;
    int64_t table_id;
};

static int nl_neighbor_sock;
static void netlink_request_neighbor_dump(int sock);


#define NDA_RTA(r) \
    ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#define NDA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ndmsg))
#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

/* OVSDB Util */
const struct ovsrec_port * find_port(const char *port_name);
const struct ovsrec_vrf * find_port_vrf(const char *port_name);
static struct vrf *find_port_vrf_in_cache(const char *port_name);

struct nh_reinstall_port_up {
    char name[IF_NAMESIZE];
    bool ipv4;
};
/* Port cache structure */
struct port_data {
    const struct ovsrec_port *port;
    struct nh_reinstall_port_up port_up_reinstal;
    char ipv4_address[INET_ADDRSTRLEN];
    char admin[32];
};

/* Mapping of all ports */
static struct shash all_ports = SHASH_INITIALIZER(&all_ports);
#define ARP_STATE_LEN 32

/* Mapping of all vrfs */
static struct shash all_vrfs = SHASH_INITIALIZER(&all_vrfs);

/* Neighbor cache structure */
struct neighbor_data {
    const struct vrf *vrf;       /* pointer to vrf */
    const struct ovsrec_port *port;     /* pointer to port */
    const struct ovsrec_neighbor *nbr;  /* pointer to nbr */
    char ip_address[INET6_ADDRSTRLEN];  /* Always nonnull. */
    char network_family[5];             /* 'ipv4' or 'ipv6' */
    char mac[MAC_ADDRSTRLEN];           /* Resolved Mac address */
    char state[ARP_STATE_LEN];          /* ARP state */
    char device[IF_NAMESIZE];           /* device */
    int  ifindex;                       /* if index of device in kernel */
    bool dp_hit;                        /* dp_hit value */
    bool nbr_unresolved;   /* the neighbor entry is a next hop */
    bool routes_nh;
    unsigned int ping_retry_cnt;         /* retry ping cnt for routes_nh */
    unsigned int revalidate_del;         /*to avoid db update for nbr entry referenced by route(s) if kernel deletes it
    */
    char vrf_name[OVSDB_VRF_NAME_MAXLEN];/* VRF name */
};
/* Mapping of all the neighbors. */
static struct shash all_neighbors = SHASH_INITIALIZER(&all_neighbors);
#define VRF_IP_KEY_MAX_LEN \
    (OVSDB_VRF_NAME_MAXLEN + INET6_ADDRSTRLEN + 2) /* includes delimiter */

/* Build hash key for a given vrf name and ip address */
static int
get_hash_key(char* vrf_name, char *ip, char *key)
{
    snprintf(key, VRF_IP_KEY_MAX_LEN, "%s-%s", vrf_name, ip);
    return strlen(key);
} /* get_hash_key */

/* Neighbor cache functions */
/*
 * Add a neighbor entry in cache keyed on
 * vrf name and ip address
 * If it exists already return existing entry
 * */
static struct neighbor_data*
add_neighbor_to_cache(char *vrf, char *ip_address)
{
    struct neighbor_data *new_nbr = NULL;
    VLOG_DBG("Neighbor update from kernel. %s being added\n", ip_address);
    if (ip_address && vrf) {
        struct shash_node *sh_node;
        char key[VRF_IP_KEY_MAX_LEN];

        if (!get_hash_key(vrf, ip_address, key)) {
            return new_nbr;
        }

        sh_node = shash_find(&all_neighbors, key);

        if (!sh_node) {
            /* Allocate structure to save state information for this interface. */
            new_nbr = (struct neighbor_data *) xcalloc(1, sizeof *new_nbr);
            nbr_alloc_cnt++;
            if (!shash_add(&all_neighbors, key, new_nbr)) {
                free(new_nbr);
                nbr_alloc_cnt--;
                new_nbr = NULL;
                VLOG_WARN("vrf %s Neighbor %s : Unable to add neighbor", vrf, ip_address);
            }
        } else {
            VLOG_WARN("vrf %s Neighbor %s specified twice", vrf, ip_address);
            new_nbr = sh_node->data;
        }
    }
    return new_nbr;
} /* add_neighbor_to_cache */

/* Delete neighbor from local cache */
static void
delete_neighbor_from_cache(char *vrf_name, char *ip_address)
{
    char key[VRF_IP_KEY_MAX_LEN];
    struct shash_node *sh_node;

    if (!get_hash_key(vrf_name, ip_address, key)) {
        VLOG_ERR("Unable to get key for entry");
        return;
    }

    sh_node = shash_find(&all_neighbors, key);

    if (!sh_node) {
        VLOG_ERR("Unable to delete a neighbor %s, vrf %s that has entry "
                "in hash", ip_address, vrf_name);
        return;
    }

    free(sh_node->data);
    nbr_alloc_cnt--;
    shash_delete(&all_neighbors, sh_node);
} /* delete_neighbor_from_cache */

/* Find a neighbor in local cache */
static struct neighbor_data*
find_neighbor_in_cache(char *vrf_name, char *ip_address)
{
    char key[VRF_IP_KEY_MAX_LEN];
    struct shash_node *sh_node;
    struct neighbor_data *nbr = NULL;

    if (!get_hash_key(vrf_name, ip_address, key)) {
        VLOG_ERR("Unable to get key for entry");
        return nbr;
    }

    sh_node = shash_find(&all_neighbors, key);

    if (!sh_node) {
        VLOG_DBG("Unable to find a neighbor %s, vrf %s that has entry "
                "in hash", ip_address, vrf_name);
        return nbr;
    }

    nbr = sh_node->data;
    return nbr;
} /* find_neighbor_in_cache */

/* Netlink functions */

/*
 * Open a netlink socket registering for group
 * by entering corresponding namespace.
 * Send a neighbor dump request on socket
 * for both the namespace.
 * */
static void
netlink_socket_open(const char *vrf_name, int *sock, int protocol, int group)
{
    struct sockaddr_nl s_addr;
    struct vrf_sock_params vrf_params;

    if (*sock > 0)
        return;

    vrf_params.nl_params.family = AF_NETLINK;
    vrf_params.nl_params.type = SOCK_RAW;
    vrf_params.nl_params.protocol = protocol;

    *sock = vrf_create_socket((char *)vrf_name, &vrf_params);

    if (*sock < 0) {
        VLOG_ERR("Netlink socket creation failed (%s)",strerror(errno));
        goto label;
    }
    uint32_t rxbufsize = 2097152; // 2 Mb
    int err = setsockopt(*sock, SOL_SOCKET, SO_RCVBUFFORCE,&rxbufsize, sizeof(rxbufsize));
    if(err){
        VLOG_ERR("setsockopt: SO_RCVBUFFORCE err %d",errno);
        close(*sock);
        return;
    }
    memset((void *) &s_addr, 0, sizeof(s_addr));
    s_addr.nl_family = AF_NETLINK;
    s_addr.nl_pid = getpid();
    s_addr.nl_groups = group;
    if (bind(*sock, (struct sockaddr *) &s_addr, sizeof(s_addr)) < 0) {
      if (errno != EADDRINUSE) {
        VLOG_ERR("netlink socket bind failed (%s)", strerror(errno));
        goto label;
      }
    }

    netlink_request_neighbor_dump(*sock);
    if(sync_state == SYNC_REQUESTED)
       sync_state = SYNC_IN_PROGRESS;

label:
    return;
} /* netlink_socket_open */

/* close the netlink socket */
static void
close_netlink_socket(int socket)
{
    close(socket);
} /* close_netlink_socket */

/* Function to Send netlink message requesting Neighbor dump */
static void
netlink_request_neighbor_dump(int sock)
{
    struct rtattr *rta;
    struct nl_req req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

    req.nlh.nlmsg_type = RTM_GETNEIGH;
    req.ndm.ndm_family = AF_UNSPEC;
    req.nlh.nlmsg_pid = 0;

    rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_len = RTA_LENGTH(4);

    if (send(sock, &req, req.nlh.nlmsg_len, 0) == -1) {
        VLOG_ERR("Failed to send netlink request for neighbor dump");
        return;
    }
    nl_dump_req_cnt++;
    return;
} /* netlink_request_neighbor_dump */

/*
 * Function to set state of a Neighbor to Delay
 * and kernel will trigger a probe
 */
static void
send_neighbor_probe(int sock, int ifindex, int family, void* ip, int plen)
{
    int len = RTA_LENGTH(plen);
    struct rtattr *rta;
    struct nl_req req;

    memset(&req, 0, sizeof(req));

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE;
    req.nlh.nlmsg_type = RTM_NEWNEIGH;
    req.ndm.ndm_family = AF_UNSPEC;
    req.ndm.ndm_state = NUD_DELAY;
    req.ndm.ndm_family = family;
    req.ndm.ndm_ifindex = ifindex;

    if (NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_ALIGN(len) > sizeof(req)) {
        VLOG_ERR("Message length exceeded sizeof request");
        return;
    }

    rta = NLMSG_TAIL(&req.nlh);
    rta->rta_type = NDA_DST;
    rta->rta_len = len;
    memcpy(RTA_DATA(rta), ip, plen);
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_ALIGN(len);

    if (send(sock, &req, req.nlh.nlmsg_len, MSG_DONTWAIT) == -1) {
        VLOG_ERR("Failed to send netlink request for neighbor probe");
        return;
    }
    nl_probe_req_cnt++;
    return;
} /* send_neighbor_probe */

/* Functions for parsing nlmsg, populating cache and updating OVSDB */

/* Update/Insert ovsdb row from cache entry */
static int
update_neighbor_to_ovsdb(struct neighbor_data *cache_nbr,
                         bool insert_row_without_checking)
{
    const struct ovsrec_neighbor *ovs_nbr;
    bool found = false;
    /* Some of the fields are not yet populated for the externally generated neighbor. Lets do them here*/
    if(cache_nbr->nbr_unresolved){
        cache_nbr->nbr_unresolved = false;
        ovs_nbr = cache_nbr->nbr;
        ovsrec_neighbor_set_address_family(ovs_nbr, cache_nbr->network_family);
        ovsrec_neighbor_set_port(ovs_nbr, cache_nbr->port);
        /* I assumeexternal module may not know proper mac, so lets' add it */
        if(cache_nbr->mac)
            ovsrec_neighbor_set_mac(ovs_nbr, cache_nbr->mac);
        /* The state information may have created but might be updated by kernel */
        if(cache_nbr->state) {
            ovsrec_neighbor_set_state(ovs_nbr, cache_nbr->state);
        }
        ovsdb_commit_required = true;
        return 1;
    }
    if (!insert_row_without_checking) {
        /*
         * Check of cache entry has pointer to ovsrec, else search in idl
         * and if row is found update in row pointer to cache entry for
         * subsequent use
         * */
        if (cache_nbr->nbr) {
            ovs_nbr = cache_nbr->nbr;
            found = true;
        } else {
            OVSREC_NEIGHBOR_FOR_EACH (ovs_nbr, idl) {
                if (!strcmp((ovs_nbr)->ip_address, cache_nbr->ip_address) &&
                        ovs_nbr->vrf == cache_nbr->vrf->cfg) {
                    /* Update cache with pointer to ovsrec */
                    cache_nbr->nbr = ovs_nbr;
                    found = true;
                    break;
                }
            }
        }
    }

    /*
     * If ovsrec row is found we will just check if
     * mac, port or state changed
     * and update accordingly,
     * else insert a new row in ovsdb.
     */
    if (found) {
        if(!ovs_nbr->mac && cache_nbr->mac) {
            ovsrec_neighbor_set_mac(ovs_nbr, cache_nbr->mac);
            ovsdb_commit_required = true;
        }
        else if (strncmp(ovs_nbr->mac, cache_nbr->mac, MAC_ADDRSTRLEN)) {
            ovsrec_neighbor_set_mac(ovs_nbr, cache_nbr->mac);
            ovsdb_commit_required = true;
        }
        if(!ovs_nbr->port && cache_nbr->port) {
            ovsrec_neighbor_set_port(ovs_nbr, cache_nbr->port);
            ovsdb_commit_required = true;
        }
        else if (ovs_nbr->port != cache_nbr->port) {
            ovsrec_neighbor_set_port(ovs_nbr, cache_nbr->port);
            ovsdb_commit_required = true;
        }
        if(!ovs_nbr->state && cache_nbr->state) {
            ovsrec_neighbor_set_state(ovs_nbr, cache_nbr->state);
            ovsdb_commit_required = true;
        }
        else if (strncmp(ovs_nbr->state, cache_nbr->state,ARP_STATE_LEN)) {
            ovsrec_neighbor_set_state(ovs_nbr, cache_nbr->state);
            ovsdb_commit_required = true;
        }
        if(!ovs_nbr->address_family && cache_nbr->network_family) {
            ovsrec_neighbor_set_address_family(ovs_nbr, cache_nbr->network_family);
        }
    } else {
        ovs_nbr = ovsrec_neighbor_insert(txn);
        ovsrec_neighbor_alloc_cnt ++;
        if (ovs_nbr) {
            ovsrec_neighbor_set_ip_address(ovs_nbr, cache_nbr->ip_address);
            ovsrec_neighbor_set_vrf(ovs_nbr, cache_nbr->vrf->cfg);
            ovsrec_neighbor_set_address_family(ovs_nbr, cache_nbr->network_family);
            ovsrec_neighbor_set_port(ovs_nbr, cache_nbr->port);
            ovsrec_neighbor_set_mac(ovs_nbr, cache_nbr->mac);
            ovsrec_neighbor_set_state(ovs_nbr, cache_nbr->state);
            ovsdb_commit_required = true;
        }
    }
    return 1;
} /* update_neighbor_to_ovsdb */

/* Delete a neighbor row from ovsdb */
static void
delete_nbr_from_ovsdb(const struct ovsrec_neighbor *ovs_nbr)
{
    if (ovs_nbr) {
        VLOG_DBG("Deleting neighbor vrf %s ip address %s from Neighbor table",
                ovs_nbr->vrf ? ovs_nbr->vrf->name : "none", ovs_nbr->ip_address);
        ovsrec_neighbor_delete(ovs_nbr);
        ovsrec_neighbor_alloc_cnt --;
        ovsdb_commit_required = true;
    }
} /* delete_nbr_from_ovsdb */

/* Delete ovsdb neighbor row corresponding to a local cache entry */
static void
delete_cache_nbr_from_ovsdb(struct neighbor_data *cache_nbr)
{
    const struct ovsrec_neighbor *ovs_nbr;
    bool found = false;
    /*
     * Check of cache entry has pointer to ovsrec, else search in idl
     * and if row is found update in row pointer to cache entry for
     * subsequent use
     * */
    if (cache_nbr->nbr) {
        ovs_nbr = cache_nbr->nbr;
        found = true;
    } else {
        OVSREC_NEIGHBOR_FOR_EACH (ovs_nbr, idl) {
            if (!strcmp((ovs_nbr)->ip_address, cache_nbr->ip_address) &&
                    ovs_nbr->vrf == cache_nbr->vrf->cfg) {
                /* Update cache with pointer to ovsrec */
                cache_nbr->nbr = ovs_nbr;
                found = true;
                break;
            }
        }
    }
    if (found) {
        delete_nbr_from_ovsdb(ovs_nbr);
    }
} /* delete_cache_nbr_from_ovsdb */

/*
 * Function to resync OVSDB 'Neighbor' table entries
 * with kernel's neighbor entries which are in local
 * local cache (all_neighbors).
 */
static void
resync_db_with_kernel()
{
    struct shash idl_neighbors;
    const struct ovsrec_neighbor *ovs_nbr;
    struct shash_node *sh_node, *sh_next;
    ovs_idl_nbr_cnt = 0;
    all_neighbors_len = 0;
    /* Collect all the interfaces in the dB. */
    shash_init(&idl_neighbors);
    OVSREC_NEIGHBOR_FOR_EACH(ovs_nbr, idl) {
        char key[VRF_IP_KEY_MAX_LEN];
        get_hash_key(ovs_nbr->vrf->name, ovs_nbr->ip_address, key);
        if (!shash_add_once(&idl_neighbors, key, ovs_nbr)) {
            VLOG_WARN("Neighbor vrf name %s ip address %s"
                    "specified twice", ovs_nbr->vrf->name, ovs_nbr->ip_address);
        }
        else{
            ovs_idl_nbr_cnt ++;
        }
    }

    /*
     * Go over neighbors in cache
     * Update neighbor in ovsdb
     * i) insert if new
     * ii) update existing row if ovsdb rec is present
     */
    SHASH_FOR_EACH_SAFE(sh_node, sh_next, &all_neighbors) {
        struct neighbor_data *cache_nbr = sh_node->data;
        struct ovsrec_neighbor *idl_nbr =
                shash_find_data(&idl_neighbors, sh_node->name);

        /*
         * Pointer to port/vrf change in case of ovsdb restart
         * We will update these
         */

        VLOG_DBG("Updating port info for nbr cache dev %s",
                cache_nbr->device);
        cache_nbr->port = find_port(cache_nbr->device);
        cache_nbr->vrf = find_port_vrf_in_cache(cache_nbr->device);

        VLOG_DBG("cache %s mac %s family %s port %s vrf %s", cache_nbr->ip_address,
                cache_nbr->mac, cache_nbr->network_family, cache_nbr->port->name, cache_nbr->vrf->name);

        if (!idl_nbr) {
            /* force insert here */
            update_neighbor_to_ovsdb(cache_nbr, true);
            idl_nbr_force_ins_cnt ++;
        } else {
            cache_nbr->nbr = idl_nbr;
            if(idl_nbr->in_use_by_routes && (*(idl_nbr->in_use_by_routes) == true)) {
                cache_nbr->routes_nh = true;
                VLOG_INFO("routes_nh ip %s restored in cache in resync", cache_nbr->ip_address);
            }
            update_neighbor_to_ovsdb(cache_nbr, false);
        }
        all_neighbors_len ++;
    }

    /*
     * If current sync process of building cache from kernel failed
     * let's not delete rows from OVSDB, since this will be expensive.
     * Probably the rows never got update in our cache.
     * We commit only any modified or new rows to OVSDB
     */
    if (sync_state != SYNC_FAILED) {
        /*
         * Go over neighbors in ovsdb
         * If neighbor is not in cache
         * i) delete ovsdb rec
         */
        SHASH_FOR_EACH_SAFE(sh_node, sh_next, &idl_neighbors) {
            struct neighbor_data *cache_nbr =
                    shash_find_data(&all_neighbors, sh_node->name);
            if (!cache_nbr) {
                /* delete the ovsrec */
                idl_nbr_force_del_cnt ++;
                const struct ovsrec_neighbor *ovs_nbr = sh_node->data;
                delete_nbr_from_ovsdb(ovs_nbr);
            }
        }
    }
    shash_destroy(&idl_neighbors);
    if (sync_state != SYNC_FAILED && sync_state != SYNC_REQUESTED) {
        sync_state = SYNC_COMPLETE;
    }
    VLOG_DBG("%s: Sync state is %d", __func__, sync_state);
} /* resync_db_with_kernel */

/*
 * Parse the ND message attribute and fill cache entry
 * with IP address, family, mac, state, device
 * If entry is a new entry add to cache
 */
static int
update_neighbor_cache(int sock, struct ndmsg* ndm, struct rtattr* rta,
                      const struct vrf *vrf, struct neighbor_data **cache_nbr)
{
    char destip[INET6_ADDRSTRLEN];
    char destmac[MAC_ADDRSTRLEN];
    struct shash_node *sh_node = NULL;
    char buff[UUID_LEN+1] = {0};
    bool dp_hit;
    /* Kernel migh update first seen entry as STALE, externally added entry that are updated as stale need to be
     * probed.so skip_dp_hit for them */
    bool skip_dp_hit = false;

    if (rta->rta_type == NDA_DST) {
        bool found = false;
        char key[VRF_IP_KEY_MAX_LEN];
        char dev[IF_NAMESIZE];

        get_vrf_ns_from_table_id (idl, (int64_t)vrf->table_id, buff);
        nl_if_indextoname(ndm->ndm_ifindex, dev, buff);
        memset(destip, 0, sizeof(destip));

        if (ndm->ndm_family == AF_INET) {
            uint32_t addr = ntohl(*(uint32_t *)RTA_DATA(rta));

            /* Ignore multicast addresses */
            if (IS_IPV4MULTICAST(addr))
            {
                VLOG_INFO("Received multicast addr %s, Ignoring", destip);
                return 0;
            }

            inet_ntop(AF_INET, RTA_DATA(rta), destip, INET_ADDRSTRLEN);
        } else if (ndm->ndm_family == AF_INET6)   {
            inet_ntop(AF_INET6, RTA_DATA(rta), destip, INET6_ADDRSTRLEN);
        }

        get_hash_key(vrf->name, destip, key);
        sh_node = shash_find(&all_neighbors, key);
        if (sh_node) {
            *cache_nbr = sh_node->data;
            if((*cache_nbr)->nbr_unresolved){
                /*ovs_nbr entry already created and some fields alreay created others are filled here */
                if(strcmp((*cache_nbr)->vrf_name, vrf->name)){
                    VLOG_ERR("Configured VRF name %s is not matching with received %s.",
                        (*cache_nbr)->vrf_name, vrf->name);
                }
                (*cache_nbr)->vrf = vrf;
                strcpy((*cache_nbr)->device, dev);
                (*cache_nbr)->ifindex = ndm->ndm_ifindex;
                (*cache_nbr)->port = find_port(dev);
                skip_dp_hit = true;
                found = true;
                goto end_chache_nbr_init;
            }
            /*This entry was triggered for delete, so all the fields are populated for it. Already ping in flight,
            no need to for dp_hit probe.*/
            else if((*cache_nbr)->revalidate_del){
                skip_dp_hit = true;
                goto end_chache_nbr_init;
            }
            else {
                found = true;
            }
        }

        if (!found) {
            VLOG_DBG("Adding new neighbor %s dev %s", destip, dev);

            *cache_nbr = add_neighbor_to_cache(vrf->name, destip);

            if (!(*cache_nbr)) {
                VLOG_ERR("Unable to allocate a new neighbor.");
                return 0;
            }

            strcpy((*cache_nbr)->vrf_name, vrf->name);
            (*cache_nbr)->vrf = vrf;
            (*cache_nbr)->nbr = NULL;
            strcpy((*cache_nbr)->ip_address, destip);
            strcpy((*cache_nbr)->device, dev);
            (*cache_nbr)->ifindex = ndm->ndm_ifindex;
            (*cache_nbr)->port = find_port(dev);
            strcpy((*cache_nbr)->mac, "");
            if (ndm->ndm_family == AF_INET) {
                strcpy((*cache_nbr)->network_family, OVSREC_NEIGHBOR_ADDRESS_FAMILY_IPV4);
            } else if (ndm->ndm_family == AF_INET6)   {
                strcpy((*cache_nbr)->network_family, OVSREC_NEIGHBOR_ADDRESS_FAMILY_IPV6);
            }

            (*cache_nbr)->nbr = NULL;
        }
end_chache_nbr_init:
        switch (ndm->ndm_state) {

        case NUD_REACHABLE:
            strcpy((*cache_nbr)->state, OVSREC_NEIGHBOR_STATE_REACHABLE);
            (*cache_nbr)->ping_retry_cnt = 0;
            /*revalidatation is complete, db can be update after that*/
            (*cache_nbr)->revalidate_del = 0;
            break;

        case NUD_STALE:
            /* Send probe request to STALE neighbor and dp_hit set */
            /* Set dp_hit default to be false */
            dp_hit = false;
            (*cache_nbr)->ping_retry_cnt = 0; // may be after ping from switch host entry cannot be stale.
            (*cache_nbr)->revalidate_del = 0;
            if ((!skip_dp_hit) && ((*cache_nbr)->nbr)) {
                dp_hit = smap_get_bool(&(*cache_nbr)->nbr->status ,
                         OVSDB_NEIGHBOR_STATUS_DP_HIT,
                         OVSDB_NEIGHBOR_STATUS_MAP_DP_HIT_DEFAULT);
            }

            VLOG_DBG("dp hit state = %d ip %s", dp_hit, destip);
            (*cache_nbr)->dp_hit = dp_hit;
            if (sock &&
               (dp_hit ||(!dbg_stop_nh_probe && (*cache_nbr)->routes_nh))) {
                send_neighbor_probe(sock, ndm->ndm_ifindex, ndm->ndm_family,
                    RTA_DATA(rta), RTA_PAYLOAD(rta));
                /*
                 * FIXME: Set state to reachable. Currently we are not receiving
                 * Reachable state from Stale state. (Bug)
)                 * If kernel is unable to resolve, we will get an explicit
                 * notification for FAILED state
                 */
                strcpy((*cache_nbr)->state, OVSREC_NEIGHBOR_STATE_REACHABLE);
            } else
            {
                strcpy((*cache_nbr)->state, OVSREC_NEIGHBOR_STATE_STALE);
            }
            break;

        case NUD_FAILED:
            VLOG_DBG("Neighbor resolution failed %s", destip);
            (*cache_nbr)->revalidate_del = 0;
            /*ping if the nbe is nh. no matter how it land up in this state.*/
            if((*cache_nbr)->routes_nh && ((*cache_nbr)->ping_retry_cnt < MAX_NH_PING_CNT)) {
                VLOG_ERR("pinging again for the in_use_by_route %s, destip = %s", (*cache_nbr)->ip_address, destip);
                 if((*cache_nbr)->network_family){
                     if(0 == strcmp((*cache_nbr)->network_family, OVSREC_NEIGHBOR_ADDRESS_FAMILY_IPV4))
                     {
                        ping4((*cache_nbr)->ip_address);
                     }
                     else if(0 == strcmp((*cache_nbr)->network_family,OVSREC_NEIGHBOR_ADDRESS_FAMILY_IPV6))
                     {
                        ping6((*cache_nbr)->ip_address);
                     }
                    strcpy((*cache_nbr)->state, OVSREC_NEIGHBOR_STATE_INCOMPLETE);
                    strcpy((*cache_nbr)->mac, "");
                    (*cache_nbr)->ping_retry_cnt ++;
                    break;
                }
                else {
                    VLOG_ERR("Address family not valid for in_use_routes entry %s",destip);
                }
            }
            strcpy((*cache_nbr)->state, OVSREC_NEIGHBOR_STATE_FAILED);
            strcpy((*cache_nbr)->mac, "");
            break;

        case NUD_INCOMPLETE:
            VLOG_DBG("Neighbor resolution incomplete %s", destip);
            /* Don't change mac and state for entries that are being revalidated before deleting from DB. */
            if(!(*cache_nbr)->revalidate_del){
                strcpy((*cache_nbr)->state, OVSREC_NEIGHBOR_STATE_INCOMPLETE);
                strcpy((*cache_nbr)->mac, "");
            }
            else {
                VLOG_INFO("nbr %s is routes_nh, revalidating before deleting from DB", destip);
            }
            break;

        case NUD_PERMANENT:
            strcpy((*cache_nbr)->state, OVSREC_NEIGHBOR_STATE_PERMANENT);
            break;

        case NUD_DELAY:
        case NUD_PROBE:
        default:
            (*cache_nbr)->revalidate_del = 0;
            strcpy((*cache_nbr)->state, OVSREC_NEIGHBOR_STATE_REACHABLE);
            break;

        }
    } else if (rta->rta_type == NDA_LLADDR) {
        /* Set MAC */
        if (*cache_nbr) {
            unsigned char *mac = RTA_DATA(rta);
            sprintf(destmac, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0],
                    mac[1], mac[2], mac[3], mac[4],
                    mac[5]);
            strcpy((*cache_nbr)->mac, destmac);
        }
    }
    return 1;
} /* update_neighbor_cache */

/* Delete neighbor from cache and ovsdb */
static int
del_neighbor(struct ndmsg* ndm, struct rtattr* rta,
             const struct vrf *vrf)
{
    const struct ovsrec_neighbor *ovs_nbr;

    if (ndm->ndm_family != AF_INET && ndm->ndm_family != AF_INET6) {
        return -1;
    }

    if (rta->rta_type == NDA_DST) {
            char destip[INET6_ADDRSTRLEN];
            bool found = false;

            memset(destip, 0, sizeof(destip));

            if (ndm->ndm_family == AF_INET) {
                inet_ntop(AF_INET, RTA_DATA(rta), destip, INET_ADDRSTRLEN);
            } else if (ndm->ndm_family == AF_INET6) {
                inet_ntop(AF_INET6, RTA_DATA(rta), destip, INET6_ADDRSTRLEN);
            }
            struct neighbor_data *cache_nbr = find_neighbor_in_cache(vrf->name, destip);
            if(!cache_nbr){
                VLOG_INFO("Unable to delete a neighbor %s, vrf %s that has entry in hash",destip, vrf->name);
                return -1;
            }
            if(cache_nbr->routes_nh && (cache_nbr->ping_retry_cnt< MAX_NH_PING_CNT)) {
                VLOG_INFO("Del notified for %s, but pinging again to keep it refreshed... ",destip);
                if (ndm->ndm_family == AF_INET) {
                    ping4(destip);
                }
                else if(ndm->ndm_family == AF_INET6) {
                    ping6(destip);
                }
                cache_nbr->revalidate_del = true;
                strcpy(cache_nbr->state, OVSREC_NEIGHBOR_STATE_INCOMPLETE);
                cache_nbr->ping_retry_cnt++;
                return 1;
            }

            OVSREC_NEIGHBOR_FOR_EACH (ovs_nbr, idl) {
                if (!strcmp((ovs_nbr)->ip_address, destip) && ovs_nbr->vrf == vrf->cfg) {
                    found = true;
                    break;
                }
            }

            if(found) {
                delete_nbr_from_ovsdb(ovs_nbr);
                VLOG_DBG("Neighbor delete: %s\n",
                       destip);
            } else {
                VLOG_ERR("Unable to find neighbor entry for %s in vrf %s. Cannot delete.", destip, vrf->name);
            }

            delete_neighbor_from_cache(vrf->name, destip);
    }
    return 1;
} /* del_neighbor */

/* Parse Netlink message */
static int
parse_nlmsg(struct vrf *vrf, int sock, struct nlmsghdr *nlh, int msglen)
{
    struct rtattr *rta;
    struct ndmsg *ndm;
    char  buff[UUID_LEN+1] = {0};
    int rtalen;

    while (NLMSG_OK(nlh, msglen)) {
        ndm = (struct ndmsg *) NLMSG_DATA(nlh);
        rta = (struct rtattr *)NDA_RTA(ndm);

        rtalen = NDA_PAYLOAD(nlh);
        if (!(ndm->ndm_state & NUD_NOARP)) {
            struct neighbor_data *cache_nbr = NULL;
            char ifname[IF_NAMESIZE];

            if (ndm->ndm_family != AF_INET && ndm->ndm_family != AF_INET6) {
                goto ndm_done;
            }

             get_vrf_ns_from_table_id (idl, (int64_t)vrf->table_id, buff);

            if (nl_if_indextoname(ndm->ndm_ifindex, ifname, buff) != 0)
              {
                VLOG_ERR("Failed to get ifname");
                return -1;
              }

            /* Ignore updates on "lo" interface */
            if(!strcmp(ifname, LOOPBACK_INTERFACE_NAME)) {
                goto ndm_done;
            }


            /*
             * State, ifindex, family is populated from 'ndm'
             * Go through each of the Attributes in NDM and populate
             * neighbor cache for IP addr and Mac address.
             * We will extract info from NDA_DST (ip address),
             * and NDA_LLADDR (MAC address) attributes.
             *
             */
            for (; RTA_OK(rta, rtalen); rta = RTA_NEXT(rta, rtalen)) {
                if (nlh->nlmsg_type == RTM_NEWNEIGH) {
                    update_neighbor_cache(sock, ndm, rta, vrf, &cache_nbr);
                } else if (nlh->nlmsg_type == RTM_DELNEIGH) {
                    /* delete cache and ovsdb */
                    del_neighbor(ndm, rta, vrf);
                }
            }

            /*
             * If a new neighbor was added/modified, lets update OVSDB
             * */
            if (cache_nbr &&
                !(cache_nbr->revalidate_del)) {
                update_neighbor_to_ovsdb(cache_nbr, false);
            }
        }

ndm_done:
        nlh = NLMSG_NEXT(nlh, msglen);
    }
    return 1;
} /* parse_nlmsg */

/* Receive message on netlink socket */
static int
receive_neighbor_update(struct vrf *vrf, int sock)
{
    int pkt_cnt = 0;
    int lcl_nl_dump_res_size = 0;
    int multipart_msg_end = 0;
    while (pkt_cnt < gbl_nl_pkt_process_cnt_per_iter){
        lcl_nl_dump_res_size = 0;
        while (!multipart_msg_end) {
            struct sockaddr_nl nladdr;
            struct msghdr msg;
            struct iovec iov;
            struct nlmsghdr *nlh;
            char buffer[RECV_BUFFER_SIZE];
            int ret;

            iov.iov_base = (void *)buffer;
            iov.iov_len = sizeof(buffer);
            msg.msg_name = (void *)&(nladdr);
            msg.msg_namelen = sizeof(nladdr);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;

            if(sync_mode == SYNC_WITH_CACHE_RESET) {
                ret = recvmsg(sock, &msg, 0);
            } else {
                ret = recvmsg(sock, &msg, MSG_DONTWAIT);
            }
            VLOG_DBG("recvmsg returned %d, nbr_alloc_cnt %d, port_data_alloc %d,",
                ret,nbr_alloc_cnt, port_data_alloc);

            if (ret < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    VLOG_ERR("err = %s ,sync_state %d, nbr_alloc_cnt %d, port_data_alloc %d, \n \
    ovsrec_neighbor_alloc_cnt %d, force_ins_cnt %d force_del_cnt %d, ovs_idl_nbr_cnt %d,all_neighbors_len %d \n",
                    strerror(errno),sync_state,nbr_alloc_cnt,
                    port_data_alloc,ovsrec_neighbor_alloc_cnt,
                    idl_nbr_force_ins_cnt,idl_nbr_force_del_cnt,ovs_idl_nbr_cnt,
                    all_neighbors_len);
                    VLOG_ERR("nl_dump_req_cnt %d, nl_dump_res_cnt %d, not_multi_part_dump_res_cnt %d \n\
    nl_probe_req_cnt %d, nl_dump_res_size %d, ovsdb_tr_trigger_cnt %d",
    nl_dump_req_cnt,nl_dump_res_cnt, nl_dump_res_nof_multi_cnt,
    nl_probe_req_cnt, nl_dump_res_size,
    ovsdb_tr_trigger_cnt);
                    /* Kernel messages could be overwhelming,
                       suspend receive temporarily */
                    if(sync_state == SYNC_NONE) {
                        sync_mode = SYNC_WITH_CACHE_RESET;
                        sync_state = SYNC_REQUESTED;
                    }
                    else {
                        sync_state = SYNC_FAILED;
                    }
                }
                return ret;
            }
            lcl_nl_dump_res_size += ret;
            nlh = (struct nlmsghdr*) buffer;

            switch (nlh->nlmsg_type) {

            case RTM_NEWNEIGH:
            case RTM_DELNEIGH:
                parse_nlmsg(vrf, sock, nlh, ret);
                break;

            case NLMSG_DONE:
                VLOG_DBG("End of multipart message\n");
                multipart_msg_end++;
                nl_dump_res_cnt++;
                break;

            default:
                VLOG_ERR("received nl msg_type %u", nlh->nlmsg_type);
                break;
            }

            if (!(nlh->nlmsg_flags & NLM_F_MULTI)) {
                VLOG_DBG("end of message. Not a multipart message\n");
                nl_dump_res_nof_multi_cnt++;
                break;
            }
        }
        nl_dump_res_size = (nl_dump_res_size > lcl_nl_dump_res_size)? nl_dump_res_size : lcl_nl_dump_res_size;
        pkt_cnt ++;
    }
    return 0;
} /* receive_neighbor_update */

/* OVSDB Utils */

/*
 * Return Port from port name.
 */
const struct ovsrec_port
*find_port(const char *port_name)
{
    const struct ovsrec_port *ovs_port;
    OVSREC_PORT_FOR_EACH (ovs_port, idl) {
        if (strcmp(ovs_port->name, port_name) == 0) {
            return ovs_port;
        }
    }
    return NULL;
} /* find_port */

/*
 * Return VRF which the Port is part in local DB.
 */
static struct vrf
*find_port_vrf_in_cache(const char *port_name)
{
  struct shash_node *vrf_node = NULL;
  struct shash_node *port_node = NULL;

  SHASH_FOR_EACH(vrf_node, &all_vrfs) {
       struct vrf *vrf = vrf_node->data;
       SHASH_FOR_EACH(port_node,
                             &vrf->ports) {
        if (!strcmp(port_node->name, port_name)) {
            return vrf;
        }
     }
  }

   return NULL;
} /* find_port_vrf_in_cache */

/*
 * Return VRF which the Port is part of.
 */
const struct ovsrec_vrf
*find_port_vrf(const char *port_name)
{
    struct vrf *vrf = find_port_vrf_in_cache(port_name);
    if (vrf)
    {
        return vrf->cfg;
    }
    return NULL;
} /* find_port_vrf */

/**
 * Identify which 'vrf' a 'port' belongs to and return
 * the corresponding vrf or NULL if not found
 */
static struct vrf*
arpmgrd_vrf_lookup(const char *uuid)
{
    struct shash_node *node = NULL;

    SHASH_FOR_EACH(node, &all_vrfs) {
        struct vrf *vrf = node->data;
        if (!strcmp(node->name, uuid)) {
            return vrf;
        }
    }
    return NULL;
}


/* delete vrf from cache */
static void
arpmgrd_vrf_del(struct shash_node *sh_node)
{
    if (sh_node) {
        struct vrf *vrf = sh_node->data;
        if (vrf) {
            /* Delete all the associated ports before destroying vrf */

            VLOG_DBG("Deleting vrf '%s'",vrf->name);

            shash_delete(&all_vrfs, sh_node);
            shash_destroy(&vrf->ports);
            close(vrf->nl_sock);
            free(vrf->name);
            free(vrf);
        }
    }
}

/*add vrf into port */
static void
arpmgrd_vrf_add_ports(struct vrf *vrf, const struct ovsrec_vrf *vrf_row)
{
    int i;

    shash_destroy(&vrf->ports);
    shash_init(&vrf->ports);
    for (i = 0; i < vrf_row->n_ports; i++) {
        const char *name = vrf_row->ports[i]->name;
        shash_add_once(&vrf->ports, name, vrf_row->ports[i]);
        VLOG_DBG("Added port '%s' in vrf '%s'", vrf_row->ports[i]->name,
                                                vrf_row->name);
    }
}
/* add vrf into cache */
static void
arpmgrd_vrf_add(const struct ovsrec_vrf *vrf_row)
{
    char buff[UUID_LEN+1]={0};
    struct vrf *vrf;
    snprintf(buff, UUID_LEN+1, UUID_FMT, UUID_ARGS(&(vrf_row->header_.uuid)));
    ovs_assert(!arpmgrd_vrf_lookup((const char*)buff));
    vrf = xzalloc(sizeof *vrf);

    vrf->name = xstrdup(vrf_row->name);
    vrf->cfg = vrf_row;
    if (strcmp(vrf->name, DEFAULT_VRF_NAME) != 0)
    {
        /* non default vrf. We need to open socket by entering corresponding
          namespace Open FD to set the thread to a namespace */
        vrf->table_id = *vrf->cfg->table_id;
        get_vrf_ns_from_table_id (idl, (int64_t)vrf->table_id, buff);
        netlink_socket_open((const char*)buff, &(vrf->nl_sock),
                             NETLINK_ROUTE, RTMGRP_NEIGH);
    }
    else
    {
        vrf->nl_sock = nl_neighbor_sock;
        vrf->table_id = 0;
    }

    shash_init(&vrf->ports);
    shash_add_once(&all_vrfs, (const char*)buff, vrf);

    VLOG_DBG("Added vrf '%s'", vrf_row->name);
     arpmgrd_vrf_add_ports(vrf, vrf_row);
}

/*add or delete the VRF from the DB*/
static void
arpmgrd_add_del_vrf(struct ovsdb_idl *idl)
{
    struct vrf *vrf;
    struct shash new_vrfs;
    struct shash_node *node, *next;
    const struct ovsrec_vrf *first_vrf_row,*vrf_row = NULL;
    char buff[UUID_LEN+1]={0};

    first_vrf_row = ovsrec_vrf_first(idl);

    if (!first_vrf_row) {
        return;
    }

    /*
     * Check if any vrf rows were added or deleted.
     * If no change just return from here
     */
    if (!OVSREC_IDL_ANY_TABLE_ROWS_INSERTED(first_vrf_row, idl_seqno) &&
        !OVSREC_IDL_ANY_TABLE_ROWS_MODIFIED(first_vrf_row, idl_seqno) &&
        !OVSREC_IDL_ANY_TABLE_ROWS_DELETED(first_vrf_row, idl_seqno)) {
        VLOG_DBG("No rows in table modified.");
        return;
    }


    /* Collect new vrfs' names and types. */
    shash_init(&new_vrfs);
    OVSREC_VRF_FOR_EACH (vrf_row, idl) {
        snprintf(buff, UUID_LEN+1, UUID_FMT,
                 UUID_ARGS(&(vrf_row->header_.uuid)));
        shash_add_once(&new_vrfs, (const char *)buff, vrf_row);
    }

    /* Delete the vrfs' that are deleted from the db */
    SHASH_FOR_EACH_SAFE (node, next, &all_vrfs) {
        vrf = shash_find_data(&all_vrfs, node->name);
        vrf->cfg = shash_find_data(&new_vrfs, node->name);
        if (!vrf->cfg) {
            arpmgrd_vrf_del(node);
        }
    }

    /* Add new vrfs. */
    OVSREC_VRF_FOR_EACH (vrf_row, idl) {
         snprintf(buff, UUID_LEN+1, UUID_FMT,
                  UUID_ARGS(&(vrf_row->header_.uuid)));
        struct vrf *vrf = arpmgrd_vrf_lookup((const char*)buff);
        if (!vrf) {
            const struct smap *vrf_smap = &vrf_row->status;
            if ((smap_count(vrf_smap)
                   && vrf_is_ready(idl, vrf_row->name))) {
                arpmgrd_vrf_add(vrf_row);
            }
        } else {
            arpmgrd_vrf_add_ports(vrf, vrf_row);
        }
    }

    shash_destroy(&new_vrfs);
}

/* arpmgrd - OVSDB */
/* Function check if system is configured */
static inline void
arpmgrd_chk_for_system_configured(void)
{
    const struct ovsrec_system *ovs_vsw = NULL;

    if (system_configured) {
        /* Nothing to do if we're already configured. */
        return;
    }

    ovs_vsw = ovsrec_system_first(idl);

    if (ovs_vsw && (ovs_vsw->cur_cfg > (int64_t) 0)) {
        system_configured = true;
        VLOG_INFO("System is now configured (cur_cfg=%d).",
                (int)ovs_vsw->cur_cfg);
    }

} /* arpmgrd_chk_for_system_configured */

/* Function to initialize IDL and register for tables and columns */
static void
arpmgrd_init(const char *remote)
{
    idl = ovsdb_idl_create(remote, &ovsrec_idl_class, false, true);
    idl_seqno = ovsdb_idl_get_seqno(idl);
    ovsdb_idl_set_lock(idl, "ops_arpmgrd");
    ovsdb_idl_verify_write_only(idl);

    ovsdb_idl_add_table(idl, &ovsrec_table_system);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_cur_cfg);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_vrfs);

    ovsdb_idl_add_table(idl, &ovsrec_table_neighbor);
    ovsdb_idl_add_column(idl, &ovsrec_neighbor_col_vrf);
    ovsdb_idl_omit_alert(idl, &ovsrec_neighbor_col_vrf);
    ovsdb_idl_add_column(idl, &ovsrec_neighbor_col_ip_address);
    ovsdb_idl_omit_alert(idl, &ovsrec_neighbor_col_ip_address);
    ovsdb_idl_add_column(idl, &ovsrec_neighbor_col_address_family);
    ovsdb_idl_omit_alert(idl, &ovsrec_neighbor_col_address_family);
    ovsdb_idl_add_column(idl, &ovsrec_neighbor_col_mac);
    ovsdb_idl_omit_alert(idl, &ovsrec_neighbor_col_mac);
    ovsdb_idl_add_column(idl, &ovsrec_neighbor_col_port);
    ovsdb_idl_omit_alert(idl, &ovsrec_neighbor_col_port);
    ovsdb_idl_add_column(idl, &ovsrec_neighbor_col_state);
    ovsdb_idl_omit_alert(idl, &ovsrec_neighbor_col_state);
    ovsdb_idl_add_column(idl, &ovsrec_neighbor_col_status);
    ovsdb_idl_add_column(idl, &ovsrec_neighbor_col_in_use_by_routes);

    ovsdb_idl_add_table(idl, &ovsrec_table_vrf);
    ovsdb_idl_add_column(idl, &ovsrec_vrf_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_vrf_col_ports);
    ovsdb_idl_add_column(idl, &ovsrec_vrf_col_status);
    ovsdb_idl_add_column(idl, &ovsrec_vrf_col_table_id);

    ovsdb_idl_add_table(idl, &ovsrec_table_port);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_admin);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_ip4_address);

    unixctl_command_register("arpmgrd/dump", "", 0, 0,
            arpmgrd_unixctl_debug_cnt, NULL);

    nl_neighbor_sock = 0;
} /* arpmgrd_init */

static void
arpmgrd_exit(void)
{
    close_netlink_socket(nl_neighbor_sock);
    ovsdb_idl_destroy(idl);
} /* arpmgrd_exit */

static void
arpmgrd_run__(void)
{
    struct shash_node *vrf_node = NULL;
    /* Receive Neighbor updates over netlink */
    SHASH_FOR_EACH(vrf_node, &all_vrfs) {
        struct vrf *vrf = vrf_node->data;
        if (vrf->nl_sock > 0) {
             receive_neighbor_update(vrf, vrf->nl_sock);
        }
    }
} /* arpmgrd_run__ */

/*
 * Look for added or deleted ports
 * - For added ports see if any neighbor was found on the port, update the neighbor's
 *   ovsdb port
 * - For deleted ports, delete all neighbors on the port.
 */
static void
arpmgrd_reconfigure_port(struct ovsdb_idl *idl)
{
#define DEFAULT_IPV4_ADD "0.0.0.0"
    struct shash sh_idl_ports;
    const struct ovsrec_port *first_row, *row;
    struct shash_node *sh_port, *sh_port_next;
    struct shash_node *sh_nbr, *sh_nbr_next;

    first_row = ovsrec_port_first(idl);

    if (!first_row) {
        return;
    }

    /*
     * Check if any port rows were added or deleted.
     * If no change just return from here
     */
    if (first_row && !OVSREC_IDL_ANY_TABLE_ROWS_INSERTED(first_row, idl_seqno) &&
        !OVSREC_IDL_ANY_TABLE_ROWS_DELETED(first_row, idl_seqno) &&
        !OVSREC_IDL_ANY_TABLE_ROWS_MODIFIED(first_row, idl_seqno)) {
        VLOG_DBG("No port cfg changes");
        return;
    }

    /* Collect all the ports in the DB. */
    shash_init(&sh_idl_ports);

    OVSREC_PORT_FOR_EACH (row, idl) {
        if (!shash_add_once(&sh_idl_ports, row->name, row)) {
            VLOG_WARN("port %s specified twice in IDL", row->name);
        }
    }

    /* Delete old ports which got deleted or got deleted and inserted */
    if (OVSREC_IDL_ANY_TABLE_ROWS_DELETED(first_row, idl_seqno)) {
        SHASH_FOR_EACH_SAFE (sh_port, sh_port_next, &all_ports) {
            struct ovsrec_port *port_row = shash_find_data(&sh_idl_ports, sh_port->name);
            struct port_data *port_cache =  sh_port->data;

            if (!port_row || OVSREC_IDL_IS_ROW_INSERTED(port_row, idl_seqno)) {
                VLOG_INFO("Port %s deleted r not part of VRF", sh_port->name);

                /* Go though neighbors and remove neighbors with this port from DB
                 * Cache will be updated by kernel */
                SHASH_FOR_EACH_SAFE (sh_nbr, sh_nbr_next, &all_neighbors) {
                    struct neighbor_data *nbr_cache = sh_nbr->data;

                    if (nbr_cache->device && sh_port->name
                        && !strcmp(nbr_cache->device, sh_port->name)) {
                        delete_cache_nbr_from_ovsdb(nbr_cache);

                        /* Delete the neighbor from cache */
                        shash_delete(&all_neighbors, sh_nbr);

                        free(nbr_cache);
                        nbr_alloc_cnt --;
                    }
                }

                shash_delete(&all_ports, sh_port);
                free(port_cache);
                port_data_alloc --;
            }
        }
    }

    /* Add new ports. */
    if (OVSREC_IDL_ANY_TABLE_ROWS_INSERTED(first_row, idl_seqno)) {
        SHASH_FOR_EACH (sh_port, &sh_idl_ports) {
            const struct ovsrec_port *port_row = (const struct ovsrec_port *) sh_port->data;

            if (OVSREC_IDL_IS_ROW_INSERTED(port_row, idl_seqno)) {
                struct port_data *new_port = NULL;

                /* Allocate structure to save state information for this port. */
                new_port = xzalloc(sizeof(struct port_data));
                port_data_alloc++;

                if (!shash_add_once(&all_ports, port_row->name, new_port)) {
                    VLOG_WARN("Port %s specified twice", port_row->name);
                    free(new_port);
                    new_port = NULL;
                    port_data_alloc --;
                    continue;
                }
                new_port->port = port_row;
                /*setting up default value for ipv4_address */
                strcpy(new_port->ipv4_address, DEFAULT_IPV4_ADD);
                strcpy(new_port->admin, PORT_CONFIG_ADMIN_DOWN);
                /*Storing incoming ip4 info and admin for the created port */
                if (port_row->ip4_address)
                    strncpy(new_port->ipv4_address, port_row->ip4_address, INET_ADDRSTRLEN);
                if(port_row->admin)
                    strncpy(new_port->admin, port_row->admin, 32);
                /* May be moved to VLOG_DBG */
                VLOG_INFO("New port %s added. ip %s admin %s", sh_port->name, new_port->ipv4_address, new_port->admin);
		struct vrf* vrf = find_port_vrf_in_cache(port_row->name);
		int local_sock = (vrf == NULL) ? nl_neighbor_sock : vrf->nl_sock;

		/* Send netlink DUMP request to kernel to check for any existing
		 * neighbors on this PORT */
		if (local_sock > 0) {
			netlink_request_neighbor_dump(local_sock);
		}
	    }
	}
        /* Send netlink DUMP request to kernel to check for any existing
         * neighbors on this PORT */
        if (nl_neighbor_sock > 0) {
            netlink_request_neighbor_dump(nl_neighbor_sock);
            VLOG_DBG("Asked for a dump from kernel");
        }
    }
    if (OVSREC_IDL_ANY_TABLE_ROWS_MODIFIED(first_row, idl_seqno)) {
        const struct ovsrec_port *ovs_port;
        OVSREC_PORT_FOR_EACH (ovs_port, idl) {
            if (ovs_port && OVSREC_IDL_IS_ROW_MODIFIED(ovs_port, idl_seqno)) {
                struct port_data *port_cache = shash_find_data(&all_ports, ovs_port->name);
                bool no_ipv4 = false;
                if(!port_cache) {
                    VLOG_ERR("Entry for Port %s is not found in port cache", ovs_port->name);
                    continue;
                }
                /*IF port transitioned to down state or no ip4 state. Trigger chache & DB clean up for the associated nbr with the port. */
                if(((strcmp(port_cache->admin, PORT_CONFIG_ADMIN_DOWN)) &&
                            (ovs_port->admin && (0 == strcmp(ovs_port->admin,PORT_CONFIG_ADMIN_DOWN)))) ||
                        (no_ipv4 = (!ovs_port->ip4_address && strcmp(DEFAULT_IPV4_ADD, port_cache->ipv4_address)))
                  ) {
                    VLOG_INFO("Port %s is admin down or %d noip4 adress.cleaning the related nbrs form db and cache: %s %s",
                            ovs_port->name,no_ipv4, port_cache->admin, port_cache->ipv4_address);
                    if(no_ipv4)
                        strncpy(port_cache->ipv4_address, DEFAULT_IPV4_ADD, INET_ADDRSTRLEN);
                    /* Go though neighbors and remove neighbors with this port from DB
                     * Cache will be updated by kernel */
                    SHASH_FOR_EACH_SAFE (sh_nbr, sh_nbr_next, &all_neighbors) {
                        struct neighbor_data *nbr_cache = sh_nbr->data;
                        if (nbr_cache->device && ovs_port->name
                                && !strcmp(nbr_cache->device, ovs_port->name)) {
                            if(!nbr_cache->routes_nh) {
                                if(!no_ipv4 ||
                                        (!strcmp(nbr_cache->network_family,
                                                 OVSREC_NEIGHBOR_ADDRESS_FAMILY_IPV4))) {
                                    delete_cache_nbr_from_ovsdb(nbr_cache);
                                    /* Delete the neighbor from cache */
                                    shash_delete(&all_neighbors, sh_nbr);

                                    free(nbr_cache);
                                    nbr_alloc_cnt --;
                                }
                            }
                            else {
                                if(!no_ipv4 ||
                                        (!strcmp(nbr_cache->network_family,
                                                 OVSREC_NEIGHBOR_ADDRESS_FAMILY_IPV4))) {
                                    /* Don't clean. entry should present in db and cache */
                                    strcpy(nbr_cache->state, OVSREC_NEIGHBOR_STATE_INCOMPLETE);
                                    strcpy(nbr_cache->mac, "");
                                    if(!nbr_cache->nbr) {
                                        VLOG_ERR("Delete attmpted cache entry does not have ovs_nbr set.");
                                        continue;
                                    }
                                    const struct ovsrec_neighbor *ovs_nbr = nbr_cache->nbr;
                                    ovsrec_neighbor_set_mac(ovs_nbr, nbr_cache->mac);
                                    ovsrec_neighbor_set_state(ovs_nbr, nbr_cache->state);
                                    ovsdb_commit_required = true;
                                }
                            }
                        }
                    }
                }
                /* port admin state changes from DOWN -> UP, ping all the next hops
                 * ipv4 add set back Then ping the only ipv4 next hops .
                 */
                no_ipv4 = false;
                if((!(strcmp(port_cache->admin, PORT_CONFIG_ADMIN_DOWN)) &&
                            (ovs_port->admin && (strcmp(ovs_port->admin,PORT_CONFIG_ADMIN_DOWN)))) ||
                        (no_ipv4 = (ovs_port->ip4_address && !strcmp(DEFAULT_IPV4_ADD, port_cache->ipv4_address)))
                  ) {
                    VLOG_INFO("Port %s either came up or ip4 resotred,<%d>. cur state: %s %s",
                            ovs_port->name,no_ipv4, port_cache->admin, port_cache->ipv4_address);
                    if(ovs_port->name) {
                        strncpy(port_cache->port_up_reinstal.name,ovs_port->name,IF_NAMESIZE);
                    }
                    port_cache->port_up_reinstal.ipv4 = no_ipv4;
                    reinstal_nh_port_up = true;
                    /*ping send was failing because of network unavalibity, so to give some time move the ping send in
                     * main loop */
                }

                /*Storing the ip4 and admin info, whichever got changed. */
                if(ovs_port->ip4_address && (strcmp(port_cache->ipv4_address, ovs_port->ip4_address))) {
                    VLOG_INFO("port %s ip is modified: from %s to %s",ovs_port->name, port_cache->ipv4_address, ovs_port->ip4_address);
                    strncpy(port_cache->ipv4_address, ovs_port->ip4_address, INET_ADDRSTRLEN);
                }
                if (ovs_port->admin && (strcmp(port_cache->admin, ovs_port->admin))) {
                    VLOG_INFO("port%s admin state modified from %s to %s",ovs_port->name, port_cache->admin, ovs_port->admin);
                    strncpy(port_cache->admin, ovs_port->admin, 32);
                }
            }
        }
    }
    /* Destroy the shash of the IDL ports */
    shash_destroy(&sh_idl_ports);
} /* arpmgrd_reconfigure_port */

/*Updates the cache_nbr with the externally configured ovs_nbr entry.
* IP, VRF, state and might be mac field populated in ovs_nbr entry. this function may re reused for static entry add.
* This returns ip_add family by checking ip address.
*/
static void
update_configured_entry_to_neighbor_cache(const struct ovsrec_neighbor *ovs_nbr,
                                            struct neighbor_data *cache_nbr,
                                            int *family,
                                            char *mac_addr, char *state)
{
    const struct ovsrec_vrf *vrf = ovs_nbr->vrf;
    bool is_ipv6 = false;

    if (strchr(ovs_nbr->ip_address, ':')) {
        is_ipv6 = true;
        *family = AF_INET6;
    }
    else {
        *family = AF_INET;
    }
    if(!is_ipv6)  {
        strcpy((cache_nbr)->network_family, OVSREC_NEIGHBOR_ADDRESS_FAMILY_IPV4);
    } else  {
        strcpy((cache_nbr)->network_family, OVSREC_NEIGHBOR_ADDRESS_FAMILY_IPV6);
    }

    strcpy((cache_nbr)->vrf_name, vrf->name);
    strcpy((cache_nbr)->ip_address, ovs_nbr->ip_address);
    strcpy((cache_nbr)->state, state);
    strcpy((cache_nbr)->device, "");
    if(mac_addr){
        strcpy((cache_nbr)->mac, mac_addr);
    }
    (cache_nbr)->nbr = ovs_nbr;
}


static void
arpmgrd_reconfigure_neighbor(struct ovsdb_idl *idl)
{
    const struct ovsrec_neighbor *ovs_nbr, *first_row;
    first_row = ovsrec_neighbor_first(idl);
    if (first_row &&
            (!OVSREC_IDL_ANY_TABLE_ROWS_INSERTED(first_row, idl_seqno))&&
            !OVSREC_IDL_ANY_TABLE_ROWS_MODIFIED(first_row, idl_seqno)) {
        VLOG_DBG("No rows in table modified.");
        return;
    }
    OVSREC_NEIGHBOR_FOR_EACH (ovs_nbr, idl) {
        struct neighbor_data *cache_nbr;
        bool dp_hit;
        if(ovs_nbr && ovs_nbr->in_use_by_routes &&
                OVSREC_IDL_IS_ROW_INSERTED(ovs_nbr, idl_seqno)) {
            /*Process for neighbor entry add into cache */
            struct neighbor_data *cache_nbr = NULL;
            int family = AF_INET;
            cache_nbr = find_neighbor_in_cache(ovs_nbr->vrf->name, ovs_nbr->ip_address);
            if (!cache_nbr) {
                VLOG_INFO("Neighbor entry is added by external module. ip %s, vrf %s",
                    ovs_nbr->ip_address, ovs_nbr->vrf->name);
                cache_nbr = add_neighbor_to_cache(ovs_nbr->vrf->name, ovs_nbr->ip_address);
                if (!(cache_nbr)) {
                    VLOG_ERR("Unable to add new neighbor.<ip> %s <vrf>%s",
                            ovs_nbr->ip_address,ovs_nbr->vrf->name);
                    return ;
                }
                char *mac_addr = NULL;
                char *state = OVSREC_NEIGHBOR_STATE_INCOMPLETE;
                update_configured_entry_to_neighbor_cache(ovs_nbr, cache_nbr, &family, mac_addr,state);
                cache_nbr->nbr_unresolved = true;
                if((ovs_nbr->in_use_by_routes && (*(ovs_nbr->in_use_by_routes) == true)) &&
                        (!ovs_nbr->state ||
                         (ovs_nbr->state && (0 == strcmp(ovs_nbr->state, OVSREC_NEIGHBOR_STATE_INCOMPLETE))))
                  ) {
                    cache_nbr->routes_nh = true;

                    /*Entry added in nbr cache, now initiate a ping to get added into the kernel ND table
                     * Kernel shall find the proper egress interface for the ping pkt
                     *   create a neighbour entry, mark its state as 'incomplete'
                     *   Resolve its mac either by arp/ND protocol.
                     *   Notify back to arpmgrd via netlink notification.
                     */
                    VLOG_INFO("externerally added entry is placed in cache, invoking ping...");
                    int ping_err = -1;
                    if(family == AF_INET6){
                        ping_err = ping6(ovs_nbr->ip_address);
                    }
                    else {
                        ping_err = ping4(ovs_nbr->ip_address);
                    }
                    if(ping_err < 0) {
                        VLOG_INFO("Need reinstal_nh %d",__LINE__);
                        reinstal_nh = true;
                    }
                }
            }
            continue;
        }
        if (ovs_nbr && !OVSREC_IDL_IS_ROW_MODIFIED(ovs_nbr, idl_seqno)) {
            VLOG_DBG("Neighbor row not modified");
            continue;
        }

        /*
         * Check for dp_hit in Neighbor rows.
         * dp_hit will be set by vswitchd
         * If dp_hit is set, we need to probe
         * and refresh kernel entry
         * */
        cache_nbr = find_neighbor_in_cache(ovs_nbr->vrf->name, ovs_nbr->ip_address);
        if (!cache_nbr) {
            VLOG_DBG("Did not find ovsdb neighbor in cache. ip %s, vrf %s",
                    ovs_nbr->ip_address, ovs_nbr->vrf->name);
            continue;
        }

        /* Update the ovsdb rec in cache */
        cache_nbr->nbr = ovs_nbr;

        /* Get in_use_by_routes from column in_use_by_routes. This takes care of the cases:
         * 1. next_hop found by routing deamon is already added in Neighbor tbl.arpmgrd should send probe to keep it
         * REACHABLE.
         * 2. next_hop is no more referenced by any route routing deamon make in_use_by_routes to false and arpmgrd should
         * not send probe to keep it REACHABLE.
        */
        if(ovs_nbr->in_use_by_routes &&
            (cache_nbr->routes_nh != (*(ovs_nbr->in_use_by_routes)))){
            VLOG_INFO("Modified in_use_by_routes for %s from %d to %d",
                cache_nbr->ip_address, cache_nbr->routes_nh, (*(ovs_nbr->in_use_by_routes)));
            cache_nbr->routes_nh = (*(ovs_nbr->in_use_by_routes));
        }
        /* routing deamon make in_use_by_routes to true for an existing entry in Neighbor Tbl whose state is
         * STALE. Then send probe to keep the entry REACHABLE.*/
        if (cache_nbr->routes_nh &&(0 == strcmp(cache_nbr->state,
                OVSREC_NEIGHBOR_STATE_STALE)) &&
                (nl_neighbor_sock > 0)) {
            int family = AF_INET;
            uint32_t dst[8];
            int plen = 0;

            if (strcmp(ovs_nbr->address_family,
                       OVSREC_NEIGHBOR_ADDRESS_FAMILY_IPV6) == 0) {
                family = AF_INET6;
                inet_pton(AF_INET6, ovs_nbr->ip_address, dst);
                plen = 16;
            } else if (strcmp(ovs_nbr->address_family,
                              OVSREC_NEIGHBOR_ADDRESS_FAMILY_IPV4) == 0) {
                family = AF_INET;
                inet_pton(AF_INET, ovs_nbr->ip_address, dst);
                plen = 4;
            }
            send_neighbor_probe(nl_neighbor_sock, cache_nbr->ifindex,
                                 family, dst, plen);
            strcpy(cache_nbr->state, OVSREC_NEIGHBOR_STATE_REACHABLE);
            update_neighbor_to_ovsdb(cache_nbr, false);
        }
        if (cache_nbr->routes_nh &&(0 == strcmp(cache_nbr->state,
                OVSREC_NEIGHBOR_STATE_INCOMPLETE))
                ) {
            int ping_err = 0;
            VLOG_INFO("routes_nh is set for %s",cache_nbr->ip_address);
            if (strcmp(cache_nbr->network_family,
                       OVSREC_NEIGHBOR_ADDRESS_FAMILY_IPV6) == 0) {
                 ping_err = ping6(cache_nbr->ip_address);
            }
            else if (strcmp(cache_nbr->network_family,
                              OVSREC_NEIGHBOR_ADDRESS_FAMILY_IPV4) == 0) {
                 ping_err = ping4(cache_nbr->ip_address);
            }
            if(ping_err < 0) {
                VLOG_INFO("Need reinstal_nh %d",__LINE__);
                reinstal_nh = true;
            }
        }

        /* Get dp_hit from status column */
        dp_hit = smap_get_bool(&ovs_nbr->status, OVSDB_NEIGHBOR_STATUS_DP_HIT,
                OVSDB_NEIGHBOR_STATUS_MAP_DP_HIT_DEFAULT);

        /* Check if dp_hit changed */
        if (cache_nbr->dp_hit != dp_hit) {
            /* If dp_hit is set, state in not reachable send probe */
            if (dp_hit &&(0 == strcmp(cache_nbr->state,
                    OVSREC_NEIGHBOR_STATE_STALE)) &&
                    (nl_neighbor_sock > 0)) {
                int family = AF_INET;
                uint32_t dst[8];
                int plen = 0;

                if (strcmp(ovs_nbr->address_family,
                           OVSREC_NEIGHBOR_ADDRESS_FAMILY_IPV6) == 0) {
                    family = AF_INET6;
                    inet_pton(AF_INET6, ovs_nbr->ip_address, dst);
                    plen = 16;
                } else if (strcmp(ovs_nbr->address_family,
                                  OVSREC_NEIGHBOR_ADDRESS_FAMILY_IPV4) == 0) {
                    family = AF_INET;
                    inet_pton(AF_INET, ovs_nbr->ip_address, dst);
                    plen = 4;
                }
                send_neighbor_probe(nl_neighbor_sock, cache_nbr->ifindex,
                                     family, dst, plen);
                /*
                 * FIXME: Set state to reachable. Currently we are not receiving
                 * Reachable state from Stale (Bug)
                 * If kernel is unable to resolve, we will get an explicit
                 * notification for FAILED state
                 */
                strcpy(cache_nbr->state, OVSREC_NEIGHBOR_STATE_REACHABLE);
                update_neighbor_to_ovsdb(cache_nbr, false);
            }
            /* Update dp_hit attribute in our cache */
            cache_nbr->dp_hit = dp_hit;
        }
    }
} /* arpmgrd_reconfigure_neighbor */

static void
arpmgrd_reconfigure(struct ovsdb_idl *idl)
{
    unsigned int new_idl_seqno = ovsdb_idl_get_seqno(idl);


    COVERAGE_INC(arpmgr);
    if (new_idl_seqno == idl_seqno){
        return;
    }

    arpmgrd_add_del_vrf(idl);
    arpmgrd_reconfigure_port(idl);
    arpmgrd_reconfigure_neighbor(idl);

    idl_seqno = new_idl_seqno;
} /* arpmgrd_reconfigure */

static void
arpmgrd_run(void)
{
    daemonize_complete();
    vlog_enable_async();
    VLOG_INFO_ONCE("%s (OpenSwitch arpmgrd) %s", program_name, VERSION);
    ovsdb_idl_run(idl);

    if (ovsdb_idl_is_lock_contended(idl)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

        VLOG_ERR_RL(&rl, "another ops-arpmgrd process is running, "
                "disabling this process until it goes away");

        return;
    } else if (!ovsdb_idl_has_lock(idl)) {
        return;
    }

    arpmgrd_chk_for_system_configured();
    if (system_configured) {
        /*
         * If previous transaction status was incomplete
         * check status again. Else destroy previous
         *  */
        if (txn && txn_status == TXN_INCOMPLETE) {
            txn_status = ovsdb_idl_txn_commit(txn);
            /* If we are still incomplete, just go back and try again */
            if (txn_status ==  TXN_INCOMPLETE) {
                goto done;
            }
        }

        /* Some transaction failure case. Lets resync with kernel */
        if(txn_status != TXN_SUCCESS && txn_status != TXN_UNCHANGED) {
            VLOG_INFO("Retry failed %d", txn_status);
            sync_mode = SYNC_WITHOUT_CACHE_RESET;
            sync_state = SYNC_IN_PROGRESS;
        }

        if (txn) {
            ovsdb_idl_txn_destroy(txn);
            txn = NULL;
        }
        if ((sync_state == SYNC_IN_PROGRESS) ||
            (sync_state == SYNC_FAILED))
         {
            /* Delete previous transaction
             * We will resync with kernel
             * Create a new transaction
             */
            VLOG_INFO("Sync with kernel called");
            if (txn) {
                ovsdb_idl_txn_destroy(txn);
            }
            txn = NULL;
            txn = ovsdb_idl_txn_create(idl);
            resync_db_with_kernel();
            VLOG_INFO("Sync with kernel was called: nbr_alloc_cnt %d, multi_part_res %d, no_n_res %d, nl_dump_res_size %d",
            nbr_alloc_cnt,nl_dump_res_cnt, nl_dump_res_nof_multi_cnt,nl_dump_res_size);
        }

        /* End "sync in progress state", and reset */
        if(sync_state == SYNC_COMPLETE) {
            VLOG_DBG("sync_state is COMPLETE");
            sync_state = SYNC_NONE;
            if(sync_mode == SYNC_WITH_CACHE_RESET) {
                close_netlink_socket(nl_neighbor_sock);
                VLOG_DBG("closed netlink socket");
                nl_neighbor_sock = 0;
            }
            sync_mode = SYNC_WITHOUT_CACHE_RESET;
        }

        /* Suspend kernel notifications, and begin resync
           of OVSDB with kernel */
        if(sync_state == SYNC_REQUESTED || sync_state == SYNC_FAILED) {

            VLOG_DBG("sync_state changed from %d to IN_PROGRESS", sync_state);
            if(sync_mode == SYNC_WITH_CACHE_RESET) {
                /* Clear up our cache for resync */
                shash_destroy_free_data(&all_neighbors);
                shash_init(&all_neighbors);
                nbr_alloc_cnt = 0;

                if(sync_state != SYNC_FAILED) {
                   /* Close the previous socket */
                   close_netlink_socket(nl_neighbor_sock);
                   VLOG_DBG("closed netlink socket");
                   nl_neighbor_sock = 0;

                   /* Open new socket for resync */
                   netlink_socket_open(DEFAULT_VRF_NAME, &nl_neighbor_sock, NETLINK_ROUTE, 0);
                }
            }
            /* Update state to sync_in_progress */
            sync_state = SYNC_IN_PROGRESS;
        }

        if (!nl_neighbor_sock) {
            VLOG_DBG("opening netlink socket");
            netlink_socket_open(DEFAULT_VRF_NAME, &nl_neighbor_sock, NETLINK_ROUTE, RTMGRP_NEIGH);
        }

        if(!txn){
            txn = ovsdb_idl_txn_create(idl);
        }

        if(reinstal_nh_port_up || reinstal_nh){
            struct shash_node *sh_nbr, *sh_nbr_next;
            int ping_err = 0;
            bool require_reinstall = false;
            SHASH_FOR_EACH_SAFE (sh_nbr, sh_nbr_next, &all_neighbors) {
                struct neighbor_data *nbr_cache = sh_nbr->data;
                /* Triggering the ping_send cycle for the unresolved nbr at port is up event */
                if(reinstal_nh_port_up && (!strcmp(nbr_cache->device, ""))) {
                    nbr_cache->ping_retry_cnt = 0;
                    goto send_ping;
                }
                /* Trggering ping_send for the unresolved entries.
                 * This should take care if ping was sent for nh resolution before the actual interface is up by the kernel */
                if(reinstal_nh && !strcmp(nbr_cache->state, OVSREC_NEIGHBOR_STATE_INCOMPLETE)) {
                    goto send_ping;
                }
                /*find the port_data for the nbr_cache->device */
                struct port_data *pport_data = shash_find_data(&all_ports, nbr_cache->device);
                if(!pport_data) {
                    VLOG_ERR("port_data not found for the dev %s",nbr_cache->device);
                    continue;
                }
                if (nbr_cache->device
                        && !strcmp(nbr_cache->device, pport_data->port_up_reinstal.name)) {
send_ping:
                    if(nbr_cache->routes_nh && (nbr_cache->ping_retry_cnt < MAX_NH_PING_CNT)) {
                        VLOG_INFO("pinging %s to restore nh in port %s again", nbr_cache->ip_address, nbr_cache->device);
                        if(!strcmp(nbr_cache->network_family,
                                    OVSREC_NEIGHBOR_ADDRESS_FAMILY_IPV4)) {
                            ping_err = ping4(nbr_cache->ip_address);
                            /*The state is changed to unresolved nbr*/
                            strcpy(nbr_cache->state,OVSREC_NEIGHBOR_STATE_INCOMPLETE);
                        }
                        else if(!strcmp(nbr_cache->network_family, OVSREC_NEIGHBOR_ADDRESS_FAMILY_IPV6)) {
                            ping_err = ping6(nbr_cache->ip_address);
                            strcpy(nbr_cache->state,OVSREC_NEIGHBOR_STATE_INCOMPLETE);
                        }
                        if(ping_err < 0) {
                            require_reinstall = true;
                        }
                    }
                    nbr_cache->ping_retry_cnt ++;
                }
            }
            /* Clears only when all the ping_sends are succesful.*/
            if(!require_reinstall) {
                reinstal_nh = false;
            }
            /*After first ping send,reinstal_nh event gets convreted into reinstal_nh for unresolved nbr*/
            reinstal_nh_port_up = false;
        }

        arpmgrd_reconfigure(idl);
        arpmgrd_run__();

        if(ovsdb_commit_required == true) {
            txn_status = ovsdb_idl_txn_commit(txn);
            ovsdb_tr_trigger_cnt ++;
            VLOG_DBG("Txn status after commit = %d", txn_status);
            ovsdb_commit_required = false;
            if (txn_status == TXN_SUCCESS) {
                ovsdb_idl_txn_destroy(txn);
                txn = NULL;
            }
        } else {
            ovsdb_idl_txn_destroy(txn);
            txn = NULL;
        }
    }
    done:
    return;
} /* arpmgrd_run */

static void
neighbor_netlink_recv_wait__()
{
    if(nl_neighbor_sock > 0 && system_configured) {
        poll_fd_wait(nl_neighbor_sock , POLLIN);
    }
} /* neighbor_netlink_recv_wait__ */

static void
arpmgrd_wait(void)
{
    ovsdb_idl_wait(idl);
    neighbor_netlink_recv_wait__();
    poll_timer_wait(ARPMGR_POLL_INTERVAL * 1000);
} /* arpmgrd_wait */

static void
arpmgrd_unixctl_debug_cnt(struct unixctl_conn *conn, int argc OVS_UNUSED,
        const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    const struct ovsrec_neighbor *ovs_nbr;
    struct shash_node *sh_node, *sh_next;
    struct ds ds = DS_EMPTY_INITIALIZER;
    ovs_idl_nbr_cnt = 0;
    all_neighbors_len = 0;
    OVSREC_NEIGHBOR_FOR_EACH(ovs_nbr, idl) {
        ovs_idl_nbr_cnt ++;
    }
    SHASH_FOR_EACH_SAFE(sh_node, sh_next, &all_neighbors) {
        all_neighbors_len ++;
    }
    ds_put_format(&ds,
"nbr_alloc_cnt %d \n\
port_data_alloc %d \n\
ovsrec_neighbor_alloc_cnt %d\n\
force_ins_cnt %d \n\
force_del_cnt %d \n\
ovs_idl_nbr_cnt %d,\n\
all_neighbors_len %d\n",nbr_alloc_cnt,
                port_data_alloc,ovsrec_neighbor_alloc_cnt,
                idl_nbr_force_ins_cnt,idl_nbr_force_del_cnt,ovs_idl_nbr_cnt,
                all_neighbors_len);
    ds_put_format(&ds,"size_neighbor_data = %lu, size_ovsrec_neighbor = %lu\n",sizeof(struct neighbor_data),
    sizeof(struct ovsrec_neighbor));
     ds_put_format(&ds,"nl_dump_req_cnt %d, nl_dump_res_cnt %d, not_multi_part_dump_res_cnt %d \n\
nl_probe_req_cnt %d, nl_dump_res_size %d,ovsdb_tr_trigger_cnt %d \n",
nl_dump_req_cnt,nl_dump_res_cnt, nl_dump_res_nof_multi_cnt,
nl_probe_req_cnt, nl_dump_res_size,
ovsdb_tr_trigger_cnt);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
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
    unixctl_command_register("exit", "", 0, 0, arpmgrd_exit_cb, &exiting);

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
} /* main */

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
} /* parse_options */

static void
usage(void)
{
    printf("%s: OpenSwitch arpmgrd daemon\n"
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
} /* usage */

static void
arpmgrd_exit_cb(struct unixctl_conn *conn, int argc OVS_UNUSED,
        const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);
} /* arpmgrd_exit_cb */
