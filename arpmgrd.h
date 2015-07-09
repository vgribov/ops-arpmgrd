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
 * File: arpmgrd.h
 */

#ifndef ARPMGRD_H_
#define ARPMGRD_H_

#define LOOPBACK_INTERFACE_NAME "lo"
#define arpmgr_POLL_INTERVAL 5
#define IPV4_ADDRESS_FAMILY_STRING "ipv4"
#define IPV6_ADDRESS_FAMILY_STRING "ipv6"

#define RECV_BUFFER_SIZE 2000
#define ISMULTICAST(address) ((address >> 28) == 14)

struct nl_req {
    struct nlmsghdr n;
    struct ndmsg r;
};

#endif /* ARPMGRD_H_ */
