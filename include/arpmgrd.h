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
 * File: arpmgrd.h
 */

#ifndef ARPMGRD_H_
#define ARPMGRD_H_

#include "openswitch-idl.h"
#include "nl-utils.h"
#include "vrf-utils.h"

#define ARPMGR_POLL_INTERVAL 5
#define LOOPBACK_INTERFACE_NAME "lo"
#define RECV_BUFFER_SIZE 8192
#define IS_IPV4MULTICAST(address) ((address >> 28) == 14)
#define MAC_ADDRSTRLEN 18

#endif /* ARPMGRD_H_ */
