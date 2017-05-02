/*
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/** Memory pool definitions for the libcoap when used with lwIP (which has its
 * own mechanism for quickly allocating chunks of data with known sizes). Has
 * to be findable by lwIP (ie. an #include <lwippools.h> must either directly
 * include this or include something more generic which includes this), and
 * MEMP_USE_CUSTOM_POOLS has to be set in lwipopts.h. */

#include "coap_config.h"
#include <net.h>
#include <resource.h>
#include <subscribe.h>

#ifndef MEMP_NUM_COAPCONTEXT
#define MEMP_NUM_COAPCONTEXT 1
#endif

#ifndef MEMP_NUM_COAPENDPOINT
#define MEMP_NUM_COAPENDPOINT 1
#endif

/* 1 is sufficient as this is very short-lived */
#ifndef MEMP_NUM_COAPPACKET
#define MEMP_NUM_COAPPACKET 1
#endif

#ifndef MEMP_NUM_COAPNODE
#define MEMP_NUM_COAPNODE 4
#endif

#ifndef MEMP_NUM_COAPPDU
#define MEMP_NUM_COAPPDU MEMP_NUM_COAPNODE
#endif

#ifndef MEMP_NUM_COAP_SUBSCRIPTION
#define MEMP_NUM_COAP_SUBSCRIPTION 4
#endif

#ifndef MEMP_NUM_COAPRESOURCE
#define MEMP_NUM_COAPRESOURCE 10
#endif

#ifndef MEMP_NUM_COAPRESOURCEATTR
#define MEMP_NUM_COAPRESOURCEATTR 20
#endif

#ifndef MEMP_NUM_COAPRESOURCELINK
#define MEMP_NUM_COAPRESOURCELINK 20
#endif

#ifndef MEMP_NUM_COAPGROUP
#define MEMP_NUM_COAPGROUP 10
#endif

#ifndef MEMP_NUM_COAPLIFETIME
#define MEMP_NUM_COAPLIFETIME 10
#endif

#ifndef MEMP_NUM_COAPGROUPENDPOINT
#define MEMP_NUM_COAPGROUPENDPOINT 10
#endif

#ifndef MEMP_NUM_COAPBLOCK
#define MEMP_NUM_COAPBLOCK 10
#endif

LWIP_MEMPOOL(COAP_CONTEXT, MEMP_NUM_COAPCONTEXT, sizeof(coap_context_t), "COAP_CONTEXT")
LWIP_MEMPOOL(COAP_ENDPOINT, MEMP_NUM_COAPENDPOINT, sizeof(coap_endpoint_t), "COAP_ENDPOINT")
LWIP_MEMPOOL(COAP_PACKET, MEMP_NUM_COAPPACKET, sizeof(coap_packet_t), "COAP_PACKET")
LWIP_MEMPOOL(COAP_NODE, MEMP_NUM_COAPNODE, sizeof(coap_queue_t), "COAP_NODE")
LWIP_MEMPOOL(COAP_PDU, MEMP_NUM_COAPPDU, sizeof(coap_pdu_t), "COAP_PDU")
LWIP_MEMPOOL(COAP_subscription, MEMP_NUM_COAP_SUBSCRIPTION, sizeof(coap_subscription_t), "COAP_subscription")
LWIP_MEMPOOL(COAP_RESOURCE, MEMP_NUM_COAPRESOURCE, sizeof(coap_resource_t), "COAP_RESOURCE")
LWIP_MEMPOOL(COAP_RESOURCEATTR, MEMP_NUM_COAPRESOURCEATTR, sizeof(coap_attr_t), "COAP_RESOURCEATTR")
LWIP_MEMPOOL(COAP_RESOURCELINK, MEMP_NUM_COAPRESOURCELINK, sizeof(coap_link_t), "COAP_RESOURCELINK")
LWIP_MEMPOOL(COAP_GROUP, MEMP_NUM_COAPGROUP, sizeof(coap_group_t), "COAP_GROUP")
LWIP_MEMPOOL(COAP_LIFETIME, MEMP_NUM_COAPLIFETIME, sizeof(coap_lifetime_t), "COAP_LIFETIME")
LWIP_MEMPOOL(COAP_GROUP_ENDPOINT, MEMP_NUM_COAPGROUPENDPOINT, sizeof(coap_endpoints_t), "COAP_GROUP_ENDPOINT")
LWIP_MEMPOOL(COAP_BLOCK, MEMP_NUM_COAPBLOCK, sizeof(coap_block1_t), "COAP_BLOCK")

