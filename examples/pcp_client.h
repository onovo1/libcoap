/**
 * @file pcp_client.h  PCP Client
 *
 * Copyright (C) 2010 - 2016
 */

#ifndef _PCP_CLIENT_H_
#define _PCP_CLIENT_H_

#include <re.h>
#include <rew.h>

/**
 * Representation of the default pcp configuration parameters.
 */
static struct pcp_conf conf = {
	3,     /* IRT */
	0,     /* MRC */
	1024,  /* MRT */
	0      /* MRD */
};

/** 
 * Creates a MAP rule and sends it to the PCP server. If the lifetime is 0, it removes a rule that was created previously. 
 * 
 * @param pcp_srv     PCP server address. 
 * @param lifetime    Lifetime.
 * @param ext_addr    External address. 
 * @param int_port    Internal port.
 * @param thrd_part   THIRD_PARTY address (e.g. 1.2.3.4)
 * 
 * @return       @c 1 if rule was set, @c 0 otherwise.
 *
 */
int coap_create_map_rule(char *pcp_srv, uint32_t lifetime, char *ext_addr, int int_port, char *thrd_part);

/** @} */

#endif /* _PCP_CLIENT_H_ */
