/**
 * @file pcp_client.c  PCP Client
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

#include <stdint.h>
#include "debug.h"
#include "pcp_client.h"

uint8_t *temp_nonce[PCP_NONCE_SZ]; /**< Mapping Nonce    */ 
int nonce_initialize = 0;

static void pcp_resp_handler(int err, struct pcp_msg *msg, void *arg)
{

	//const struct pcp_peer *peer = pcp_msg_payload(msg);
	(void)arg;

//	re_printf("PCP Response: %H\n", pcp_msg_print, msg);

	if (err) {
		debug("PCP error response: %m\n", err);
		goto out;
	}

	if (msg->hdr.result != PCP_SUCCESS) {
		debug("PCP error response: %s\n", 
			pcp_result_name(msg->hdr.result));
		goto out;
	} else {
		debug("PCP response: %s\n", 
			pcp_result_name(msg->hdr.result));
	}

 out:
	re_cancel();

}

int coap_create_map_rule(char *pcp_srv, uint32_t lifetime, char *ext_addr, int int_port, char *thrd_part)
{
	struct pcp_request *req = NULL;
	struct pcp_peer peer;
        struct sa third_party;
	struct sa pcp_server;
	int err = 0;

	sa_init(&peer.map.ext_addr, AF_UNSPEC);
	sa_init(&peer.remote_addr, AF_UNSPEC);
	sa_init(&pcp_server, AF_UNSPEC);
	sa_init(&third_party, AF_UNSPEC);
	
	/* default values */
	peer.map.proto = IPPROTO_UDP;

	err = libre_init();
	if (err)
		return 2;

	err = sa_decode(&peer.map.ext_addr, ext_addr, strlen(ext_addr));
	if (err) {
		debug("invalid external address: '%s'\n",
			ext_addr);
		return 2;
	}

	err = sa_set_str(&third_party, thrd_part, 0);
	if (err) {
		debug("invalid thirdparty address:"
			   " '%s'\n",
			   thrd_part);
		return 2;
	}

	err = sa_decode(&pcp_server, pcp_srv, strlen(pcp_srv));
	if (err) {
		debug("invalid server address:"
			   " '%s'\n", pcp_srv);
		return 2;
	}
	peer.map.int_port = int_port;
 
	/* Maximum retransmission duration*/
	conf.mrd = 4; 

/*re_printf("lifetime = %u sec, pcp_server = %J, protocol = %s, internal_port = %u, external = %J, T = %j\n",
			  lifetime, &pcp_server, pcp_proto_name(peer.map.proto),
			  peer.map.int_port, &peer.map.ext_addr, &third_party);*/

	if (!nonce_initialize){
		rand_bytes(peer.map.nonce, sizeof peer.map.nonce);
		nonce_initialize = 1;
		memcpy(temp_nonce, &peer.map.nonce, PCP_NONCE_SZ*sizeof(uint8_t));
	} else {
		memcpy(&peer.map.nonce, temp_nonce, PCP_NONCE_SZ*sizeof(uint8_t));
	}

	/* send the PCP request */
	err = pcp_request(&req, &conf, &pcp_server, PCP_MAP,
			  lifetime, &peer,
			  pcp_resp_handler, NULL,
			  1,
			  PCP_OPTION_THIRD_PARTY, &third_party);
	if (err) {
		debug("failed to send PCP request: %m\n", err);
		goto out;
	}

	err = re_main(NULL);

 out:
	mem_deref(req);
	libre_close();

	/* check for memory leaks */
	mem_debug();
	tmr_debug();

	return err;
}
