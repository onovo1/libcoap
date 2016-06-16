/* group.h -- CoAP group structures used in the resource directory
 *
 * Copyright (C) 2010,2011,2015 Oscar Novo
 *
 * This file is part of the CoAP library libcoap. Please see README for terms of
 * use.
 */

#include "group.h"
#include "mem.h"
#include "utlist.h"
#include "debug.h"

void
coap_delete_endpoint(coap_group_t *group, coap_endpoints_t *endpoint) {
  if (!endpoint)
    return;

  if (endpoint->ep.s){
    coap_free(endpoint->ep.s);
  }

  LL_DELETE(group->endpoints,endpoint);

#ifdef WITH_LWIP
  memp_free(MEMP_COAP_GROUP_ENDPOINT, endpoint);
#endif
#ifndef WITH_LWIP
  coap_free_type(COAP_GROUP_ENDPOINT, endpoint);
#endif
}

coap_endpoints_t *
coap_add_endpoint(coap_group_t *group, 
	       const char *ep) {

  coap_endpoints_t *endpoint;

  if (!group || !ep)
    return NULL;

#ifdef WITH_LWIP
  endpoint = (coap_endpoints_t *)memp_malloc(MEMP_COAP_GROUP_ENDPOINT);
#endif
#ifndef WITH_LWIP
  endpoint = (coap_endpoints_t *)coap_malloc_type(COAP_GROUP_ENDPOINT, sizeof(coap_endpoints_t));
#endif

  if (endpoint) {

    endpoint->ep.s = (unsigned char *)ep;
    endpoint->ep.length =  ep ? strlen(ep) : 0;

    /* add endpoint to group list */
    LL_PREPEND(group->endpoints, endpoint);
  } else {
    debug("coap_add_endpoint: no memory left\n");
  }
  
  return endpoint;
}

coap_group_t *
coap_group_rd_init(const unsigned char *uri, size_t len, const unsigned char *key_uri, size_t key_len, str d, str con, coap_method_group_handler_t handler) {

  coap_group_t *g;
  unsigned char *buf;

#ifdef WITH_LWIP
  g = (coap_group_t *)memp_malloc(MEMP_COAP_GROUP);
#endif
#ifndef WITH_LWIP
  g = (coap_group_t *)coap_malloc_type(COAP_GROUP, sizeof(coap_group_t));
#endif
  if (g) {
    memset(g, 0, sizeof(coap_group_t));

    g->uri.s = (unsigned char *)uri;
    g->uri.length = len;
    
    if ((d.s) && (d.length<=63)) {
      buf = (unsigned char *)coap_malloc(d.length + 2);
      if (buf) {
        /* add missing quotes */
        buf[0] = '"';
        memcpy(buf + 1, d.s, d.length);
        buf[d.length + 1] = '"';

	g->d.s = buf;
	g->d.length = d.length+2; 
      } else {
	debug("coap_group_init: no memory left\n");
        return NULL;
      }
    }

    if ((con.s) && (con.length<=63)) {
      buf = (unsigned char *)coap_malloc(con.length + 2);
      if (buf) {
        /* add missing quotes */
        buf[0] = '"';
        memcpy(buf + 1, con.s, con.length);
        buf[con.length + 1] = '"';

	g->con.s = buf;
	g->con.length = con.length+2; 
      } else {
	debug("coap_group_init: no memory left\n");
        return NULL;
      }
    }

    g->handler[0] = handler;

    coap_hash_path(key_uri, key_len, g->key);
    
  } else {
    debug("coap_group_init: no memory left\n");
    return NULL;
  }
  
  return g;
}

void
coap_add_group(coap_context_t *context, coap_group_t *group) {
  GROUP_ADD(context->groups, group);
}

void
coap_free_group(coap_group_t *group) {
  coap_endpoints_t *endpoints, *endpoints_tmp;

  assert(group);

  /* delete registered endpoints */
  LL_FOREACH_SAFE(group->endpoints, endpoints, endpoints_tmp) coap_delete_endpoint(group, endpoints);

  /*release the URI identifier*/
  if (group->uri.s!=NULL)
    coap_free(group->uri.s);

  /*release the A identifier*/
  if (group->A.s!=NULL)
    coap_free(group->A.s);

  /*release the 'con' information*/
  if (group->con.s!=NULL)
    coap_free(group->con.s);

  /*release the 'd' information*/
  if (group->d.s!=NULL)
    coap_free(group->d.s);

#ifdef WITH_LWIP
  memp_free(MEMP_COAP_GROUP, group);
#endif
#ifndef WITH_LWIP
  coap_free_type(COAP_GROUP, group);
#endif /* WITH_CONTIKI */
}

int
coap_delete_all_groups(coap_context_t *context) {

  if (!context)
    return 0;

  GROUP_ITER(context->groups,group) {

    /* remove group from list */
    GROUP_DELETE(context->groups, group);

    /* and free its allocated memory */
    coap_free_group(group);

  }

  context->groups = NULL;

  return 1;
}

int
coap_delete_group(coap_context_t *context, coap_key_t key) {
  coap_group_t *group;

  if (!context)
    return 0;

  group = coap_get_group_from_key(context, key);

  if (!group) 
    return 0;

  /* remove group from list */
  GROUP_DELETE(context->groups, group);

  /* and free its allocated memory */
  coap_free_group(group);

  return 1;
}

coap_group_t *
coap_get_group_from_key(coap_context_t *context, coap_key_t key) {
  coap_group_t *result;

  GROUP_FIND(context->groups, key, result);

  return result;
}
