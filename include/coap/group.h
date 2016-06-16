/* group.h -- CoAP group structures used in the resource directory
 *
 * Copyright (C) 2010,2011,2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms of
 * use.
 */

/**
 * @file group.h
 * @brief Generic group handling
 */

#ifndef _GROUP_H_
#define _GROUP_H_

# include <assert.h>

#ifdef COAP_RESOURCES_NOHASH
#  include "utlist.h"
#else
#  include "uthash.h"
#endif

#include "str.h"
#include "hashkey.h"
#include "net.h"

/**
 * Definition of message handler function (@sa coap_group_t).
 */
typedef void (*coap_method_group_handler_t)
  (coap_context_t  *,
   struct coap_group_t *,
   const coap_endpoint_t *,
   coap_address_t *,
   coap_pdu_t *,
   str * /* token */,
   coap_pdu_t * /* response */);

typedef struct coap_endpoints_t {
  struct coap_endpoints_t *next;
  str ep;	/*URI target of the endpoint*/
} coap_endpoints_t;

typedef struct coap_group_t {

  /**
   * Used to store handler for the coap method @c DELETE. coap_dispatch() will pass 
   * incoming requests to the handler that corresponds to its request method or 
   * generate a 4.05 response if no handler is available.
   */
  coap_method_group_handler_t handler[1];

  coap_key_t key;                /**< the actual key bytes for this resource */

#ifdef COAP_RESOURCES_NOHASH
  struct coap_group_t *next;
#else
  UT_hash_handle gh;
#endif

  coap_endpoints_t *endpoints; /**< endpoints to be included with the group */

  /**
   * Request URI for this group (rd-group/gp-name). This field will point into the static
   * memory.
   */
  str uri;
  str A; /** The source IP address and source port of the request*/

  str con;
  str d;

} coap_group_t;

/**
 * Deletes and endpoint.
 *
 * @param group The group to look for the endpoint and delete it.
 * @param endpoint Pointer to a previously created endpoint.
 *
 */
void
coap_delete_endpoint(coap_group_t *group, coap_endpoints_t *endpoint);

/**
 * Registers a new endpoint with the given @p group. As the
 * endpoint str fields will point to @p ep the
 * caller must ensure that this pointer is valid during the
 * endpoint's lifetime.
 *
 * @param group    The group to register the endpoint with.
 * @param ep       The endpoint's name.
 *
 * @return         A pointer to the new endpoint or @c NULL on error.
 */
coap_endpoints_t *
coap_add_endpoint(coap_group_t *group, 
	      const char *ep);
 
/**
 * Creates a new group object in the resource directory and initializes the URI path to the string
 * of length @p len. This function returns the new coap_group_t object.
 *
 * @param uri        The URI path of the new group.
 * @param len        The length of @p uri.
 * @param key_uri    The URI path of the identifier of the group.
 * @param key_len    The length of @p key_uri.
 * @param d	     The option d.
 * @param con	     The option con.
 * @param handler    The handler to delete the group later.
 *
 * @return       A pointer to the new object or @c NULL on error.
 */
coap_group_t *
coap_group_rd_init(const unsigned char *uri, size_t len, const unsigned char *key_uri, size_t key_len, str d, str con, coap_method_group_handler_t handler);

/**
 * Registers the given @p group for @p context. The group must have been
 * created by coap_group_rd_init(), the storage allocated for the group will
 * be released by coap_delete_group().
 *
 * @param context  The context to use.
 * @param group	   The group to store.
 */
void
coap_add_group(coap_context_t *context, coap_group_t *group);

/**
 * Deletes all the nodes of the group list. The storage allocated for the
 * list is freed.
 *
 * @param context  The context where the group are stored.
 *
 * @return         @c 1 if the group's list was found (and destroyed),
 *                 @c 0 otherwise.
 */
int
coap_delete_all_groups(coap_context_t *context);

/**
 * Deletes a group identified by @p key. The storage allocated for that
 * group is freed.
 *
 * @param context  The context where the group are stored.
 * @param key      The unique key for the group to delete.
 *
 * @return         @c 1 if the group was found (and destroyed),
 *                 @c 0 otherwise.
 */
int
coap_delete_group(coap_context_t *context, coap_key_t key);

/**
 * Deletes a group identified by @p group. The storage allocated for that
 * group is freed.
 *
 * @param group  The group to be freed.
 *
 */
void
coap_free_group(coap_group_t *group);

/**
 * Returns the group identified by the unique string @p key. If no group
 * was found, this function returns @c NULL.
 *
 * @param context  The context to look for this group.
 * @param key      The unique key of the group.
 *
 * @return         A pointer to the group or @c NULL if not found.
 */

coap_group_t *
coap_get_group_from_key(coap_context_t *context, coap_key_t key);


#ifdef COAP_RESOURCES_NOHASH

#define GROUP_ADD(g, obj) \
  LL_PREPEND((g), (obj))

#define GROUP_FIND(g, k, res) {                             \
    coap_group_t *tmp;                                      \
    (res) = tmp = NULL;                                     \
    LL_FOREACH((g), tmp) {                                  \
      if (memcmp((k), tmp->key, sizeof(coap_key_t)) == 0) { \
        (res) = tmp;                                        \
        break;                                              \
      }                                                     \
    }                                                       \
  }

#define GROUP_ITER(g,tmp) \
  coap_group_t *tmp;       \
  LL_FOREACH((g), tmp)

#define GROUP_DELETE(g, obj) \
  LL_DELETE((g), (obj))

#else /* COAP_RESOURCES_NOHASH */

#define GROUP_ADD(g, obj) \
  HASH_ADD(gh, (g), key, sizeof(coap_key_t), (obj))

#define GROUP_ITER(g,tmp)  \
  coap_group_t *tmp, *gtmp; \
  HASH_ITER(gh, (g), tmp, gtmp)

#define GROUP_DELETE(g, obj) \
  HASH_DELETE(gh, (g), (obj))

#define GROUP_FIND(g, k, res) {                     \
    HASH_FIND(gh, (g), (k), sizeof(coap_key_t), (res)); \
  }
#endif /* COAP_RESOURCES_NOHASH */

#endif /* _GROUP_H_ */
