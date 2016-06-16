/* resource.c -- generic resource handling
 *
 * Copyright (C) 2010--2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include "coap_config.h"
#include "coap.h"
#include "debug.h"
#include "mem.h"
#include "net.h"
#include "resource.h"
#include "subscribe.h"
#include "utlist.h"

#ifdef WITH_LWIP
/* mem.h is only needed for the string free calls for
 * COAP_ATTR_FLAGS_RELEASE_NAME / COAP_ATTR_FLAGS_RELEASE_VALUE /
 * COAP_RESOURCE_FLAGS_RELEASE_URI. not sure what those lines should actually
 * do on lwip. */

#include <lwip/memp.h>

#define COAP_MALLOC_TYPE(Type) \
  ((coap_##Type##_t *)memp_malloc(MEMP_COAP_##Type))
#define COAP_FREE_TYPE(Type, Object) memp_free(MEMP_COAP_##Type, Object)

#endif

#ifdef WITH_POSIX

#define COAP_MALLOC_TYPE(Type) \
  ((coap_##Type##_t *)coap_malloc(sizeof(coap_##Type##_t)))
#define COAP_FREE_TYPE(Type, Object) coap_free(Object)

#endif /* WITH_POSIX */
#ifdef WITH_CONTIKI
#include "memb.h"

#define COAP_MALLOC_TYPE(Type) \
  ((coap_##Type##_t *)memb_alloc(&(Type##_storage)))
#define COAP_FREE_TYPE(Type, Object) memb_free(&(Type##_storage), (Object))

MEMB(subscription_storage, coap_subscription_t, COAP_MAX_SUBSCRIBERS);

void
coap_resources_init() {
  memb_init(&subscription_storage);
}

static inline coap_subscription_t *
coap_malloc_subscription() {
  return memb_alloc(&subscription_storage);
}

static inline void
coap_free_subscription(coap_subscription_t *subscription) {
  memb_free(&subscription_storage, subscription);
}

#endif /* WITH_CONTIKI */

#define min(a,b) ((a) < (b) ? (a) : (b))

int
coap_match(const str *text, const str *pattern, int match_prefix, int match_substring) {
  assert(text); assert(pattern);
 
  if (text->length < pattern->length)
    return 0;
  if (match_substring) {
    unsigned char *next_token = text->s;
    size_t remaining_length = text->length;
    while (remaining_length) {
      size_t token_length;
      unsigned char *token = next_token;
      next_token = memchr(token, ' ', remaining_length);
      if (next_token) {
        token_length = next_token - token;
        remaining_length -= (token_length + 1);
        next_token++;
      } else {
        token_length = remaining_length;
        remaining_length = 0;
      }
      
      if ((match_prefix || pattern->length == token_length) &&
            memcmp(token, pattern->s, pattern->length) == 0)
        return 1;
    }
    return 0;
  }
  return (match_prefix || pattern->length == text->length) &&
    memcmp(text->s, pattern->s, pattern->length) == 0;
}

static coap_print_status_t
coap_print_link(const coap_resource_t *resource, 
		unsigned char *buf, size_t *len, size_t *offset) {
  unsigned char *p = buf;
  const unsigned char *bufend = buf + *len;
  coap_attr_t *attr;
  coap_print_status_t result = 0;
  const size_t old_offset = *offset;
  
  *len = 0;
  PRINT_COND_WITH_OFFSET(p, bufend, *offset, '<', *len);
  PRINT_COND_WITH_OFFSET(p, bufend, *offset, '/', *len);

  COPY_COND_WITH_OFFSET(p, bufend, *offset, 
			resource->uri.s, resource->uri.length, *len);
  
  PRINT_COND_WITH_OFFSET(p, bufend, *offset, '>', *len);

  LL_FOREACH(resource->link_attr, attr) {

    PRINT_COND_WITH_OFFSET(p, bufend, *offset, ';', *len);

    COPY_COND_WITH_OFFSET(p, bufend, *offset,
			  attr->name.s, attr->name.length, *len);

    if (attr->value.s) {
      PRINT_COND_WITH_OFFSET(p, bufend, *offset, '=', *len);

      COPY_COND_WITH_OFFSET(p, bufend, *offset,
			    attr->value.s, attr->value.length, *len);
    }

  }
  if (resource->observable) {
    COPY_COND_WITH_OFFSET(p, bufend, *offset, ";obs", 4, *len);
  }

  result = p - buf;
  if (result + old_offset - *offset < *len) {
    result |= COAP_PRINT_STATUS_TRUNC;
  }

  return result;
}

/** 
 * Discovers the information of the Resource Directory. The 
 * resource directory implementation supports query filtering 
 * for the rt parameter. The query filter might contain one or 
 * more of the values "core.rd", "core.rd-lookup", 
 * "core.rd-group" or "core.rd*".

 * This function sets @p buflen to the number of bytes actually 
 * written and returns * @c 1 on succes. On error, the value 
 * in @p buflen is undefined and the return value will be @c 0.
 * 
 * @param context The context with the resource map.
 * @param buf     The buffer to write the result.
 * @param buflen  Must be initialized to the maximum length of @p buf and will be
 *                set to the length of the well-known response on return.
 * @param offset  The offset in bytes where the output shall start and is
 *                shifted accordingly with the characters that have been
 *                processed. This parameter is used to support the block 
 *                option. 
 * @param query_filter A filter query according to <a href="http://tools.ietf.org/html/draft-ietf-core-link-format-11#section-4.1">Link Format</a>
 * 
 * @return COAP_PRINT_STATUS_ERROR on error. Otherwise, the lower 28 bits are
 *         set to the number of bytes that have actually been written to
 *         @p buf. COAP_PRINT_STATUS_TRUNC is set when the output has been
 *         truncated.
 */
#if defined(__GNUC__) && defined(WITHOUT_QUERY_FILTER)
coap_print_status_t
coap_print_wellknown_rd(coap_context_t *context, unsigned char *buf, size_t *buflen,
		size_t offset,
		coap_opt_t *query_filter __attribute__ ((unused))) {
#else /* not a GCC */
coap_print_status_t
coap_print_wellknown_rd(coap_context_t *context, unsigned char *buf, size_t *buflen,
		size_t offset, coap_opt_t *query_filter) {
#endif /* GCC */
  unsigned char *p = buf;
  const unsigned char *bufend = buf + *buflen;
  size_t left, written = 0;
  coap_print_status_t result;
  const size_t old_offset = offset;
  int subsequent_resource = 0;
#ifndef WITHOUT_QUERY_FILTER
  str resource_param = { 0, NULL }, query_pattern = { 8, (unsigned char *)"core.rd*" };
  int flags = 0; /* MATCH_PREFIX, MATCH_URI */
#define MATCH_URI       0x01
#define MATCH_PREFIX    0x02
#endif /* WITHOUT_QUERY_FILTER */

#ifndef WITHOUT_QUERY_FILTER
  /* split query filter, if any */
  if (query_filter) {

    resource_param.s = coap_opt_value(query_filter);
    while (resource_param.length < coap_opt_length(query_filter)
	   && resource_param.s[resource_param.length] != '=')
      resource_param.length++;

    if (resource_param.length < coap_opt_length(query_filter)) {

      if (resource_param.length == 2 && 
            memcmp(resource_param.s, "rt", 2) == 0) {
        flags |= MATCH_URI;
      } else {
        return 0;
      }

      /* rest is query-pattern */
      query_pattern.s = 
	coap_opt_value(query_filter) + resource_param.length + 1;

      assert((resource_param.length + 1) <= coap_opt_length(query_filter));
      query_pattern.length = 
	coap_opt_length(query_filter) - (resource_param.length + 1);
    }
  }
#endif /* WITHOUT_QUERY_FILTER */

  str unquoted_val;

  if (strstr((const char *)query_pattern.s, "core.rd") == NULL) return 0;

  RESOURCES_ITER(context->resources, r) {

    coap_attr_t *attr;
    attr = coap_find_attr(r, (const unsigned char *)"rt", 2);
    if (!attr) continue;
    if (attr->value.s[0] == '"') {          /* if attribute has a quoted value, remove double quotes */
      unquoted_val.length = attr->value.length - 2;
      unquoted_val.s = attr->value.s + 1;
    } else {
      unquoted_val = attr->value;
    }

    if (query_pattern.length && 
      query_pattern.s[query_pattern.length-1] == '*') {

      query_pattern.length--;
      flags |= MATCH_PREFIX;
    }

    if (!(coap_match(&unquoted_val, &query_pattern, 
      (flags & MATCH_PREFIX) != 0, 0)))
      continue;

    if (!subsequent_resource) {	/* this is the first resource  */
      subsequent_resource = 1;
    } else {
      PRINT_COND_WITH_OFFSET(p, bufend, offset, ',', written);
      PRINT_COND_WITH_OFFSET(p, bufend, offset, '\n', written);
    }

    left = bufend - p; /* calculate available space */
    result = coap_print_link(r, p, &left, &offset);

    if (result & COAP_PRINT_STATUS_ERROR) {
      break;
    }
 
    /* coap_print_link() returns the number of characters that
     * where actually written to p. Now advance to its end. */
    p += COAP_PRINT_OUTPUT_LENGTH(result);
    written += left;
  }

  *buflen = written;
  result = p - buf;
  if (result + old_offset - offset < *buflen) {
    result |= COAP_PRINT_STATUS_TRUNC;
  }
  return result;
}

/** 
 * Prints the names of all known resources to @p buf. This function
 * sets @p buflen to the number of bytes actually written and returns
 * @c 1 on succes. On error, the value in @p buflen is undefined and
 * the return value will be @c 0.
 * 
 * @param context The context with the resource map.
 * @param buf     The buffer to write the result.
 * @param buflen  Must be initialized to the maximum length of @p buf and will be
 *                set to the length of the well-known response on return.
 * @param offset  The offset in bytes where the output shall start and is
 *                shifted accordingly with the characters that have been
 *                processed. This parameter is used to support the block 
 *                option. 
 * @param query_filter A filter query according to <a href="http://tools.ietf.org/html/draft-ietf-core-link-format-11#section-4.1">Link Format</a>
 * 
 * @return COAP_PRINT_STATUS_ERROR on error. Otherwise, the lower 28 bits are
 *         set to the number of bytes that have actually been written to
 *         @p buf. COAP_PRINT_STATUS_TRUNC is set when the output has been
 *         truncated.
 */
#if defined(__GNUC__) && defined(WITHOUT_QUERY_FILTER)
coap_print_status_t
coap_print_wellknown(coap_context_t *context, unsigned char *buf, size_t *buflen,
		size_t offset,
		coap_opt_t *query_filter __attribute__ ((unused))) {
#else /* not a GCC */
coap_print_status_t
coap_print_wellknown(coap_context_t *context, unsigned char *buf, size_t *buflen,
		size_t offset, coap_opt_t *query_filter) {
#endif /* GCC */
  unsigned char *p = buf;
  const unsigned char *bufend = buf + *buflen;
  size_t left, written = 0;
  coap_print_status_t result;
  const size_t old_offset = offset;
  int subsequent_resource = 0;
#ifndef WITHOUT_QUERY_FILTER
  str resource_param = { 0, NULL }, query_pattern = { 0, NULL };
  int flags = 0; /* MATCH_SUBSTRING, MATCH_PREFIX, MATCH_URI */
#define MATCH_URI       0x01
#define MATCH_PREFIX    0x02
#define MATCH_SUBSTRING 0x04
  static const str _rt_attributes[] = {
    {2, (unsigned char *)"rt"},
    {2, (unsigned char *)"if"},
    {3, (unsigned char *)"rel"},
    {0, NULL}};
#endif /* WITHOUT_QUERY_FILTER */

#ifndef WITHOUT_QUERY_FILTER
  /* split query filter, if any */
  if (query_filter) {
    resource_param.s = COAP_OPT_VALUE(query_filter);
    while (resource_param.length < COAP_OPT_LENGTH(query_filter)
	   && resource_param.s[resource_param.length] != '=')
      resource_param.length++;
    
    if (resource_param.length < COAP_OPT_LENGTH(query_filter)) {
      const str *rt_attributes;
      if (resource_param.length == 4 && 
	  memcmp(resource_param.s, "href", 4) == 0)
	flags |= MATCH_URI;

      for (rt_attributes = _rt_attributes; rt_attributes->s; rt_attributes++) {
        if (resource_param.length == rt_attributes->length && 
            memcmp(resource_param.s, rt_attributes->s, rt_attributes->length) == 0) {
          flags |= MATCH_SUBSTRING;
          break;
        }
      }

      /* rest is query-pattern */
      query_pattern.s = 
	COAP_OPT_VALUE(query_filter) + resource_param.length + 1;

      assert((resource_param.length + 1) <= COAP_OPT_LENGTH(query_filter));
      query_pattern.length = 
	COAP_OPT_LENGTH(query_filter) - (resource_param.length + 1);

     if ((query_pattern.s[0] == '/') && ((flags & MATCH_URI) == MATCH_URI)) {
       query_pattern.s++;
       query_pattern.length--;
      }

      if (query_pattern.length && 
	  query_pattern.s[query_pattern.length-1] == '*') {
	query_pattern.length--;
	flags |= MATCH_PREFIX;
      }      
    }
  }
#endif /* WITHOUT_QUERY_FILTER */

  RESOURCES_ITER(context->resources, r) {

#ifndef WITHOUT_QUERY_FILTER
    if (resource_param.length) { /* there is a query filter */
      
      if (flags & MATCH_URI) {	/* match resource URI */
	if (!coap_match(&r->uri, &query_pattern, (flags & MATCH_PREFIX) != 0, (flags & MATCH_SUBSTRING) != 0))
	  continue;
      } else {			/* match attribute */
	coap_attr_t *attr;
        str unquoted_val;
	attr = coap_find_attr(r, resource_param.s, resource_param.length);
        if (!attr) continue;
        if (attr->value.s[0] == '"') {          /* if attribute has a quoted value, remove double quotes */
          unquoted_val.length = attr->value.length - 2;
          unquoted_val.s = attr->value.s + 1;
        } else {
          unquoted_val = attr->value;
        }
	if (!(coap_match(&unquoted_val, &query_pattern, 
                    (flags & MATCH_PREFIX) != 0,
                    (flags & MATCH_SUBSTRING) != 0)))
	  continue;
      }
    }
#endif /* WITHOUT_QUERY_FILTER */

    if (!subsequent_resource) {	/* this is the first resource  */
      subsequent_resource = 1;
    } else {
      PRINT_COND_WITH_OFFSET(p, bufend, offset, ',', written);
      PRINT_COND_WITH_OFFSET(p, bufend, offset, '\n', written);
    }

    left = bufend - p; /* calculate available space */
    result = coap_print_link(r, p, &left, &offset);

    if (result & COAP_PRINT_STATUS_ERROR) {
      break;
    }

    /* coap_print_link() returns the number of characters that
     * where actually written to p. Now advance to its end. */
    p += COAP_PRINT_OUTPUT_LENGTH(result);
    written += left;
  }

  *buflen = written;
  result = p - buf;
  if (result + old_offset - offset < *buflen) {
    result |= COAP_PRINT_STATUS_TRUNC;
  }
  return result;
}

coap_resource_t *
coap_resource_rd_init(const unsigned char *uri, size_t len, const unsigned char *key_uri, size_t key_len, int flags) {
  coap_resource_t *r;

#ifdef WITH_LWIP
  r = (coap_resource_t *)memp_malloc(MEMP_COAP_RESOURCE);
#endif
#ifndef WITH_LWIP
  r = (coap_resource_t *)coap_malloc_type(COAP_RESOURCE, sizeof(coap_resource_t));
#endif
  if (r) {
    memset(r, 0, sizeof(coap_resource_t));

    r->uri.s = (unsigned char *)uri;
    r->uri.length = len;
    
    coap_hash_path(key_uri, key_len, r->key);
    
    r->flags = flags;
  } else {
    debug("coap_resource_rd_init: no memory left\n");
  }
  
  return r;
}

coap_link_t *
coap_add_link(coap_resource_t *resource, 
	      const char *href, const char *ct, const char *rt, 
	      const char *ifd, const char *rel, const char *ins, 
              int exp) {

  coap_link_t *link;

  if (!resource || !href)
    return NULL;

#ifdef WITH_LWIP
  link = (coap_link_t *)memp_malloc(MEMP_COAP_RESOURCELINK);
#endif
#ifndef WITH_LWIP
  link = (coap_link_t *)coap_malloc_type(COAP_RESOURCELINK, sizeof(coap_link_t));
#endif

  if (link) {

    link->href.s = (unsigned char *)href;
    link->href.length = strlen(href);

    link->ct.s = (unsigned char *)ct;
    link->ct.length = ct ? strlen(ct) : 0;

    link->rt.s = (unsigned char *)rt;
    link->rt.length = rt ? strlen(rt) : 0;

    link->ifd.s = (unsigned char *)ifd;
    link->ifd.length = ifd ? strlen(ifd) : 0;

    link->rel.s = (unsigned char *)rel;
    link->rel.length = rel ? strlen(rel) : 0;

    link->ins.s = (unsigned char *)ins;
    link->ins.length = ins ? strlen(ins) : 0;

    link->exp = exp;

    /* add link to resource list */
    LL_PREPEND(resource->links, link);
  } else {
    debug("coap_add_link: no memory left\n");
  }
  
  return link;
}

coap_link_t *
coap_find_link(coap_resource_t *resource, 
	       const char *href, size_t nlen) {
  coap_link_t *link;

  if (!resource || !href)
    return NULL;

  LL_FOREACH(resource->links, link) {
    if (link->href.length == nlen &&
	memcmp(link->href.s, href, nlen) == 0)
      return link;
  }

  return NULL;
}

void
coap_delete_link(coap_resource_t *resource, coap_link_t *link) {
  if (!link)
    return;

  if (link->href.s){
    coap_free(link->href.s);
  }

  if (link->ct.s){
    coap_free(link->ct.s);
  }

  if (link->rt.s){
    coap_free(link->rt.s);
  }

  if (link->ifd.s){
    coap_free(link->ifd.s);
  }

  if (link->rel.s){
    coap_free(link->rel.s);
  }

  if (link->ins.s){
    coap_free(link->ins.s);
  }

  LL_DELETE(resource->links,link);

#ifdef WITH_LWIP
  memp_free(MEMP_COAP_RESOURCELINK, link);
#endif
#ifndef WITH_LWIP
  coap_free_type(COAP_RESOURCELINK, link);
#endif
}

coap_resource_t *
coap_resource_init(const unsigned char *uri, size_t len, int flags) {
  coap_resource_t *r;

#ifdef WITH_LWIP
  r = (coap_resource_t *)memp_malloc(MEMP_COAP_RESOURCE);
#endif
#ifndef WITH_LWIP
  r = (coap_resource_t *)coap_malloc_type(COAP_RESOURCE, sizeof(coap_resource_t));
#endif
  if (r) {
    memset(r, 0, sizeof(coap_resource_t));

    r->uri.s = (unsigned char *)uri;
    r->uri.length = len;
    
    coap_hash_path(r->uri.s, r->uri.length, r->key);

    r->flags = flags;
  } else {
    debug("coap_resource_init: no memory left\n");
  }
  
  return r;
}

/*void
coap_add_lifetime(coap_resource_t *resource, 
              unsigned long time_sec) {

  if (!resource)
    return;
*/
  /* Current time in seconds */
/*  time_t sec = time(0);

  sec = sec + (time_t)time_sec;

  resource->lifetime = sec;

}*/

coap_attr_t *
coap_add_attr(coap_resource_t *resource, 
	      const unsigned char *name, size_t nlen,
	      const unsigned char *val, size_t vlen,
              int flags) {
  coap_attr_t *attr;

  if (!resource || !name)
    return NULL;

#ifdef WITH_LWIP
  attr = (coap_attr_t *)memp_malloc(MEMP_COAP_RESOURCEATTR);
#endif
#ifndef WITH_LWIP
  attr = (coap_attr_t *)coap_malloc_type(COAP_RESOURCEATTR, sizeof(coap_attr_t));
#endif

  if (attr) {
    attr->name.length = nlen;
    attr->value.length = val ? vlen : 0;

    attr->name.s = (unsigned char *)name;
    attr->value.s = (unsigned char *)val;

    attr->flags = flags;

    /* add attribute to resource list */
    LL_PREPEND(resource->link_attr, attr);
  } else {
    debug("coap_add_attr: no memory left\n");
  }
  
  return attr;
}

coap_attr_t *
coap_find_attr(coap_resource_t *resource, 
	       const unsigned char *name, size_t nlen) {
  coap_attr_t *attr;

  if (!resource || !name)
    return NULL;

  LL_FOREACH(resource->link_attr, attr) {
    if (attr->name.length == nlen &&
	memcmp(attr->name.s, name, nlen) == 0)
      return attr;
  }

  return NULL;
}

void
coap_delete_attr(coap_resource_t *resource, coap_attr_t *attr) {
  if (!attr)
    return;

  if (attr->flags & COAP_ATTR_FLAGS_RELEASE_NAME)
    coap_free(attr->name.s);

  if (attr->flags & COAP_ATTR_FLAGS_RELEASE_VALUE)
    coap_free(attr->value.s);

  LL_DELETE(resource->link_attr, attr);

#ifdef WITH_LWIP
  memp_free(MEMP_COAP_RESOURCEATTR, attr);
#endif
#ifndef WITH_LWIP
  coap_free_type(COAP_RESOURCEATTR, attr);
#endif
}

void
coap_hash_request_uri(const coap_pdu_t *request, coap_key_t key) {
  coap_opt_iterator_t opt_iter;
  coap_opt_filter_t filter;
  coap_opt_t *option;

  memset(key, 0, sizeof(coap_key_t));

  coap_option_filter_clear(filter);
  coap_option_setb(filter, COAP_OPTION_URI_PATH);

  coap_option_iterator_init((coap_pdu_t *)request, &opt_iter, filter);
  while ((option = coap_option_next(&opt_iter))){
    coap_hash(COAP_OPT_VALUE(option), COAP_OPT_LENGTH(option), key);

    if (strncmp((const char *)coap_opt_value(option), "rd-lookup", 9) == 0){
      return;
    }
  }
}

void
coap_add_resource(coap_context_t *context, coap_resource_t *resource) {
  RESOURCES_ADD(context->resources, resource);
}

void
coap_free_resource(coap_resource_t *resource) {
  coap_attr_t *attr, *tmp;
  coap_subscription_t *obs, *otmp;
  coap_link_t *link, *link_tmp;

  assert(resource);

  /* delete registered attributes */
  LL_FOREACH_SAFE(resource->link_attr, attr, tmp) coap_delete_attr(resource, attr);

  /* delete registered links */
  LL_FOREACH_SAFE(resource->links, link, link_tmp) coap_delete_link(resource, link);

  if (resource->flags & COAP_RESOURCE_FLAGS_RELEASE_URI)
    coap_free(resource->uri.s);

  /*release the IP information*/
  if (resource->A.s!=NULL)
    coap_free(resource->A.s);

  /* free all elements from resource->subscribers */
  LL_FOREACH_SAFE(resource->subscribers, obs, otmp) COAP_FREE_TYPE(subscription, obs);

#ifdef WITH_LWIP
  memp_free(MEMP_COAP_RESOURCE, resource);
#endif
#ifndef WITH_LWIP
  coap_free_type(COAP_RESOURCE, resource);
#endif /* WITH_CONTIKI */
}
 
int
coap_delete_resource(coap_context_t *context, coap_key_t key) {
  coap_resource_t *resource;

  if (!context)
    return 0;

  resource = coap_get_resource_from_key(context, key);

  if (!resource) 
    return 0;

  /* remove resource from list */
  RESOURCES_DELETE(context->resources, resource);

  /* remove the resource from the lifetime list too */
  if (resource->lifetime)
    coap_delete_lifetime_node(context, resource->lifetime);

  /* and free its allocated memory */
  coap_free_resource(resource);

  return 1;
}

void
coap_delete_all_resources(coap_context_t *context) {
  coap_resource_t *res;
  coap_resource_t *rtmp;

  /* Cannot call RESOURCES_ITER because coap_free_resource() releases
   * the allocated storage. */

#ifdef COAP_RESOURCES_NOHASH
  LL_FOREACH_SAFE(context->resources, res, rtmp) {
#else
  HASH_ITER(hh, context->resources, res, rtmp) {
    HASH_DELETE(hh, context->resources, res);
#endif
    coap_free_resource(res);
  }

  context->resources = NULL;
}

coap_key_t *
coap_build_key_for_resource(str ep, unsigned char *root, int KEYSIZE) {

  unsigned int *int_ep_key;
  coap_key_t ep_key = {0};
  char ep_key_str[16] = {0};
  size_t ep_size, key_size;
  coap_key_t *resource_key = malloc (sizeof(coap_key_t));
  size_t loc_size = strlen((const char *)root);

  memset(resource_key, 0, sizeof(coap_key_t));

  /* create a key from the ep node */
  ep_size = min(ep.length, KEYSIZE - loc_size - 1);
  coap_hash_path(ep.s, ep_size, ep_key);

  /* translate the key into a string */
  int_ep_key = (void *)(&ep_key);
  snprintf(ep_key_str, 16, "%u", *int_ep_key);

  /* rd/ep_key_str */
  memcpy(root + loc_size, ep_key_str, min(strlen(ep_key_str), KEYSIZE - loc_size - 1));
  key_size = min(strlen(ep_key_str), KEYSIZE - loc_size - 1) + loc_size;

  root[key_size] = '\0';

  /* create the final key of rd/ep_key_str. We will send rd/ep_key_str to the client */
  coap_hash_path(root, key_size, (unsigned char *)resource_key);

  return resource_key;
}

coap_resource_t *
coap_get_resource_from_key(coap_context_t *context, coap_key_t key) {
  coap_resource_t *result;

  RESOURCES_FIND(context->resources, key, result);

  return result;
}


unsigned char *
coap_print_sequence_links(coap_link_t *link, unsigned char *buf, const unsigned char *bufend, size_t *len, size_t *offset){

    PRINT_COND_WITH_OFFSET(buf, bufend, *offset, '\n', *len);

    if (link->href.s) {
      	COPY_COND_WITH_OFFSET(buf, bufend, *offset,
		  	  link->href.s, link->href.length, *len);
    }

    if (link->ct.s) {
	COPY_COND_WITH_OFFSET(buf, bufend, *offset, ";ct=", 4, *len);
    	COPY_COND_WITH_OFFSET(buf, bufend, *offset,
			  link->ct.s, link->ct.length, *len);
    }

    if (link->rt.s) {
	COPY_COND_WITH_OFFSET(buf, bufend, *offset, ";rt=", 4, *len);
    	COPY_COND_WITH_OFFSET(buf, bufend, *offset,
			  link->rt.s, link->rt.length, *len);
    }

    if (link->ifd.s) {
        COPY_COND_WITH_OFFSET(buf, bufend, *offset, ";if=", 4, *len);
    	COPY_COND_WITH_OFFSET(buf, bufend, *offset,
			  link->ifd.s, link->ifd.length, *len);
    }

    if (link->rel.s) {
        COPY_COND_WITH_OFFSET(buf, bufend, *offset, ";rel=", 5, *len);
    	COPY_COND_WITH_OFFSET(buf, bufend, *offset,
			  link->rel.s, link->rel.length, *len);
    }

    if (link->ins.s) {
        COPY_COND_WITH_OFFSET(buf, bufend, *offset, ";ins=", 5, *len);
    	COPY_COND_WITH_OFFSET(buf, bufend, *offset,
			  link->ins.s, link->ins.length, *len);
    }

    if (link->exp) {
        COPY_COND_WITH_OFFSET(buf, bufend, *offset, ";exp", 4, *len);
    }

  return buf;

}

#ifndef WITHOUT_OBSERVE
coap_subscription_t *
coap_find_observer(coap_resource_t *resource, const coap_address_t *peer,
		     const str *token) {
  coap_subscription_t *s;

  assert(resource);
  assert(peer);

  LL_FOREACH(resource->subscribers, s) {
    if (coap_address_equals(&s->subscriber, peer)
	&& (!token || (token->length == s->token_length 
		       && memcmp(token->s, s->token, token->length) == 0)))
      return s;
  }
  
  return NULL;
}

coap_subscription_t *
coap_add_observer(coap_resource_t *resource, 
		  const coap_endpoint_t *local_interface,
		  const coap_address_t *observer,
		  const str *token) {
  coap_subscription_t *s;
  
  assert(observer);

  /* Check if there is already a subscription for this peer. */
  s = coap_find_observer(resource, observer, token);

  /* We are done if subscription was found. */
  if (s)
    return s;

  /* s points to a different subscription, so we have to create
   * another one. */
  s = COAP_MALLOC_TYPE(subscription);

  if (!s)
    return NULL;

  coap_subscription_init(s);
  s->local_if = *local_interface;
  memcpy(&s->subscriber, observer, sizeof(coap_address_t));
  
  if (token && token->length) {
    s->token_length = token->length;
    memcpy(s->token, token->s, min(s->token_length, 8));
  }

  /* add subscriber to resource */
  LL_PREPEND(resource->subscribers, s);

  return s;
}

void
coap_touch_observer(coap_context_t *context, const coap_address_t *observer,
		    const str *token) {
  coap_subscription_t *s;

  RESOURCES_ITER(context->resources, r) {
    s = coap_find_observer(r, observer, token);
    if (s) {
      s->fail_cnt = 0;
    }
  }
}

int
coap_delete_observer(coap_resource_t *resource, const coap_address_t *observer,
		     const str *token) {
  coap_subscription_t *s;

  s = coap_find_observer(resource, observer, token);

  if (resource->subscribers && s) {
    LL_DELETE(resource->subscribers, s);

    COAP_FREE_TYPE(subscription,s);
  }

  return s != NULL;
}

static void
coap_notify_observers(coap_context_t *context, coap_resource_t *r) {
  coap_method_handler_t h;
  coap_subscription_t *obs;
  str token;
  coap_pdu_t *response;

  if (r->observable && (r->dirty || r->partiallydirty)) {
    r->partiallydirty = 0;

    /* retrieve GET handler, prepare response */
    h = r->handler[COAP_REQUEST_GET - 1];
    assert(h);		/* we do not allow subscriptions if no
			 * GET handler is defined */

    LL_FOREACH(r->subscribers, obs) {
      if (r->dirty == 0 && obs->dirty == 0)
        /* running this resource due to partiallydirty, but this observation's notification was already enqueued */
        continue;

      coap_tid_t tid = COAP_INVALID_TID;
      obs->dirty = 0;
      /* initialize response */
      response = coap_pdu_init(COAP_MESSAGE_CON, 0, 0, COAP_MAX_PDU_SIZE);
      if (!response) {
        obs->dirty = 1;
        r->partiallydirty = 1;
	debug("coap_check_notify: pdu init failed, resource stays partially dirty\n");
	continue;
      }

      if (!coap_add_token(response, obs->token_length, obs->token)) {
        obs->dirty = 1;
        r->partiallydirty = 1;
	debug("coap_check_notify: cannot add token, resource stays partially dirty\n");
	coap_delete_pdu(response);
	continue;
      }

      token.length = obs->token_length;
      token.s = obs->token;

      response->hdr->id = coap_new_message_id(context);
      if ((r->flags & COAP_RESOURCE_FLAGS_NOTIFY_CON) == 0
	  && obs->non_cnt < COAP_OBS_MAX_NON) {
	response->hdr->type = COAP_MESSAGE_NON;
      } else {
	response->hdr->type = COAP_MESSAGE_CON;
      }
      /* fill with observer-specific data */
      h(context, r, &obs->local_if, &obs->subscriber, NULL, &token, response);

      /* TODO: do not send response and remove observer when 
       *  COAP_RESPONSE_CLASS(response->hdr->code) > 2
       */
      if (response->hdr->type == COAP_MESSAGE_CON) {
	tid = coap_send_confirmed(context, &obs->local_if, &obs->subscriber, response);
	obs->non_cnt = 0;
      } else {
	tid = coap_send(context, &obs->local_if, &obs->subscriber, response);
	obs->non_cnt++;
      }

      if (COAP_INVALID_TID == tid || response->hdr->type != COAP_MESSAGE_CON)
	coap_delete_pdu(response);
      if (COAP_INVALID_TID == tid)
      {
	debug("coap_check_notify: sending failed, resource stays partially dirty\n");
        obs->dirty = 1;
        r->partiallydirty = 1;
      }

    }

    /* Increment value for next Observe use. */
    context->observe++;
  }
  r->dirty = 0;
}

void
coap_check_notify(coap_context_t *context) {

  RESOURCES_ITER(context->resources, r) {
    coap_notify_observers(context, r);
  }
}

/**
 * Checks the failure counter for (peer, token) and removes peer from
 * the list of observers for the given resource when COAP_OBS_MAX_FAIL
 * is reached.
 *
 * @param context  The CoAP context to use
 * @param resource The resource to check for (peer, token)
 * @param peer     The observer's address
 * @param token    The token that has been used for subscription.
 */
static void
coap_remove_failed_observers(coap_context_t *context,
			     coap_resource_t *resource,
			     const coap_address_t *peer,
			     const str *token) {
  coap_subscription_t *obs, *otmp;

  LL_FOREACH_SAFE(resource->subscribers, obs, otmp) {
    if (coap_address_equals(peer, &obs->subscriber) &&
	token->length == obs->token_length &&
	memcmp(token->s, obs->token, token->length) == 0) {
      
      /* count failed notifies and remove when
       * COAP_MAX_FAILED_NOTIFY is reached */
      if (obs->fail_cnt < COAP_OBS_MAX_FAIL)
	obs->fail_cnt++;
      else {
	LL_DELETE(resource->subscribers, obs);
	obs->fail_cnt = 0;
	
#ifndef NDEBUG
	if (LOG_DEBUG <= coap_get_log_level()) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
	  unsigned char addr[INET6_ADDRSTRLEN+8];

	  if (coap_print_addr(&obs->subscriber, addr, INET6_ADDRSTRLEN+8))
	    debug("** removed observer %s\n", addr);
	}
#endif
	coap_cancel_all_messages(context, &obs->subscriber, 
				 obs->token, obs->token_length);

	COAP_FREE_TYPE(subscription, obs);
      }
    }
    break;			/* break loop if observer was found */
  }
}

void
coap_handle_failed_notify(coap_context_t *context, 
			  const coap_address_t *peer, 
			  const str *token) {

  RESOURCES_ITER(context->resources, r) {
	coap_remove_failed_observers(context, r, peer, token);
  }
}
#endif /* WITHOUT_NOTIFY */
