/** @file lifetime.c -- Double Linked-list implementation.
 *
 * Copyright (C) Oscar Novo
 *
 * This file is part of the CoAP library libcoap. Please see README for terms of
 * use.
 *
 *
 */

#include <stdio.h>
#include "lifetime.h"
#include "utlist.h"
#include "mem.h"

coap_print_status_t coap_display_lifetime(coap_context_t *context, unsigned char *buf,
		size_t *buflen, size_t offset){

  unsigned char *p = buf;
  const unsigned char *bufend = buf + *buflen;
  size_t left, written = 0;
  int subsequent_resource = 0;
  coap_print_status_t result = NULL;
  const size_t old_offset = offset;
  coap_lifetime_t *r;

  DL_FOREACH(context->lifetime, r) {

    if (!subsequent_resource) {	
      subsequent_resource = 1;
    } else {
      PRINT_COND_WITH_OFFSET(p, bufend, offset, ',', written);
      PRINT_COND_WITH_OFFSET(p, bufend, offset, '\n', written);
    }

    left = bufend - p; 

    if(r->time){
      char buffer[11];

      /* Current time in seconds */
      time_t sec = time(0);

      if(sec>r->time){
        COPY_COND_WITH_OFFSET(p, bufend, offset, "(timeout)", 9, written);
        sec = sec - (time_t)r->time;
      } else {
        sec = (time_t)r->time - sec;
      }

      snprintf(buffer, 11, "%zu", sec);

      COPY_COND_WITH_OFFSET(p, bufend, offset, "lt=", 3, written);
      COPY_COND_WITH_OFFSET(p, bufend, offset, buffer, strlen(buffer), written);
      COPY_COND_WITH_OFFSET(p, bufend, offset, ";", 1, written);
    }

    if (result & COAP_PRINT_STATUS_ERROR) {
      break;
    }
 
    p += COAP_PRINT_OUTPUT_LENGTH(result);
    written += left;
  }


  // END - Print Group Info //
  *buflen = written;
  result = p - buf;
  if (result + old_offset - offset < *buflen) {
    result |= COAP_PRINT_STATUS_TRUNC;
  }

  return result;
}


 
int coap_lifetime_init(coap_context_t *context){

  if (!context)
    return 0;

  context -> lifetime =NULL;

  return 1;
}

static void
coap_free_lifetime(coap_context_t *context, coap_lifetime_t *lifetime) {

  if (!lifetime)
    return;

  if (!context)
    return;

  /* and free the resource too */
  if (lifetime -> resource) {
    lifetime ->resource->lifetime = NULL;
    coap_delete_resource(context, lifetime -> resource -> key);
    lifetime -> resource = NULL;
  }

#ifdef WITH_LWIP
  memp_free(MEMP_COAP_LIFETIME, lifetime);
#endif
#ifndef WITH_LWIP
  coap_free_type(COAP_LIFETIME, lifetime);
#endif /* WITH_CONTIKI */

}

unsigned long int coap_lifetime_read_first(coap_context_t *context){
  coap_lifetime_t *r=NULL;

  if (!context)
    return 0;

  r = context -> lifetime;
  if(r==NULL){
    return 0;
  }else {
    return(r->time);
  }
}

int coap_update_lifetime(coap_context_t *context, coap_resource_t *resource, time_t timeout)
{

  if (!context)
    return 0;

  if (!resource)
    return 0;

  if (!resource->key)
    return 0;

  if (!resource->lifetime)
    return 0;

  if (!coap_delete_lifetime_node(context, resource->lifetime)) return 0;

  if (!coap_add_lifetime(context, resource, timeout)) return 0;

  return 1;

}

int coap_add_lifetime(coap_context_t *context, coap_resource_t *resource, time_t timeout)
{

  coap_lifetime_t *n_temp=NULL, *elt=NULL, *elt_tmp=NULL;
  int c = 0;

  if (!context)
    return 0;

  if (!resource)
    return 0;

#ifdef WITH_LWIP
  n_temp = (coap_lifetime_t *)memp_malloc(MEMP_COAP_LIFETIME);
#endif
#ifndef WITH_LWIP
  n_temp = (coap_lifetime_t *)coap_malloc_type(COAP_LIFETIME, sizeof(coap_lifetime_t));
#endif

  if (!n_temp)
    return 0;

  /* Current time in seconds */
  time_t sec = time(0);
  sec = sec + (time_t)timeout;

  n_temp->time=sec;
  n_temp->resource=resource;
  n_temp->next = NULL;
  n_temp->prev = NULL;

  if(context->lifetime==NULL) {
    DL_PREPEND(context->lifetime, n_temp);
  }else{
    DL_FOREACH(context->lifetime,elt) {
      if (timeout >(elt->time)) {
        elt_tmp=elt;
        c++;
      } else {
        break;
      }
    }

    if(c==0){
      DL_PREPEND_ELEM(context->lifetime, elt_tmp,n_temp);
    } else {
      DL_APPEND_ELEM(context->lifetime, elt_tmp,n_temp);
    }

  }

  /* Add the link from the resource node to the lifetime node */
  resource->lifetime = n_temp;

  return 1;

}

int coap_delete_lifetime_node(coap_context_t *context, coap_lifetime_t *lifetime)
{

  if (!context)
    return 0;

  if (!lifetime)
    return 0;

  /* remove node from list */
  DL_DELETE(context->lifetime,lifetime);

  /* put the resource pointer to NULL because this operation
     does not removed the resource*/
  lifetime-> resource = NULL;

  /* and free its allocated memory */
  coap_free_lifetime(context, lifetime);

  return 1;
}

int coap_delete_lifetime(coap_context_t *context, coap_key_t key, time_t timeout)
{
  coap_lifetime_t *elt=NULL, *tmp=NULL;
  int found = 0;

  if (!context)
    return 0;

  if (!key)
    return 0;

  DL_FOREACH_SAFE(context->lifetime,elt, tmp)
  {
    if(elt->time==timeout)
    {
      if ((elt->resource) && (elt->resource->key)){
        if (elt->resource->key == key){

          if (!coap_delete_lifetime_node(context, elt)) return 0;

          found = 1;
        }
      }
    }

    if(elt->time>timeout){
      return found;
    }
  }
  return found;
}


int coap_delete_lifetime_list(coap_context_t *context) {

  coap_lifetime_t *elt=NULL, *tmp=NULL;

  if (!context)
    return 0;

  DL_FOREACH_SAFE(context->lifetime,elt,tmp){
    /* remove node from list */
    DL_DELETE(context->lifetime,elt);

    /* put the resource pointer to NULL because this operation
       does not removed the resource*/
    elt-> resource = NULL;

    /* and free its allocated memory */
    coap_free_lifetime(context, elt);
  }

  context -> lifetime = NULL;
  
  return 1;

}


int coap_timeout(coap_context_t *context, time_t timeout)
{
  coap_lifetime_t *elt=NULL, *tmp=NULL;
  int found = 0;

  if (!context)
    return 0;

  DL_FOREACH_SAFE(context->lifetime,elt, tmp){
    if(elt->time<=timeout){

        /* remove node from list */
        DL_DELETE(context->lifetime,elt);

        /* and free its allocated memory */
        coap_free_lifetime(context, elt);

        found = 1;

    } else if (elt->time>timeout){
      return found;
    } 
  }
  return found;
}
 

int coap_count_nodes_lifetime(coap_context_t *context)
{
  int count=0;
  coap_lifetime_t *elt=NULL;

  if (!context)
    return 0;

  DL_COUNT(context->lifetime,elt,count);

  return count;
}
