/*
 * lifetime.h -- DOuble Linked-list
 *
 * Copyright (C) Oscar Novo
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file lifetime.h
 * @brief Double Linked-list of the lifetime of every element
 */

#ifndef LIFETIME_H
#define LIFETIME_H

#include "resource.h"

typedef struct coap_lifetime_t {
    struct coap_resource_t *resource;	/* link to the resource */
    //unsigned long int time;	   /** lifetime of the resource **/
    time_t time;	           /** lifetime of the resource **/
    struct coap_lifetime_t *prev;  /* previous link */
    struct coap_lifetime_t *next;  /* next link */
} coap_lifetime_t;

coap_print_status_t coap_display_lifetime(coap_context_t *context, unsigned char *buf,
		size_t *buflen, size_t offset);

/* member functions */
/**
 * Create new linked-list
 *
 * @param context The context to use.
 *
 * @return returns 1 if the list could be initialized.
 *
 * @code
 *  coap_lifetime_init();
 * @endcode
 *
 */
extern int coap_lifetime_init(coap_context_t *context);

/**
 * coap_update_lifetime(): Updates an existing element in the lifetime list.
 *
 * @param context The context to use.
 *
 * @param resource  The resource to register the link.
 *
 * @param timeout  new time of the element.
 *
 * @return returns 1 if an element could be updated to the list.
 *
 */
int coap_update_lifetime(coap_context_t *context, coap_resource_t *resource, time_t timeout);

/**
 * coap_add_lifetime(): Insert a new element in the lifetime list sorted by time.
 *
 * @param context The context to use.
 *
 * @param resource  The resource to register the link.
 *
 * @param timeout  time to timeout the element.
 *
 * @return returns 1 if an element could be added to the lifetime list.
 *
 */
extern int coap_add_lifetime(coap_context_t *context, coap_resource_t *resource, time_t timeout);

/**
 * coap_delete_lifetime_node(): Delete a specific node from the lifetime list.
 *
 * @param context The context to use.
 *
 * @param lifetime The node to delete.
 *
 * @return 1 if the element has been deleted from the list, 0 otherwise. 
 *
 * @note
 *  This function can delete several elements at the same time.
 *  Careful! This function does ONLY delete the elements in the lifetime list but not the linked element in the resource list.
 */ 
extern int coap_delete_lifetime_node(coap_context_t *context, coap_lifetime_t *lifetime);
/**
 * coap_delete_lifetime(): Delete all the elements in the list with the especific time. This function deletes the 
 * elements in the lifetime list.
 *
 * @param context The context to use.
 *
 * @param key  The key of the resource to delete.
 *
 * @param timeout time.
 *
 * @return 1 if an element (or many elements) has been deleted from the list, 0 otherwise. 
 *
 * @note
 *  This function can delete several elements at the same time.
 *  Careful! This function does ONLY delete the elements in the lifetime list but not the linked element in the resource list.
 */ 
extern int coap_delete_lifetime(coap_context_t *context, coap_key_t key, time_t timeout);
/**
 * coap_timeout(): Delete all the elements in the lifetime list that timeout. This function deletes the 
 * elements in the lifetime list and the elements in the resource list.
 *
 * @param context The context to use.
 *
 * @param timeout timeout.
 *
 * @return 1 if an element (or many elements) has been deleted from the list, 0 otherwise. 
 *
 * @note
 *  This function can delete several elements at the same time.
 */ 
extern int coap_timeout(coap_context_t *context, time_t timeout);
/**
 * coap_delete_lifetime_list(): Delete all the elements in the list that timeout.
 *
 * @param context The context to use.
 *
 * @return 1 if list could be removed
 *
 * @note
 *  Careful! This function does ONLY delete the elements in the lifetime list but not the linked element in the resource list.
 */ 
extern int coap_delete_lifetime_list(coap_context_t *context);
/**
 * coap_count_nodes_lifetime(): Returns the number of elements in the list.
 *
 * @param context The context to use.
 *
 * @return returns the number of elements in the list. 
 *
 */ 
extern int coap_count_nodes_lifetime(coap_context_t *context);
/**
 * coap_lifetime_read_first(): Read the data of the first element in the list.
 *
 * @param context The context to use.
 *
 * @return data of the first element of the list.
 *
 */
extern unsigned long int coap_lifetime_read_first(coap_context_t *context);

#endif /* LIFETIME_H */

