/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 * -*- */

/* coap -- simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 *
 * Copyright (C) 2010--2016 Oscar Novo
 *
 * This file is part of the CoAP library libcoap. Please see README for terms of
 * use.
 */


/**
 * @file coap-rd.h
 * @brief CoRE resource directory
 *
 * @see http://tools.ietf.org/id/draft-shelby-core-resource-directory
 */

#ifndef _COAP_RD_H_
#define _COAP_RD_H_

#define BLOCK_ADD(b, obj)                     \
  LL_PREPEND((b), (obj))

#define BLOCK_DELETE(b, obj)                  \
  LL_DELETE((b), (obj))

#define BLOCK_FIND(b, k, res) {               \
    coap_block1_t *tmp;                       \
    (res) = tmp = NULL;                       \
    LL_FOREACH((b), tmp) {                    \
      if ((k) == (tmp->id + 1)) {             \
        (res) = tmp;                          \
        break;                                \
      }                                       \
    }                                         \
  }

typedef struct coap_variables_t {
/*Attribute parameters*/
  str d;  /*Domain name*/
  str ep; /*URI of End Point*/
  str gp; /*URI of End Point*/
  str et; /*EndPoint Type*/
/*Link parameters*/
  str href;	/*URI target of the link*/
  str rel;	/*relation type*/
  str rt;	/*Resource type*/
  str ifd;	/*Interface Description*/
  str ct;	/*Content Type*/
  str ins;	/*Resource Instance*/
  int exp; 	/*Export attribute*/
  str sem; /*Semantic ID*/

} coap_variables_t;

typedef enum { 
  D=1, 
  EP, 
  RES,
  GP
} Option_type;

typedef struct coap_block1_t {

  int id;                         /** id of the message */
  unsigned int num;               /** number of the block */
  unsigned int szx:3;             /**< block size */
  unsigned int m:1;               /**< 1 if more blocks follow, 0 otherwise */

  struct coap_block1_t *next;

  unsigned char *payload; /**< stores the payload of the message  */

} coap_block1_t;

#endif /* _COAP_RD_H_ */
