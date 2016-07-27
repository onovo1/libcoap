/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 * -*- */

/* coap -- simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 *
 * Copyright (C) 2010--2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms of
 * use.
 */


/**
 * @file rd.c
 * @brief CoRE resource directory
 *
 * @see http://tools.ietf.org/id/draft-shelby-core-resource-directory
 */

#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>

#include "coap_config.h"
#include "coap.h"
#include "coap_rd.h"
#include "group.h"

#include "coap_list.h"
#include "utlist.h"
#include "lifetime.h"
#include "pcp_client.h"

//TODO file included only for testing proposed
//#include "rd_list_elements.h"

#include "mjson.h"
#include <errno.h>

#include <net/if.h>
#include <sys/ioctl.h>

#define COAP_RESOURCE_CHECK_TIME 2

#define MAX_JSON_LINKS 72
#define MAX_LENGTH_LINK_CHAR 64

#define RD_ROOT_STR   ((unsigned char *)"rd")
#define RD_ROOT_SIZE  2

#define RD_LOOKUP_STR   ((unsigned char *)"rd-lookup")
#define RD_LOOKUP_SIZE  9

#define RD_GROUP_STR   ((unsigned char *)"rd-group")
#define RD_GROUP_SIZE  8

#define LOCSIZE 68

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

coap_block1_t *blocks = NULL; /* Pointer to the blockwise structure */

unsigned int wait_seconds = 90;         /* default timeout in seconds */
coap_tick_t max_wait;                   /* global timeout (changed by set_timeout()) */

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

/* temporary storage for dynamic resource representations */
static int quit = 0;

static const char *configfile = "./pcp.conf";
static const char *configfile_ = "../pcp.conf";
char pcp_server[128], external_interface[20];
int pcp_internal_port = 5683;
int pcp_nat = 0;
int portnum = 1024;


uint8_t *temp_nonce[PCP_NONCE_SZ]; /** Mapping Nonce  **/ 
int nonce_initialize = 0;


/**********************************************************/
/***                    UTILS FUNTIONS                  ***/
/**********************************************************/

static void upload_config_file(void){

  FILE *fp;
  char buff[256];
  char name[80];

  /* configuration file */
  if(((fp = fopen(configfile, "r")) == NULL) && ((fp = fopen(configfile_, "r")) == NULL)) {
    fprintf(stderr, "error loading configuration: %s\n", configfile);
        exit(1);
  }

  /* Read next line */
  while ((fgets (buff, sizeof buff, fp)) != NULL)
  {
    /* Skip blank lines and comments */
    if (buff[0] == '\n' || buff[0] == '#')
      continue;

    if (strstr(buff, "NAT"))
      sscanf(buff, "%s %d\n", name, &pcp_nat);
    /* Parse name/value pair from line */
    if (strstr(buff, "pcp_server_listen"))
      sscanf(buff, "%s %s\n", name, pcp_server);
    else if (strstr(buff, "internal_port"))
      sscanf(buff, "%s %d\n", name, &pcp_internal_port);
    else if (strstr(buff, "external_interface"))
      sscanf(buff, "%s %s\n", name, external_interface);
  }
  fclose (fp);
  return;

}

static unsigned char* concat(unsigned char *s1, unsigned char *s2)
{
    size_t len1 = strlen((char *)s1), len2 = strlen((char *)s2);

    unsigned char *result = coap_malloc(len1+len2+1);//+1 for the zero-terminator
    if (!result) return NULL;

    memcpy(result, s1, len1);
    memcpy(result+len1, s2, len2+1);//+1 to copy the null-terminator
    return result;
}

static int find_port(int fd_rd, char *ext_int){

  struct hostent *server;
  struct sockaddr_in serv_addr;
  int max_num_ports = 64511; //max number of available ports 65535-1024
  int i;

  /* Find a port for the external interface */
  server = gethostbyname(ext_int);
 
  if (server == NULL) {
    debug("find_port, no such host\n");
    return -1;
  }
 
  bzero((char *) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  bcopy((char *)server->h_addr,
       (char *)&serv_addr.sin_addr.s_addr,
       server->h_length);
 
  portnum = portnum + 1;
  serv_addr.sin_port = htons(portnum);

  for (i=0; i<max_num_ports;i++){

    if (connect(fd_rd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0){

      if (portnum >= 65535){
        portnum = 1025;
      } else {
        portnum = portnum + 1;
      }

      serv_addr.sin_port = htons(portnum);
    } else {
      break;
    }

  }


  if (i == max_num_ports){
    debug("find_port, all ports are taken\n");
    return -1;
  }

  return 0;
}

static int add_NAT_rule(coap_resource_t *r, uint32_t lifetime, char *thrd_part, char *ext_addr_NAT, time_t sec){

  int fd_rd, err=0;
  struct ifreq ifr;
  char *ext_int, *ext_addr=NULL;
  char str[7];
  int len1;

  fd_rd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd_rd < 0) {
    debug("add_NAT_rule, ERROR opening socket\n");
    return 2;
  }

  /* Get an IPv4 IP address */
  ifr.ifr_addr.sa_family = AF_INET;

  /* IP address attached to "external_interface" */
  strncpy(ifr.ifr_name, external_interface, IFNAMSIZ-1);

  ioctl(fd_rd, SIOCGIFADDR, &ifr);

  ext_int = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

  if (lifetime == 0){
    // delete a mapping

    err = coap_create_map_rule(pcp_server, 0, ext_addr_NAT, pcp_internal_port, thrd_part);

//  coap_create_map_rule("10.0.0.210:5351", 7200, "10.0.0.210:3000", 5683, "192.168.0.2");
//  coap_create_map_rule(char *pcp_srv, uint32_t lifetime, char *ext_addr, int int_port, char *thrd_part){

  } else {
    // add o refresh a mapping

    if (ext_addr_NAT == NULL){
      // add mapping

      if (find_port(fd_rd, ext_int)==0){
        //convert port to string
        sprintf(str, ":%d", portnum);

        ext_addr = (char*)concat((unsigned char*)ext_int, (unsigned char*)str);
        if (ext_addr == NULL) return 2;

        err = coap_create_map_rule(pcp_server, lifetime, ext_addr, pcp_internal_port, thrd_part);

        if (r->NAT.s!=NULL)
           coap_free(r->NAT.s);

        if (err==0){
          r->NAT.s= (unsigned char *)ext_addr;
          r->NAT.length= strlen(ext_addr);
          r->NAT_lifetime= sec;
        } else {
          r->NAT.s= NULL;
          r->NAT.length= 0;
          r->NAT_lifetime= 0;
          coap_free(ext_addr);
        }
      }

    } else {
    // refresh mapping

      len1 = strlen((char *)ext_addr_NAT);

      ext_addr = (char *) coap_malloc(len1 +1);//+1 for the zero-terminator
      if (!ext_addr) return 2;

      memcpy(ext_addr, ext_addr_NAT, len1+1);//+1 to copy the null-terminator

      //First delete the previous mapping before adding the new one
      err = coap_create_map_rule(pcp_server, 0, ext_addr, pcp_internal_port, thrd_part);

      err = coap_create_map_rule(pcp_server, lifetime, ext_addr, pcp_internal_port, thrd_part);

      if (r->NAT.s!=NULL)
        coap_free(r->NAT.s);

      if (err==0){
        r->NAT.s= (unsigned char *)ext_addr;
        r->NAT.length= strlen(ext_addr);
        r->NAT_lifetime= sec;
      } else {
          r->NAT.s= NULL;
          r->NAT.length= 0;
          r->NAT_lifetime= 0;
          coap_free(ext_addr);
        }
    }
  }

  close(fd_rd);

  return(err);
  
}

static inline void
set_timeout(coap_tick_t *timer, const unsigned int seconds) {
  coap_ticks(timer);
  *timer += seconds * COAP_TICKS_PER_SECOND;
}

/* SIGINT handler: set quit to 1 for graceful termination */
static void
handle_sigint(int signum UNUSED_PARAM) {

  if (pcp_nat)
	  re_cancel();

  quit = 1;

}

// Remove the spaces and stores the trimmed input string into an output buffer
static char * trimwhitespace(char *str)
{
  const char *end;
  size_t out_size;
  char *out = NULL;

  if( str == NULL ) { return NULL; }
  if( str[0] == '\0' ) { return str; }

  // Trim leading space
  while(isspace(*str)) str++;

  if(*str == 0)  // All spaces?
  {
    *out = 0;
    return NULL;
  }

  // Trim trailing space
  end = str + strlen(str) - 1;
  while(end > str && isspace(*end)) end--;
  end++;

  // Set output size to minimum of trimmed string length and buffer size minus 1
  out_size = end - str;

  if (out_size<=0)
    return NULL;

  // Copy trimmed string and add null terminator
  out = (char *)coap_malloc(out_size+1);
  if (!out)
    return NULL;

  memcpy(out, str, out_size);
  out[out_size] = '\0';

  return out;
}

static str remove_cotation_marks(str text){

  str buf = {0, NULL};

  if (text.s[0] == '"' && text.s[strlen((const char*)text.s)-1] == '"') {
      buf.s = (unsigned char *)text.s + 1;
      buf.length = text.length - 2;

  } else {
      buf.s = (unsigned char *)text.s;
      buf.length = text.length;
  } 

  return buf;

}

static int match_options(str pattern, str option) {

  str unquoted_val = {0, NULL}, unquoted_pattern = {0, NULL};
  int match_substring = 0;

  if (pattern.length <= 0) return 0;

  if ((pattern.s) && (option.s)){
    unquoted_val = remove_cotation_marks(option);

    /* Check if the option is a Prefix Value String followed by an "*" */
    if ((pattern.s) && (pattern.s[pattern.length-1] == '*')) {          
      match_substring = 1;

      //remove the '*' from the string before comparing
      unquoted_pattern.length = pattern.length - 1;
      unquoted_pattern.s = pattern.s;

    } else {
      unquoted_pattern = pattern;
    }

    if (coap_match(&unquoted_val, &unquoted_pattern, match_substring, 0)){
      return 1;
    }
  }
  return 0;
}

static char *
get_source_address(coap_address_t *peer) {

//64 bits
#define BUFSIZE 64

  char *buf;
  //char buf[64];
  size_t n = 0;

  buf = (char *)coap_malloc(BUFSIZE);
  if (!buf)
    return NULL;

  switch(peer->addr.sa.sa_family) {

  case AF_INET:

    inet_ntop(AF_INET, &(peer->addr.sin.sin_addr.s_addr), buf, 16);

    n = sizeof(buf) + 1;
    break;

  case AF_INET6:
    n += snprintf(buf + n, BUFSIZE - n,
      "[%02x%02x:%02x%02x:%02x%02x:%02x%02x" \
      ":%02x%02x:%02x%02x:%02x%02x:%02x%02x]",
      peer->addr.sin6.sin6_addr.s6_addr[0],
      peer->addr.sin6.sin6_addr.s6_addr[1],
      peer->addr.sin6.sin6_addr.s6_addr[2],
      peer->addr.sin6.sin6_addr.s6_addr[3],
      peer->addr.sin6.sin6_addr.s6_addr[4],
      peer->addr.sin6.sin6_addr.s6_addr[5],
      peer->addr.sin6.sin6_addr.s6_addr[6],
      peer->addr.sin6.sin6_addr.s6_addr[7],
      peer->addr.sin6.sin6_addr.s6_addr[8],
      peer->addr.sin6.sin6_addr.s6_addr[9],
      peer->addr.sin6.sin6_addr.s6_addr[10],
      peer->addr.sin6.sin6_addr.s6_addr[11],
      peer->addr.sin6.sin6_addr.s6_addr[12],
      peer->addr.sin6.sin6_addr.s6_addr[13],
      peer->addr.sin6.sin6_addr.s6_addr[14],
      peer->addr.sin6.sin6_addr.s6_addr[15]);

    break;
    default:
    ;
  }

  if (n < BUFSIZE)
    buf[n++] = '\0';

  return buf;

#undef BUFSIZE
}

static char *
add_source_address(coap_address_t *peer) {

//64 bits + quotation marks 
#define BUFSIZE 66

  char *buf;
  size_t n = 1;

  buf = (char *)coap_malloc(BUFSIZE);
  if (!buf)
    return NULL;

  buf[0] = '"';

  switch(peer->addr.sa.sa_family) {

  case AF_INET:

    //buf = 
    inet_ntop(AF_INET, &(peer->addr.sin.sin_addr.s_addr), buf+n, 16);

    if (peer->addr.sin.sin_port != htons(COAP_DEFAULT_PORT)) {
        n =
        snprintf(buf + sizeof(buf) + n + 1, BUFSIZE - sizeof(buf) -n, ":%d", peer->addr.sin.sin_port) + sizeof(buf) + 2;
    }
    break;

  case AF_INET6:
    n += snprintf(buf + n, BUFSIZE - n,
      "[%02x%02x:%02x%02x:%02x%02x:%02x%02x" \
      ":%02x%02x:%02x%02x:%02x%02x:%02x%02x]",
      peer->addr.sin6.sin6_addr.s6_addr[0],
      peer->addr.sin6.sin6_addr.s6_addr[1],
      peer->addr.sin6.sin6_addr.s6_addr[2],
      peer->addr.sin6.sin6_addr.s6_addr[3],
      peer->addr.sin6.sin6_addr.s6_addr[4],
      peer->addr.sin6.sin6_addr.s6_addr[5],
      peer->addr.sin6.sin6_addr.s6_addr[6],
      peer->addr.sin6.sin6_addr.s6_addr[7],
      peer->addr.sin6.sin6_addr.s6_addr[8],
      peer->addr.sin6.sin6_addr.s6_addr[9],
      peer->addr.sin6.sin6_addr.s6_addr[10],
      peer->addr.sin6.sin6_addr.s6_addr[11],
      peer->addr.sin6.sin6_addr.s6_addr[12],
      peer->addr.sin6.sin6_addr.s6_addr[13],
      peer->addr.sin6.sin6_addr.s6_addr[14],
      peer->addr.sin6.sin6_addr.s6_addr[15]);

    if (peer->addr.sin6.sin6_port != htons(COAP_DEFAULT_PORT)) {
      n +=
      snprintf(buf + n, BUFSIZE - n, ":%d", peer->addr.sin6.sin6_port);
    }
    break;
    default:
    ;
  }

  if (n < BUFSIZE){
    buf[n++] = '"';
    buf[n++] = '\0';
}

  return buf;

#undef BUFSIZE
}

/**********************************************************/
/***                   BLOCK1 FUNTIONS                  ***/
/**********************************************************/

static coap_block1_t *
coap_block_init(int id, unsigned int num, unsigned int szx, unsigned int m, unsigned char *payload) {

  coap_block1_t *b;

#ifdef WITH_LWIP
  b = (coap_block1_t *)memp_malloc(MEMP_COAP_BLOCK);
#endif
#ifndef WITH_LWIP
  b = (coap_block1_t *)coap_malloc_type(COAP_BLOCK, sizeof(coap_block1_t));
#endif
  if (b) {
    memset(b, 0, sizeof(coap_block1_t));

    size_t len = strlen((char *)payload);
    unsigned char *buffer = coap_malloc(len+1);//+1 for the zero-terminator
    if (!buffer) return NULL;

    memcpy(buffer, payload, len);

    b->id = id;
    b->num = num;
    b->szx = szx;
    b->m = m;
    b->payload = buffer;
  } else {
    debug("coap_block1_init: no memory left\n");
    return NULL;
  }
  
  return b;
}

static void delete_block(coap_block1_t * block){

  if (!block) return;

  /* free the payload */
  coap_free(block->payload);

  /* free the block */
  BLOCK_DELETE(blocks, block);

  return;

}

static coap_block1_t * 
coap_process_block1(coap_pdu_t *request, coap_pdu_t *response){
       
  unsigned char block_buf[4];
  unsigned char *payload = NULL;
  coap_block1_t *result = NULL, *b = NULL;
  coap_block_t block = { .num = 0, .m = 0, .szx = 6 };
  size_t length;
  int id = 0;

  if ((!request) || (!request->hdr)) return NULL;

  /* split block option into number/more/size where more is the
   * letter M if set, the _ otherwise */

  coap_get_block(request, COAP_OPTION_BLOCK1, &block);

  debug("found Block1, block size is %u, M bit is %i, block nr. %u\n",
  2 << (block.szx + 4), block.m, block.num);

  id = (int)ntohs(request->hdr->id);

  /* store the block */
  /* read the payload */
  if (coap_get_data(request, &length, &payload)) {

    if (payload) {
      if (!block.m) {
        // add \0 to the end of the payload 
        payload[length-1] = '\0';
      } else {
        // add \0 to the end of every block 
        payload[length] = '\0';
      }

      BLOCK_FIND(blocks, id, result);

      if (result){
        if (result->num == (block.num -1)){

          unsigned char* s = concat(result->payload, payload);

          if (s == NULL){
            debug("coap_process_block1: error in memory\n");
            coap_free(s);
            response->hdr->code = COAP_RESPONSE_CODE(503);
            return NULL;
          }

          result-> id = id;
          result-> m = block.m;
          result-> num = block.num;

          //deallocate the old payload
          coap_free(result->payload);
          result-> payload = s;
        } else {
          /* Block1 transfer is not in sequence */
          debug("coap_process_block1: request transfer is not in sequence\n");
          coap_add_option(response,
                    COAP_OPTION_BLOCK1,
                    coap_encode_var_bytes(block_buf,
                           (((result->num)+1) << 4) | block.m << 3 |
                            block.szx), block_buf);
          response->hdr->code = COAP_RESPONSE_CODE(408);
          return NULL;
        }
      } else {

        /*If the block is 0, we create a new block*/
        if (block.num == 0){
          b = coap_block_init(id, block.num, block.szx, block.m, payload);
          BLOCK_ADD(blocks, b);
        } else {
          /* Block1 transfer is not in sequence */
          debug("coap_process_block1: request incomplete\n");
          coap_add_option(response,
                    COAP_OPTION_BLOCK1,
                    coap_encode_var_bytes(block_buf,
                           ((0) << 4) | block.m << 3 |
                            block.szx), block_buf);
          response->hdr->code = COAP_RESPONSE_CODE(408);

          return NULL;
        }
      }
    }
  }

  if (block.m) {
    coap_add_option(response,
                    COAP_OPTION_BLOCK1,
                    coap_encode_var_bytes(block_buf,
                           ((block.num) << 4) | block.m << 3 |
                            block.szx), block_buf);
    response->hdr->code = COAP_RESPONSE_CODE(231);

  } else {
    response->hdr->code = COAP_RESPONSE_CODE(204);
    BLOCK_FIND(blocks, id+1, result);
  
    return result;
  }

  return NULL;
}

/**********************************************************/
/***                   GROUP FUNTIONS                   ***/
/**********************************************************/

static int parse_group_link_format(coap_context_t  *ctx, char *s, coap_group_t *g){

  char *cp, *sc, *link, *buf = NULL;
  char seps[] = ",", sep_c[] = ";", sep_eq[] = "=";
  str ep = {0, NULL}, unquoted_val = {0, NULL};
  unsigned char loc[LOCSIZE];
  coap_key_t *resource_key = {0};
  size_t loc_size;

  memcpy(loc, RD_ROOT_STR, RD_ROOT_SIZE);

  loc_size = RD_ROOT_SIZE;

  loc[loc_size++] = '/';
  loc[loc_size] = '\0';

  while ((cp = strsep (&s, seps))) {
    if (*cp != '\0'){

      if((sc = strsep (&cp, sep_c))){
        if (*sc != '\0'){
          /* Check href first*/
          if((strstr(sc, "<")!= NULL) && (strstr(sc, ">")!= NULL)) {
            while((sc = strsep (&cp, sep_c))){
              if (*sc != '\0'){
                link = strsep (&sc, sep_eq);
            
                buf = trimwhitespace(link);
                link = strsep (&sc, sep_eq);
              
                if (strcmp(buf, "ep") == 0) { 
                  ep.s = (unsigned char *)trimwhitespace(link);
                  ep.length= strlen((const char *)ep.s); 
                } else {
                  debug("parse_group_link_format: unknown content-format '%s'\n",buf);
                  coap_free(buf);
                  return 0;
                }
                coap_free(buf);
              }
            }  

	          /* Check if the endpoint exists in the system*/     

            /* Check if the option has quotation marks ('"'). If so, remove them */
            if ((ep.s) && (ep.s[0] == '"') && (ep.s[ep.length-1] == '"')) {          
              unquoted_val.s = (unsigned char *)ep.s + 1;
              unquoted_val.length = strlen((const char *)ep.s) - 2;
              unquoted_val.s[unquoted_val.length] = '\0';
            } else {
              unquoted_val.s = (unsigned char *)ep.s;
              unquoted_val.length = (ep.s == NULL) ? 0 : strlen((const char *)ep.s);
            }

            /* try to find the resource from the request URI */        
            resource_key =  coap_build_key_for_resource(unquoted_val, loc, LOCSIZE);

            /* If the resource already exist, we continue*/
            if (coap_get_resource_from_key(ctx, (unsigned char *)resource_key)==NULL) {
              debug("parse_group_link_format: one of the resources do not exist\n");
              coap_free(resource_key);
              coap_free(ep.s);
              return 0;
            }
            coap_free(resource_key);

            /* Create new link struct */
            coap_add_endpoint(g, (const char *)ep.s);

            /* clean-up the variables */
            ep.s = NULL;
            unquoted_val.s = NULL;
            loc[loc_size] = '\0';

          } else {
            debug("parse_group_link_format: 'href' does not exist\n");
            return 0;
          }
        }
      }
    }
  }
  return 1;
}


static int parse_group_json_format(coap_context_t  *ctx, char *s, coap_group_t *g){

  int i, status = 0;
  static int visible;
  str ep = {0,NULL}; 
  unsigned char loc[LOCSIZE];
  coap_key_t *resource_key = {0};
  size_t loc_size;

  static struct linkstruct_t {
    char href[MAX_LENGTH_LINK_CHAR-3];
    char ep[MAX_LENGTH_LINK_CHAR];
  } linkstruck[MAX_JSON_LINKS];

  static json_attr_t json_link_attrs_subtype[] = {
    {"href",  t_string,  .addr.offset = offsetof(struct linkstruct_t, href),
                         .len = MAX_LENGTH_LINK_CHAR},
    {"ep",  t_string,  .addr.offset = offsetof(struct linkstruct_t, ep),
                         .len = MAX_LENGTH_LINK_CHAR},
    {NULL},
  };

  static json_array_t json_link_attrs[] = {
    {.element_type = t_structobject,
    .arr.objects.subtype = json_link_attrs_subtype,
    .arr.objects.base = (char*)&linkstruck,
    .arr.objects.stride = sizeof(struct linkstruct_t),                       
    .count = &visible,
    .maxlen = sizeof(linkstruck)/sizeof(linkstruck[0])},
  };

  memcpy(loc, RD_ROOT_STR, RD_ROOT_SIZE);

  loc_size = RD_ROOT_SIZE;
  loc[loc_size++] = '/';
  loc[loc_size] = '\0';

  status = json_read_array(s, json_link_attrs, NULL);

  if (status != 0){
    debug("parse_group_json_format: there is some error while parsing JSON:\n");
    return 0;
  }

  for (i = 0; i < visible; i++){

    if ((strlen(linkstruck[i].href)-2) > 63 || strlen(linkstruck[i].ep)>63){
      debug("parse_group_json_format: some links exceed the maximum lenght\n");
      return 0;
    }

    if (strlen(linkstruck[i].href) == 0){
      debug("parse_group_json_format: 'href' does not exist\n");
      return 0;
    }

    if (strlen(linkstruck[i].ep) > 0){

      ep.s = (unsigned char *)linkstruck[i].ep;
      ep.length= strlen(linkstruck[i].ep);


      /* Check if the endpoint exists in the system*/

      /* try to find the resource from the request URI */        
      resource_key =  coap_build_key_for_resource(ep, loc, LOCSIZE);

      /* If the resource already exist, we continue*/
      if (coap_get_resource_from_key(ctx, (unsigned char *)resource_key)==NULL) {
        debug("parse_group_json_format: one of the resources do not exist\n");
        coap_free(resource_key);
        return 0;
      }
      coap_free(resource_key);

      ep.length= strlen(linkstruck[i].ep)+3;
      ep.s = (unsigned char *)coap_malloc(ep.length);
      if (!ep.s)
        return 0;

      /* add missing quotes */
      ep.s[0] = '"';
      memcpy(ep.s+1, linkstruck[i].ep, strlen(linkstruck[i].ep));
      ep.s[strlen(linkstruck[i].ep)+1] = '"';
      ep.s[strlen(linkstruck[i].ep)+2] = '\0';
    } else {
      ep.s = NULL;
    }

    /* Create new link struct */
    coap_add_endpoint(g, (const char *)ep.s);

    /* clean-up the variables */
    ep.s = NULL;
    loc[loc_size] = '\0';
  }
   
  return 1;
}

static int read_group_payload(coap_context_t  *ctx, coap_pdu_t *request, coap_group_t *g, unsigned char *payload){

  coap_opt_iterator_t opt_iter;
  unsigned int content_format = -1;
  coap_opt_t *type;
 
  if (!payload) return 1;

  /* get media_type if available */
  type = coap_check_option(request, COAP_OPTION_CONTENT_TYPE, &opt_iter);
  if (type) {
    content_format = coap_decode_var_bytes(COAP_OPT_VALUE(type), COAP_OPT_LENGTH(type));

    switch (content_format) {
    case COAP_MEDIATYPE_APPLICATION_JSON :
      debug("read_group_payload:media type is JSON\n");
      if (!parse_group_json_format(ctx, (char *)payload, g)) return 0;
      break;  
    case COAP_MEDIATYPE_APPLICATION_CBOR :
      debug("read_group_payload:media type is CBOR\n");
      //TODO Implement the CBOR Parser
      return 0;
      break;  
    default:
      debug("read_group_payload:media type is default. LINK_FORMAT\n");
      if (!parse_group_link_format(ctx, (char *)payload, g)) return 0;
      break;
    } 
  } else {
      debug("read_group_payload:no TYPE. LINK_FORMAT\n");
      if (!parse_group_link_format(ctx, (char *)payload, g)) return 0;
  }

  return 1;
}

static unsigned char * 
lookup_print_group(coap_group_t *group, unsigned char *buf, const unsigned char *bufend, size_t *len, size_t *offset, Option_type lk_type){

  if (!group) return buf;
  if ((lk_type == D) && (!(group->d.s))) return buf;

  PRINT_COND_WITH_OFFSET(buf, bufend, *offset, '\n', *len);

  switch(lk_type){
    case GP:

      if (group->con.s) {
        PRINT_COND_WITH_OFFSET(buf, bufend, *offset, '<', *len);
        COPY_COND_WITH_OFFSET(buf, bufend, *offset,
                    			   (group->con.s == 0) ? NULL : (group->con.s+1), 
                             (group->con.length == 0) ? 0 : (group->con.length-2), *len);
        PRINT_COND_WITH_OFFSET(buf, bufend, *offset, '>', *len);
      } else {
        COPY_COND_WITH_OFFSET(buf, bufend, *offset, "</rd-group>", 11, *len);
      }


      if (group->uri.s) {

        COPY_COND_WITH_OFFSET(buf, bufend, *offset, ";gp=", 4, *len);
        // remove the 'rd-group/' from the path
       	COPY_COND_WITH_OFFSET(buf, bufend, *offset,
                      			  (group->uri.length > 9) ? group->uri.s + 9 : group->uri.s, 
                              (group->uri.length > 9) ? (group->uri.length - 9) : group->uri.length, *len);
      }
      if (group->d.s) {
        COPY_COND_WITH_OFFSET(buf, bufend, *offset, ";d=", 3, *len);
       	COPY_COND_WITH_OFFSET(buf, bufend, *offset,
                      			  group->d.s, group->d.length, *len);
      }
      break;
    case D:
      if (group->d.s) {

        COPY_COND_WITH_OFFSET(buf, bufend, *offset, "</", 2, *len);
     	  COPY_COND_WITH_OFFSET(buf, bufend, *offset, RD_ROOT_STR, RD_ROOT_SIZE, *len);
        PRINT_COND_WITH_OFFSET(buf, bufend, *offset, '>', *len);


        COPY_COND_WITH_OFFSET(buf, bufend, *offset, ";d=", 3, *len);
       	COPY_COND_WITH_OFFSET(buf, bufend, *offset,
                      			  group->d.s, group->d.length, *len);
      }
/*      if (group->ins.s) {
        COPY_COND_WITH_OFFSET(buf, bufend, *offset, ";ins=", 5, *len);
        COPY_COND_WITH_OFFSET(buf, bufend, *offset,
                      			  group->ins.s, group->ins.length, *len);
      }

      if (group->exp) {
        COPY_COND_WITH_OFFSET(buf, bufend, *offset, ";exp", 4, *len);
      }*/
      break;
    case EP:
    case RES:
      break;
    default:
      break;
  }

  return buf;

}

static void
hnd_delete_group(coap_context_t  *ctx,
                    struct coap_group_t *group,
                    const coap_endpoint_t *local_interface UNUSED_PARAM,
                    coap_address_t *peer UNUSED_PARAM,
                    coap_pdu_t *request UNUSED_PARAM,
                    str *token UNUSED_PARAM,
                    coap_pdu_t *response) {

  if (coap_delete_group(ctx, group->key)) {
    response->hdr->code = COAP_RESPONSE_CODE(202);
  } else {
    response->hdr->code = COAP_RESPONSE_CODE(404);
  }
}

static void
hnd_post_rd_group(coap_context_t  *ctx,
            struct coap_resource_t *resource UNUSED_PARAM,
            const coap_endpoint_t *local_interface UNUSED_PARAM,
            coap_address_t *peer UNUSED_PARAM,
            coap_pdu_t *request,
            str *token UNUSED_PARAM,
            coap_pdu_t *response) {

  coap_group_t *g;
  coap_opt_iterator_t opt_iter;
  coap_opt_t *query, *block_opt = NULL; 
  unsigned char loc[LOCSIZE], *uri;
  size_t loc_size, gp_size, key_size, uri_size, payload_length;
  str gp = {0, NULL}, d = {0, NULL}, con = {0, NULL}; /* store query parameters */
  unsigned int *int_gp_key;
  coap_key_t gp_key = {0}, group_key = {0};
  coap_opt_filter_t filter;
  char seps[] = "=", gp_key_str[16] = {0};
  char *cp, *buf_op, *buf_address;
  coap_block1_t *result= NULL;
  unsigned char block_buf[4], *payload=NULL;
  int val_offset = 0, delete = 0;

  /* Got some data, check if block1 option is set. */
  block_opt = coap_check_option(request, COAP_OPTION_BLOCK1, &opt_iter);

  if (block_opt) { 
    /* handle Block1 */
    if (!(result = coap_process_block1(request, response))) return;

  }

  memcpy(loc, RD_GROUP_STR, RD_GROUP_SIZE);

  loc_size = RD_GROUP_SIZE;
  loc[loc_size++] = '/';

  /* store query parameters for later use */

  coap_option_filter_clear(filter);
  coap_option_setb(filter, COAP_OPTION_URI_QUERY);

  coap_option_iterator_init(request, &opt_iter, filter);

  while((query = coap_option_next(&opt_iter))) {

    int length = coap_opt_length(query);

    buf_op = (char *)coap_malloc(length + 1);
    if (!buf_op) {
      response->hdr->code = COAP_RESPONSE_CODE(503);
      return;
    }

    // add \0 to the end of the payload 
    memcpy(buf_op, coap_opt_value(query), length);
    buf_op[length] = '\0';

    cp = strsep (&buf_op, seps);

    val_offset = buf_op - cp;

    if ((*cp != '\0') && (cp != NULL)){
      if (buf_op == NULL) {
          response->hdr->code = COAP_RESPONSE_CODE(400);
          return;
      }
      if (strcmp(cp, "gp") == 0) { 
          gp.s= (unsigned char *) coap_opt_value(query) + val_offset;
          gp.length= strlen(buf_op);        
      } else if (strcmp(cp, "d") == 0) {
          d.s= (unsigned char *) coap_opt_value(query) + val_offset;
          d.length= strlen(buf_op);        
      } else if (strcmp(cp, "con") == 0) {
          con.s= (unsigned char *) coap_opt_value(query) + val_offset;
          con.length= strlen(buf_op);        
      } else {
          debug("hnd_post_rd_group: cannot find option\n");
          response->hdr->code = COAP_RESPONSE_CODE(400);
          coap_free(cp);
          return;
      }
    }
    coap_free(cp);
  }

  if ((gp.length) && (gp.length<=63)) {   /* client has specified a group name */

    /* create a key from the ep node */
    gp_size = min(gp.length, LOCSIZE - loc_size - 1);
    coap_hash_path(gp.s, gp_size, gp_key);

    /* translate the key into a string */
    int_gp_key = (void *)(&gp_key);
    snprintf(gp_key_str, 16, "%u", *int_gp_key);

    /* rd-group/gp_key_str */
    memcpy(loc + loc_size, gp_key_str, min(strlen(gp_key_str), LOCSIZE - loc_size - 1));
    key_size = min(strlen(gp_key_str), LOCSIZE - loc_size - 1) + loc_size;

    /* create the final key of rd/gp_key_str. We will send rd/gp_key_str to the client */
    coap_hash_path(loc, key_size, group_key);

    /* If the group already exist, we delete it and create it again*/
    if (coap_get_group_from_key(ctx, group_key)!=NULL) {
      delete = 1;
      debug("hnd_post_rd_group: the group already exist, we delete it and create a new one\n");
    }
  } else {   /* create response error */
    response->hdr->code = COAP_RESPONSE_CODE(400);
    return;
  }

  /* Create a new uri rd-group/ep-name */
  uri = (unsigned char *)coap_malloc(LOCSIZE);
  if (!uri) {
    response->hdr->code = COAP_RESPONSE_CODE(503);
    return;
  }

  memcpy(uri, RD_GROUP_STR, RD_GROUP_SIZE);

  uri_size = RD_GROUP_SIZE;
  uri[uri_size++] = '/';

  memcpy(uri + uri_size, gp.s, min(gp.length, LOCSIZE - uri_size - 1));
  uri_size += min(gp.length, LOCSIZE - uri_size - 1); 
  uri[uri_size] = '\0';

  g = coap_group_rd_init(uri, uri_size, loc, key_size, d, con, hnd_delete_group);

  if (g == NULL){
    response->hdr->code = COAP_RESPONSE_CODE(503);
    coap_free_group(g);
    return;
  }

  /* Store the address of the device*/
  if ((buf_address = add_source_address(peer))!= NULL){
    g->A.s= (unsigned char *)buf_address;
    g->A.length= strlen(buf_address);
  } else {
      /* create response error */
      response->hdr->code = COAP_RESPONSE_CODE(503);
      coap_free_group(g);
      return;
  } 

  /* read the payload */
  if (block_opt) { 
    if (result){
      payload = result->payload;
    }
  } else {
    /* read the payload */
    if (request->data){
      if (coap_get_data(request, &payload_length, &payload)) {
        if (payload) {
          // add \0 to the end of the payload 
          payload[payload_length-1] = '\0';
        }
      }
    }
  }

  /* read the payload */
  if (payload){
    if (!read_group_payload(ctx, request, g, payload)) {
      /* create response error */
      response->hdr->code = COAP_RESPONSE_CODE(400);
      coap_free_group(g);
      return;
    }
  }

  //Delete the previous group
  if (delete){ 
    coap_delete_group(ctx, group_key);
  }

  coap_add_group(ctx, g);

  /* create response */

  response->hdr->code = COAP_RESPONSE_CODE(201);

  /* split path into segments and add Location-Path options */
  unsigned char _b[LOCSIZE];
  unsigned char *b = _b;
  size_t buflen = LOCSIZE;
  int nseg;

  nseg = coap_split_path(loc, key_size, b, &buflen);

  while (nseg--) {
    coap_add_option(response,
                    COAP_OPTION_LOCATION_PATH,
                    coap_opt_length(b),
                    coap_opt_value(b));
    b += COAP_OPT_SIZE(b);
  }

  if (block_opt) { 
    if (result){
      coap_add_option(response,
                      COAP_OPTION_BLOCK1,
                      coap_encode_var_bytes(block_buf,
                             ((result->num) << 4) | result->m << 3 |
                              result->szx), block_buf);
      delete_block(result);
    }
  }

  /*If DEBUG active, print the response */
  if (LOG_DEBUG <= coap_get_log_level()) {
    coap_show_pdu(response);
  }

}

/**********************************************************/
/***                 RESOURCE FUNTIONS                  ***/
/**********************************************************/

static int parse_link_format(char *s, coap_resource_t *r, int update){

  char *cp, *sc, *link;
  char seps[] = ",", sep_c[] = ";", sep_eq[] = "=";
  char *href = NULL, *rel = NULL, *rt = NULL, *ifd = NULL, *ct = NULL, *ins = NULL, *buf = NULL;
  int exp = 0; 
  coap_link_t *link_update;     
 
  while ((cp = strsep (&s, seps))) {
    if (*cp != '\0'){

      if((sc = strsep (&cp, sep_c))){
        if (*sc != '\0'){
          /* Check href first*/
          if((strstr(sc, "<")!= NULL) && (strstr(sc, ">")!= NULL)) {
            href = trimwhitespace(sc);

            /* Only for the update operation: Remove the link if exist */            
            if (update){         
             link_update = coap_find_link(r, (const char *) href, strlen(href) + 1);
              if (link_update) {
                coap_delete_link(r, link_update);
              }
            }

            while((sc = strsep (&cp, sep_c))){

              if (*sc != '\0'){

                buf = trimwhitespace(sc);
                if (strcmp(buf, "exp") == 0) { 
                  exp = COAP_RESOURCE_FLAGS_EXPORT; 
                } else { 
                  link = strsep (&sc, sep_eq);
              
                  //free the previous memory from the temp variable buf
                  coap_free(buf);
                  buf = trimwhitespace(link);
                  if (strcmp(buf, "rel") == 0) { 
                    rel = trimwhitespace(sc);
                  } else if (strcmp(buf, "rt") == 0) { 
                    rt = trimwhitespace(sc);
                  } else if (strcmp(buf, "if") == 0) { 
                    ifd = trimwhitespace(sc);
                  } else if (strcmp(buf, "ct") == 0) { 
                    ct = trimwhitespace(sc);
                  } else if (strcmp(buf, "ins") == 0) { 
                    ins = trimwhitespace(sc);
                  } else {
                    debug("parse_link_format: unknown content-format '%s'\n",buf);
                    coap_free(buf);
                    return 0;
                  }
                }
                coap_free(buf);
              }
            }  
     
            /* Create new link struct */
            coap_add_link(r, href, ct, rt, ifd, rel, ins, exp);

            /* clean-up the variables */
            href = NULL; ct = NULL; rt = NULL; ifd = NULL; rel=NULL; ins=NULL; exp=0;

          } else {
            debug("parse_link_format: 'href' does not exist\n");
            return 0;
          }
        }
      }
    }
  }
  return 1;
}

static int parse_json_format(char *s, coap_resource_t *r, int update){

  int i, status = 0;
  static int visible;
  char *ct = NULL, *href = NULL, *rel = NULL, *rt = NULL, *ifd = NULL, *ins = NULL;
  coap_link_t *link_update;  

  static struct linkstruct_t {
    char href[MAX_LENGTH_LINK_CHAR-3];
    char rel[MAX_LENGTH_LINK_CHAR];
    char rt[MAX_LENGTH_LINK_CHAR];
    char ifd[MAX_LENGTH_LINK_CHAR];
    char ins[MAX_LENGTH_LINK_CHAR];
    int ct;
    int exp;
  } linkstruck[MAX_JSON_LINKS];

  static json_attr_t json_link_attrs_subtype[] = {
    {"href",  t_string,  .addr.offset = offsetof(struct linkstruct_t, href),
                         .len = MAX_LENGTH_LINK_CHAR},
    {"rel",  t_string,  .addr.offset = offsetof(struct linkstruct_t, rel),
                         .len = MAX_LENGTH_LINK_CHAR},
    {"rt",  t_string,  .addr.offset = offsetof(struct linkstruct_t, rt),
                         .len = MAX_LENGTH_LINK_CHAR},
    {"if",  t_string,  .addr.offset = offsetof(struct linkstruct_t, ifd),
                         .len = MAX_LENGTH_LINK_CHAR},
    {"ct",  t_integer,  .addr.offset = offsetof(struct linkstruct_t, ct)},
    {"ins",  t_string,  .addr.offset = offsetof(struct linkstruct_t, ins),
                         .len = MAX_LENGTH_LINK_CHAR},
    {"exp",  t_integer,  .addr.offset = offsetof(struct linkstruct_t, exp)},
    {NULL},
  };

  static json_array_t json_link_attrs[] = {
    {.element_type = t_structobject,
    .arr.objects.subtype = json_link_attrs_subtype,
    .arr.objects.base = (char*)&linkstruck,
    .arr.objects.stride = sizeof(struct linkstruct_t),                       
    .count = &visible,
    .maxlen = sizeof(linkstruck)/sizeof(linkstruck[0])},
  };

  status = json_read_array(s, json_link_attrs, NULL);

  if (status != 0){
    debug("parse_json_format: there is some error while parsing JSON:\n");
    return 0;
  }

  for (i = 0; i < visible; i++){

    if ((strlen(linkstruck[i].href)-3) > 63 || strlen(linkstruck[i].rt)>63 
          || strlen(linkstruck[i].ifd)>63 || strlen(linkstruck[i].rel)>63){
      debug("parse_json_format: some links exceed the maximum lenght\n");
      return 0;
    }

    if (strlen(linkstruck[i].href) == 0){
      debug("parse_json_format: 'href' does not exist\n");
      return 0;
    } else {
      href = (char *)coap_malloc(strlen(linkstruck[i].href)+3);
      if (!href) {
        return 0;
      }


      snprintf(href, strlen(linkstruck[i].href)+3, "%s%s%s", "<", linkstruck[i].href, ">");

      /* Only for the update operation: Remove the link if exist */            
      if (update){
        link_update = coap_find_link(r, (const char *) href, strlen(href) + 1); 
        if (link_update) {
          coap_delete_link(r, link_update);
        }
      }

    }

    if (linkstruck[i].ct>0){
      char buf[sizeof(linkstruck[i].ct) * 2 + 3];

      snprintf(buf, sizeof(linkstruck[i].ct) * 2 + 3, "%d", linkstruck[i].ct);

      ct = (char *)coap_malloc(strlen(buf)+1);
      if (!ct) 
        return 0;

      memcpy(ct, buf, strlen(buf)+1);

    } else {
      ct = NULL;
    }

    if (strlen(linkstruck[i].rt) > 0){
      rt = (char *)coap_malloc(strlen(linkstruck[i].rt)+3);
      if (!rt)
        return 0;

      /* add missing quotes */
      rt[0] = '"';
      memcpy(rt+1, linkstruck[i].rt, strlen(linkstruck[i].rt));
      rt[strlen(linkstruck[i].rt)+1] = '"';
      rt[strlen(linkstruck[i].rt)+2] = '\0';
    } else {
      rt = NULL;
    }

    if (strlen(linkstruck[i].ifd) > 0){
      ifd = (char *)coap_malloc(strlen(linkstruck[i].ifd)+3);
      if (!ifd)
        return 0;

      /* add missing quotes */
      ifd[0] = '"';
      memcpy(ifd+1, linkstruck[i].ifd, strlen(linkstruck[i].ifd));
      ifd[strlen(linkstruck[i].ifd)+1] = '"';
      ifd[strlen(linkstruck[i].ifd)+2] = '\0';

    } else {
      ifd = NULL;
    }

    if (strlen(linkstruck[i].ins) > 0){
      ins = (char *)coap_malloc(strlen(linkstruck[i].ins)+3);
      if (!ins)
        return 0;

      /* add missing quotes */
      ins[0] = '"';
      memcpy(ins+1, linkstruck[i].ins, strlen(linkstruck[i].ins));
      ins[strlen(linkstruck[i].ins)+1] = '"';
      ins[strlen(linkstruck[i].ins)+2] = '\0';

    } else {
      ins = NULL;
    }

    if (strlen(linkstruck[i].rel) > 0){
      rel = (char *)coap_malloc(strlen(linkstruck[i].rel)+3);
      if (!rel)
        return 0;

      /* add missing quotes */
      rel[0] = '"';
      memcpy(rel+1, linkstruck[i].rel, strlen(linkstruck[i].rel));
      rel[strlen(linkstruck[i].rel)+1] = '"';
      rel[strlen(linkstruck[i].rel)+2] = '\0';
      
    } else {
      rel = NULL;
    }

    if (linkstruck[i].exp>0){
      /* Create new link struct */
      coap_add_link(r, href, ct, rt, ifd, rel, ins, COAP_RESOURCE_FLAGS_EXPORT);
    } else {
      /* Create new link struct */
      coap_add_link(r, href, ct, rt, ifd, rel, ins, 0);
    }

  }
   
  return 1;
}

static int read_payload(coap_pdu_t *request, coap_resource_t *r, unsigned char *payload, int update){

  coap_opt_iterator_t opt_iter;
  unsigned int content_format = -1;
  coap_opt_t *type;
 
  if (!payload) return 1;

  /* get media_type if available */
  type = coap_check_option(request, COAP_OPTION_CONTENT_TYPE, &opt_iter);
  if (type) {
    content_format = coap_decode_var_bytes(COAP_OPT_VALUE(type), COAP_OPT_LENGTH(type));
    switch (content_format) {
    case COAP_MEDIATYPE_APPLICATION_JSON :
      debug("read_payload:media type is JSON\n");
      if (!parse_json_format((char *)payload, r, update)) return 0;
      break;
    case COAP_MEDIATYPE_APPLICATION_CBOR :
      debug("read_payload:media type is CBOR\n");
      //TODO Implement the CBOR Parser
      return 0;
      break;  
    default:
      debug("read_payload:media type is default. LINK_FORMAT\n");
      if (!parse_link_format((char *)payload, r, update)) return 0;
      break;
    } 
  } else {
      debug("read_payload:no TYPE. LINK_FORMAT\n");
      if (!parse_link_format((char *)payload, r, update)) return 0;
  }

  return 1;
}

/**********************************************************/
/***                  RD FUNCTIONS SET                  ***/
/**********************************************************/

static void
hnd_get_resource(coap_context_t  *ctx UNUSED_PARAM,
                 struct coap_resource_t *resource,
                 const coap_endpoint_t *local_interface UNUSED_PARAM,
                 coap_address_t *peer UNUSED_PARAM,
                 coap_pdu_t *request UNUSED_PARAM,
                 str *token UNUSED_PARAM,
                 coap_pdu_t *response) {

  coap_resource_t *res;
  coap_opt_filter_t filter;
  coap_link_t *link;
  coap_opt_iterator_t opt_iter;
  coap_opt_t *query; 
  char seps[] = "=";
  char *cp, *buf_op;
  size_t len = 0, offset = 0;
  coap_print_status_t result;
  str unquoted_link = {0, NULL}, href = {0, NULL}, rel = {0, NULL}, rt = {0, NULL}, ifd = {0, NULL}, ct = {0, NULL}, ins = {0, NULL}; /* store query parameters */
  int first_link = 0, val_offset = 0, exp = 0;
  unsigned char *p, buf[3];
  const unsigned char *bufend;

  res = coap_get_resource_from_key(ctx, resource->key);

  if (res == NULL){
    response->hdr->code = COAP_RESPONSE_CODE(404);
    return;
  }

  /* store query parameters for later use */
  coap_option_filter_clear(filter);
  coap_option_setb(filter, COAP_OPTION_URI_QUERY);

  coap_option_iterator_init(request, &opt_iter, filter);

  while((query = coap_option_next(&opt_iter))) {

    int length = coap_opt_length(query);
    buf_op = (char *)coap_malloc(length + 1);
    if (!buf_op) {
      response->hdr->code = COAP_RESPONSE_CODE(503);
      return;
    }
      
    memcpy(buf_op, coap_opt_value(query), coap_opt_length(query));
    // add \0 to the end of the payload 
    buf_op[length] = '\0';

    if (strcmp(buf_op, "exp") == 0) {
      exp = 1;
      coap_free(buf_op);
    } else {

      cp = strsep (&buf_op, seps);

      val_offset = buf_op - cp;

      if ((*cp != '\0') && (cp != NULL)){
        if (buf_op == NULL) {
            response->hdr->code = COAP_RESPONSE_CODE(400);
            coap_free(cp);
            return;
        }
        if (strcmp(cp, "href") == 0) {
            if (buf_op[0] == '<') {          /* if attribute has brackets (< >) value, remove them */
              href.length = strlen(buf_op) - 2;
              href.s = (unsigned char *) coap_opt_value(query) + val_offset +1;
            } else {
              href.s= (unsigned char *) coap_opt_value(query) + val_offset;
              href.length= strlen(buf_op);        
            }
        } else if (strcmp(cp, "rel") == 0) {
            rel.s= (unsigned char *) coap_opt_value(query) + val_offset;
            rel.length= strlen(buf_op);
        } else if (strcmp(cp, "rt") == 0) {
            rt.s= (unsigned char *) coap_opt_value(query) + val_offset;
            rt.length= strlen(buf_op);        
        } else if (strcmp(cp, "if") == 0) {
            ifd.s= (unsigned char *) coap_opt_value(query) + val_offset;
            ifd.length= strlen(buf_op);        
        } else if (strcmp(cp, "ct") == 0) {
            ct.s= (unsigned char *) coap_opt_value(query) + val_offset;
            ct.length= strlen(buf_op);        
        } else if (strcmp(cp, "ins") == 0) {
            ins.s= (unsigned char *) coap_opt_value(query) + val_offset;
            ins.length= strlen(buf_op);        
        } else {
            debug("hnd_get_resource: cannot find option\n");
            response->hdr->code = COAP_RESPONSE_CODE(400);
            coap_free(cp);
            return;
        }
      }
      coap_free(cp);
    }
  }

  response->hdr->code = COAP_RESPONSE_CODE(205);

  coap_add_option(response,
                  COAP_OPTION_CONTENT_TYPE,
                  coap_encode_var_bytes(buf,
                                        COAP_MEDIATYPE_APPLICATION_LINK_FORMAT),
                                        buf);

  /* Manually set payload of response to let print_wellknown() write,
   * into our buffer without copying data. */

  response->data = (unsigned char *)response->hdr + response->length;
  *response->data = COAP_PAYLOAD_START;
  response->data++;
  response->length++;
  //len = need_block2 ? SZX_TO_BYTES(block.szx) : resp->max_size - resp->length;

  len = response->max_size - response->length;

  p = response->data;
  bufend = response->data + len;

  LL_FOREACH(resource->links, link) {

    if (href.s) {
      if (!link->href.s) continue;

      if (link->href.s[0] == '<') {  /* if the link has brackets (< >) value, remove them before to compare*/
        unquoted_link.length = link->href.length - 2;
        unquoted_link.s = link->href.s + 1;
      } else {
        unquoted_link = link->href;
      }
      if (!match_options(href, unquoted_link))
        continue;
    }
    if (rel.s) {
      if (!link->rel.s) continue;
      if (!match_options(rel, link->rel))
        continue;
    }
    if (rt.s) {
      if (!link->rt.s) continue;
      if (!match_options(rt, link->rt))
        continue;
    }
    if (ifd.s) {
      if (!link->ifd.s) continue;
      if (!match_options(ifd, link->ifd))
        continue;
    }
    if (ct.s) {
      if (!link->ct.s) continue;
      if (!match_options(ct, link->ct))
        continue;
    }

    if (ins.s) {
      if (!link->ins.s) continue;
      if (!match_options(ins, link->ins))
        continue;
    }
   
    if (exp) {
      if (!link->exp) continue;
    }

    if (first_link){
      PRINT_COND_WITH_OFFSET(p, bufend, offset, ',', len);
    } else {
      first_link++;
    }

    p = coap_print_sequence_links(link, p, bufend, &len, &offset);

  }

  result = p - response->data;

  if (result == 0){
    p[0] = '\0';
    result = result + 1;
  }

  response->length += COAP_PRINT_OUTPUT_LENGTH(result);

  return;

}

static void
hnd_post_resource(coap_context_t  *ctx UNUSED_PARAM,
                 struct coap_resource_t *resource,
                 const coap_endpoint_t *local_interface UNUSED_PARAM,
                 coap_address_t *peer UNUSED_PARAM,
                 coap_pdu_t *request,
                 str *token UNUSED_PARAM,
                 coap_pdu_t *response) {

  coap_opt_iterator_t opt_iter;
  coap_opt_t *query = NULL, *block_opt = NULL; 
  coap_opt_filter_t filter;
  str lt = {0, NULL}, con = {0, NULL}; /* store query parameters */
  unsigned char *buf, *payload=NULL, block_buf[4];
  coap_attr_t *attr;
  char seps[] = "=";
  char *cp, *buf_op;
  int val_offset = 0;
  size_t payload_length;
  coap_block1_t *result = NULL;
  time_t sec;
  char *ext_addr = NULL;
  char *address_peer = NULL;

  /* Got some data, check if block1 option is set. */
  block_opt = coap_check_option(request, COAP_OPTION_BLOCK1, &opt_iter);

  if (block_opt) { 
    /* handle Block1 */
    if (!(result = coap_process_block1(request, response))) return;

      coap_add_option(response,
                      COAP_OPTION_BLOCK1,
                      coap_encode_var_bytes(block_buf,
                             ((result->num) << 4) | result->m << 3 |
                              result->szx), block_buf);
  
  }

  /* store query parameters for later use */
  coap_option_filter_clear(filter);
  coap_option_setb(filter, COAP_OPTION_URI_QUERY);

  coap_option_iterator_init(request, &opt_iter, filter);


  while((query = coap_option_next(&opt_iter))) {

    int length = coap_opt_length(query);
    buf_op = (char *)coap_malloc(length + 1);

    if (!buf_op) {
      response->hdr->code = COAP_RESPONSE_CODE(503);
      return;
    }
      
    memcpy(buf_op, coap_opt_value(query), length);
    // add \0 to the end of the payload 
    buf_op[length] = '\0';

    cp = strsep (&buf_op, seps);

    val_offset = buf_op - cp;

    if ((*cp != '\0') && (cp != NULL)){
      if (buf_op == NULL) {
          response->hdr->code = COAP_RESPONSE_CODE(400);
          coap_free(cp);
          return;
      }
      if (strcmp(cp, "lt") == 0) {
          lt.s= (unsigned char *) coap_opt_value(query) + val_offset;
          lt.length= strlen(buf_op);
      } else if (strcmp(cp, "con") == 0) {
          con.s= (unsigned char *) coap_opt_value(query) + val_offset;
          con.length= strlen(buf_op);        
      } else {
          debug("hnd_post_resource: cannot find option\n");
          response->hdr->code = COAP_RESPONSE_CODE(400);
          coap_free(cp);
          return;
      }
    }
    coap_free(cp);
  }

  /* Update expiration to the resource */

  unsigned long ltime = 86400;

  if (lt.length) {

    char *time_s = NULL, *end = NULL;
    time_s = coap_malloc(lt.length+1);
    if (!time_s) {
      response->hdr->code = COAP_RESPONSE_CODE(503);
      return;
    }
    memcpy(time_s, lt.s, lt.length);
    time_s[lt.length] = 0;

    errno = 0;    /* To distinguish success/failure after call */
    ltime = strtol((const char *)time_s, &end, 10);

    if ((ltime > UINT_MAX) || (ltime < 60) || (errno == ERANGE && (ltime == LONG_MAX || ltime == 0))
                   || (errno != 0 && ltime == 0)) {
      /* Out of range, create response error */
      debug("hnd_post_rd: lt is out of range\n");
      response->hdr->code = COAP_RESPONSE_CODE(400);
      coap_free(time_s);
      return;
    }

    if (end != (const char *)time_s) {
      coap_update_lifetime(ctx, resource, ltime);
    }

    coap_free(time_s);

  } else {
    coap_update_lifetime(ctx, resource, ltime);
  }

  /*Update rule in the NAT table too*/
  if (pcp_nat){  
    /* Current time in seconds */
    sec = time(NULL);

    sec = sec + (time_t)ltime;

    //store old value of the lt
    int old_lt = resource->NAT_lifetime; 
    
    //modify the value of the NAT_lifetime with the new lt
    resource->NAT_lifetime= sec;

    address_peer = get_source_address(peer);
    /* Create rule in the NAT table*/
    if (coap_find_same_address(ctx, address_peer, sec, &ext_addr)){
      add_NAT_rule(resource, ltime, address_peer, ext_addr, sec);
    } else {

      if (old_lt>sec){
        //modify the NATTING with the new lt
        add_NAT_rule(resource, ltime, address_peer, ext_addr, sec);
      } else {
        //Copy the NATTING information into the node
        if (ext_addr){
          int len = strlen((char *)ext_addr);

          char *NAT_addr = (char *) coap_malloc(len +1);//+1 for the zero-terminator
          if (!NAT_addr) return;

          memcpy(NAT_addr, ext_addr, len+1);//+1 to copy the null-terminator

          if (resource->NAT.s!=NULL)
            coap_free(resource->NAT.s);

          resource->NAT.s= (unsigned char *)NAT_addr;
          resource->NAT.length= strlen(NAT_addr);
          resource->NAT_lifetime= sec;
        }
      }
    }
    coap_free(address_peer); 
  }

  
  /* Add or Update context to the resource */

  attr = coap_find_attr(resource, con.s, con.length);
  
  if (attr) {
   coap_delete_attr(resource, attr);
  }
  if ((con.s) && (con.length<=63)) {
    buf = (unsigned char *)coap_malloc(con.length + 2);
    if (buf) {
      /* add missing quotes */
      buf[0] = '"';
      memcpy(buf + 1, con.s, con.length);
      buf[con.length + 1] = '"';
      coap_add_attr(resource,
                  (unsigned char *)"con",
                  3,
                  buf,
                  con.length + 2,COAP_ATTR_FLAGS_RELEASE_VALUE);
    } else {
        response->hdr->code = COAP_RESPONSE_CODE(503);
        return;
    }
  }

  /* read the payload */
  if (block_opt) { 
    if (result){
      payload = result->payload;
    }
  } else {
    /* read the payload */
    if (request->data){
      if (coap_get_data(request, &payload_length, &payload)) {
        if (payload) {
          // add \0 to the end of the payload 
          payload[payload_length-1] = '\0';
        }
      }
    }
  }

  /* read the payload */
  if (payload){
    if (!read_payload(request, resource, payload, 1)) {
      /* create response error */
      response->hdr->code = COAP_RESPONSE_CODE(400);
      return;
    }
  }

  if (block_opt){
    delete_block(result);
  }

  response->hdr->code = COAP_RESPONSE_CODE(204);

  return;
}

static void
hnd_delete_resource(coap_context_t  *ctx,
                    struct coap_resource_t *resource,
                    const coap_endpoint_t *local_interface UNUSED_PARAM,
                    coap_address_t *peer UNUSED_PARAM,
                    coap_pdu_t *request UNUSED_PARAM,
                    str *token UNUSED_PARAM,
                    coap_pdu_t *response) {
  char *ext_addr = NULL;
  char *address_peer = NULL;

  /* Delete rule in the NAT table only if there is a resource with that IP in the list*/
  if (pcp_nat){
    address_peer = get_source_address(peer);
    if (coap_find_same_address(ctx, address_peer, 0, &ext_addr)){
      add_NAT_rule(NULL, 0, address_peer, ext_addr, 0);
    }
    coap_free(address_peer);
  }

  if (coap_delete_resource(ctx, resource->key)) {
    response->hdr->code = COAP_RESPONSE_CODE(202);
  } else {
    response->hdr->code = COAP_RESPONSE_CODE(404);
  }

}

static unsigned char *
lookup_print_resource(coap_link_t *link, unsigned char *buf, const unsigned char *bufend, size_t *len, size_t *offset, Option_type lk_type){

    if (lk_type != RES)
    	PRINT_COND_WITH_OFFSET(buf, bufend, *offset, '\n', *len);

    if (link->href.s) {
      if (lk_type != RES) {
      	COPY_COND_WITH_OFFSET(buf, bufend, *offset,
		  	  link->href.s, link->href.length, *len);
      } else {
        /* Remove the '<' from the ref*/
        COPY_COND_WITH_OFFSET(buf, bufend, *offset,
		  	  (link->href.length>0) ? link->href.s+1 : link->href.s, 
          (link->href.length>0) ? link->href.length-1 : link->href.length, *len);
      }
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

static unsigned char * 
lookup_print_endpoint(coap_resource_t *r, unsigned char *buf, const unsigned char *bufend, size_t *len, size_t *offset, Option_type lk_type){

  coap_attr_t *attr;

  if (!r) return buf;
  if (!(r->A.s)) return buf;

  if ((lk_type == D) && (coap_find_attr(r, (const unsigned char *)"d", 1)==NULL)) return buf;

  if (lk_type == D){
    PRINT_COND_WITH_OFFSET(buf, bufend, *offset, '\n', *len);

    COPY_COND_WITH_OFFSET(buf, bufend, *offset, "</rd>", 5, *len);

  }

  if ((lk_type == RES) || (lk_type == EP)){

    PRINT_COND_WITH_OFFSET(buf, bufend, *offset, '\n', *len);

    PRINT_COND_WITH_OFFSET(buf, bufend, *offset, '<', *len);

    if (pcp_nat && (r->NAT.s)){
      COPY_COND_WITH_OFFSET(buf, bufend, *offset, "coap://", 8, *len);

      COPY_COND_WITH_OFFSET(buf, bufend, *offset,
                    			  r->NAT.s, r->NAT.length, *len);
    } else {
      attr = coap_find_attr(r, (const unsigned char *)"con", 3);
      if (attr) {
     	  COPY_COND_WITH_OFFSET(buf, bufend, *offset,
                      			  (attr->value.s == 0) ? NULL : (attr->value.s+1), 
                              (attr->value.length == 0) ? 0 : (attr->value.length-2), *len);
      } else {
        COPY_COND_WITH_OFFSET(buf, bufend, *offset, "coap://", 8, *len);

     	  COPY_COND_WITH_OFFSET(buf, bufend, *offset,
                      			  r->A.s+1, r->A.length-2, *len);
      }
    }

    if (lk_type != RES) {
      PRINT_COND_WITH_OFFSET(buf, bufend, *offset, '>', *len);
    }
  } 

  switch(lk_type){
    case D:
      attr = coap_find_attr(r, (const unsigned char *)"d", 1);
      if (attr) {
        COPY_COND_WITH_OFFSET(buf, bufend, *offset, ";d=", 3, *len);
       	COPY_COND_WITH_OFFSET(buf, bufend, *offset,
                      			  attr->value.s, attr->value.length, *len);
      }
    break;
    case EP:
      if (r->uri.s) {
        COPY_COND_WITH_OFFSET(buf, bufend, *offset, ";ep=", 4, *len);
        // remove the 'rd/' from the path
       	COPY_COND_WITH_OFFSET(buf, bufend, *offset,
                      			  (r->uri.length > 3) ? r->uri.s + 3 : r->uri.s, 
                              (r->uri.length > 3) ? (r->uri.length -3) : r->uri.length, *len);
      }

      if (r->exp) {
        COPY_COND_WITH_OFFSET(buf, bufend, *offset, ";exp", 4, *len);
      }

      LL_FOREACH(r->link_attr, attr) {

        if ((strncmp((const char *)attr->name.s, "d", 1) != 0) &&
            (strncmp((const char *)attr->name.s, "con", 3) != 0)){
          PRINT_COND_WITH_OFFSET(buf, bufend, *offset, ';', *len);
          COPY_COND_WITH_OFFSET(buf, bufend, *offset,
                        			  attr->name.s, attr->name.length, *len);
          PRINT_COND_WITH_OFFSET(buf, bufend, *offset, '=', *len);
          COPY_COND_WITH_OFFSET(buf, bufend, *offset,
                        			  attr->value.s, attr->value.length, *len);

        }
      }

      break;
    case RES:
    case GP:
      break;
    default:
      break;
  }

  return buf;

}

static void
coap_delete_variable(coap_variables_t *variable){

    if (!variable)
      return;

    if (variable->d.s){
      coap_free(variable->d.s);
    }

    if (variable->ep.s){
      coap_free(variable->ep.s);
    }

    if (variable->gp.s){
      coap_free(variable->gp.s);
    }

    if (variable->et.s){
      coap_free(variable->et.s);
    }

    if (variable->href.s){
      coap_free(variable->href.s);
    }

    if (variable->rel.s){
      coap_free(variable->rel.s);
    }

    if (variable->rt.s){
      coap_free(variable->rt.s);
    }

    if (variable->ifd.s){
      coap_free(variable->ifd.s);
    }

    if (variable->ct.s){
      coap_free(variable->ct.s);
    }

    if (variable->ins.s){
      coap_free(variable->ins.s);
    }

  #ifdef WITH_LWIP
    memp_free(MEMP_COAP_VARIABLES, variable);
  #endif
  #ifndef WITH_LWIP
    coap_free_type(COAP_VARIABLES, variable);
  #endif
}

static unsigned char * 
lookup_resource(coap_variables_t *variables_buf, coap_resource_t *r, coap_group_t *g, unsigned char *buf, 
                const unsigned char *bufend, size_t len, size_t offset, Option_type lk_type, int *group_printed){

  coap_attr_t *attr;
  coap_link_t *link;
  str unquoted_val = {0, NULL};

  if (!r) return buf;

  attr = coap_find_attr(r, (const unsigned char *)"d", 1);  
  if ((lk_type == D) && (!attr)) return buf;


  int endpoint_printed = 0;

  /*Query all the attributes of the endpoint*/
  if (variables_buf->et.s){
    attr = coap_find_attr(r, (const unsigned char *)"et", 2);
    if (!attr) return buf;
    if (!match_options(variables_buf->et, attr->value))
      return buf;
  }

  if (variables_buf->ep.s){
    if (!r->uri.s) return buf;

    //remove the 'rd/' from the ep
    unquoted_val.s = r->uri.s + 3;
    unquoted_val.length = r->uri.length - 3;

    if (!match_options(variables_buf->ep, unquoted_val))
      return buf;
  }

  if (variables_buf->d.s){
    attr = coap_find_attr(r, (const unsigned char *)"d", 1);
    if (!attr) return buf;
    if (!match_options(variables_buf->d, attr->value))
      return buf;
  }

  /* Search the list of resources of a particular endpoint */
  LL_FOREACH(r->links, link) {

    if (variables_buf->rel.s) {
      if (!link->rel.s) continue;
      if (!match_options(variables_buf->rel, link->rel))
        continue;
    }

    if (variables_buf->ct.s) {
      if (!link->ct.s) continue;
      if (!match_options(variables_buf->ct, link->ct))
        continue;
    }

    if (variables_buf->rt.s) {
      if (!link->rt.s) continue;
      if (!match_options(variables_buf->rt, link->rt))
        continue;
    }

    if (variables_buf->ifd.s) {
      if (!link->ifd.s) continue;
      if (!match_options(variables_buf->ifd, link->ifd))
        continue;
    }
 
    if (variables_buf->href.s) {
      if (!link->href.s) continue;
      if (!match_options(variables_buf->href, link->href))
        continue;
    }

    if (variables_buf->exp==1) 
      if (link->exp==0)
        continue;
    
    if (variables_buf->ins.s) {
      if (!link->ins.s) continue;
      if (!match_options(variables_buf->ins, link->ins))
        continue;
    }

    if (lk_type == GP){
      if ((g) && (*group_printed==0)){
            buf = lookup_print_group(g, buf, bufend, &len, &offset, lk_type);
            *group_printed = 1;
      }
    }

    if (lk_type != RES) {
      if (!endpoint_printed){
        buf = lookup_print_endpoint(r, buf, bufend, &len, &offset, lk_type);
        endpoint_printed = 1;
      }
    } else {
      buf = lookup_print_endpoint(r, buf, bufend, &len, &offset, lk_type);
    }

    if ((lk_type != D) && (lk_type != GP))
      buf = lookup_print_resource(link, buf, bufend, &len, &offset, lk_type);
  }

  return buf;
}

static coap_print_status_t 
lookup_function(coap_context_t  *ctx, coap_pdu_t *request, unsigned char *buf, size_t len, Option_type lk_type){

  coap_opt_iterator_t opt_iter;
  coap_opt_filter_t filter;
  coap_opt_t *option;
  char *cp, *buf_op; 
  unsigned char *buf_val, *p = buf, *loc;
  coap_print_status_t result = 1;
  char seps[] = "=", *end;

  const unsigned char *bufend = buf + len;
  coap_resource_t *resource = NULL;
  coap_endpoints_t *endpoint;

  coap_variables_t *variables_buf;
  size_t offset = 0;
  str unquoted_val = {0, NULL};
  int page = 0, count = 0, group_printed = 0, loc_size;
  coap_key_t *resource_key = {0};

  if (!ctx || !request || !lk_type)
    return 0;

  /* Create the link structure to store all the variables temporarily*/ 
  #ifdef WITH_LWIP
    variables_buf = (coap_variables_t *)memp_malloc(MEMP_COAP_VARIABLES);
  #endif
  #ifndef WITH_LWIP
    variables_buf = (coap_variables_t *)coap_malloc_type(COAP_VARIABLES, sizeof(coap_variables_t));
  #endif
  if (!variables_buf) {
    debug("lookup_function: no memory left\n");
  }

  memset(variables_buf, 0, sizeof(coap_variables_t));

  /* store query parameters for later use */
  coap_option_filter_clear(filter);
  coap_option_setb(filter, COAP_OPTION_URI_QUERY);

  coap_option_iterator_init((coap_pdu_t *)request, &opt_iter, filter);


  while((option = coap_option_next(&opt_iter))) {

    int length = coap_opt_length(option) + 1;
    buf_op = (char *)coap_malloc(length);
    if (!buf_op) {
      return 0;
    }

    // add \0 to the end of the payload 
    buf_op[length-1] = '\0';

    memcpy(buf_op, coap_opt_value(option), coap_opt_length(option));

    cp = strsep (&buf_op, seps);

    /* Check if the option has a maximum of 63 bytes  */
    if ((buf_op) && strlen(buf_op)>63) {
      debug("lookup_function: debug option is too big\n");
      return 1;
    }

    /* Check if the option has quotation marks ('"'). If so, remove them */
    if ((buf_op) && (buf_op[0] == '"') && (buf_op[strlen(buf_op)-1] == '"')) {          
      unquoted_val.s = (unsigned char *)buf_op + 1;
      unquoted_val.length = strlen(buf_op) - 2;
      unquoted_val.s[unquoted_val.length] = '\0';
    } else {
      unquoted_val.s = (unsigned char *)buf_op;
      unquoted_val.length = (buf_op == NULL) ? 0 : strlen(buf_op);
    }

    if ((*cp != '\0') && (cp != NULL)){
      if (strcmp(cp, "page") == 0) {
          page = (int) strtol((const char *)unquoted_val.s, &end, 10);
          if (*end) {
            /* create response error */
            debug("lookup_function: error cannot convert string to int\n");
            return 0;
          }
      } else if (strcmp(cp, "count") == 0) {
          count = (int) strtol((const char *)unquoted_val.s, &end, 10);
          if (*end) {
            //TODO check the error since is not correct
            /* create response error */
            debug("lookup_function: error cannot convert string to int\n");
            return 0;
          }
      } else if (strcmp(cp, "exp") == 0) {
          variables_buf->exp = COAP_RESOURCE_FLAGS_EXPORT;
      } else {

        buf_val = coap_malloc(unquoted_val.length+1);
        if (!buf_val) {
         return 0;
        }
        memcpy(buf_val, unquoted_val.s, unquoted_val.length);
        buf_val[unquoted_val.length] = '\0';

        if (strcmp(cp, "d") == 0) {
            variables_buf->d.s= buf_val;
            variables_buf->d.length= unquoted_val.length;
        } else if (strcmp(cp, "et") == 0) {
            variables_buf->et.s= buf_val;
            variables_buf->et.length= unquoted_val.length; 
        } else if (strcmp(cp, "ep") == 0) {
            variables_buf->ep.s= buf_val;
            variables_buf->ep.length= unquoted_val.length; 
        } else if (strcmp(cp, "gp") == 0) {
            variables_buf->gp.s= buf_val;
            variables_buf->gp.length= unquoted_val.length; 
        } else if (strcmp(cp, "rel") == 0) {
            variables_buf->rel.s= buf_val;
            variables_buf->rel.length= unquoted_val.length; 
        } else if (strcmp(cp, "ct") == 0) {
            variables_buf->ct.s= buf_val;
            variables_buf->ct.length= unquoted_val.length; 
        } else if (strcmp(cp, "rt") == 0) {
            variables_buf->rt.s= buf_val;
            variables_buf->rt.length= unquoted_val.length; 
        } else if (strcmp(cp, "if") == 0) {
            variables_buf->ifd.s= buf_val;
            variables_buf->ifd.length= unquoted_val.length; 
        } else if (strcmp(cp, "href") == 0) {
            variables_buf->href.s= buf_val;
            variables_buf->href.length= unquoted_val.length; 
        } else if (strcmp(cp, "ins") == 0) {
            variables_buf->ins.s= buf_val;
            variables_buf->ins.length= unquoted_val.length; 
        } else {
            debug("lookup_function: cannot find option\n");
            return 0;
        }
      }
      coap_free(cp);
    }
  }

  if (lk_type == D) {

    /* Search in the list of groups*/
    GROUP_ITER(ctx->groups, group) {

      group_printed = 0;

      /*Query all the attributes of the group*/
      if (variables_buf->d.s) {
        if (!group->d.s) continue;
        if (!match_options(variables_buf->d, group->d))
          continue;
      }

      if (!group_printed){
        p = lookup_print_group(group, p, bufend, &len, &offset, lk_type);
      }
    }

    /* Search the list of endpoints */
    RESOURCES_ITER(ctx->resources, r) {

      p = lookup_resource(variables_buf, r, NULL, p, bufend, len, offset, lk_type, 0);
      if (p == NULL) continue;

    }

  } else if ((variables_buf->gp.s) || (lk_type == GP)){

    /* Search in the list of groups*/
    GROUP_ITER(ctx->groups, group) {

      group_printed = 0;

      /*Query all the attributes of the group*/
      if (variables_buf->d.s) {
        if (!group->d.s) continue;
        if (!match_options(variables_buf->d, group->d))
          continue;
      }

      if (variables_buf->gp.s) {
        if (!group->uri.s) continue;

        //remove the 'rd-group/' from the gp
        unquoted_val.s = group->uri.s + 9;
        unquoted_val.length = group->uri.length - 9;

        if (!match_options(variables_buf->gp, unquoted_val))
          continue;
      }

      /* Search the list of endpoints of a particular group*/
      LL_FOREACH(group->endpoints, endpoint) {

        /*Look for the endpoint*/
        if (!endpoint->ep.s) continue;

        unquoted_val = remove_cotation_marks(endpoint->ep);

        loc = (unsigned char *)coap_malloc(LOCSIZE);
        if (!loc) {
          return 0;
        }
        memcpy(loc, RD_ROOT_STR, RD_ROOT_SIZE);

        loc_size = RD_ROOT_SIZE;

        loc[loc_size++] = '/';
        loc[loc_size] = '\0';

        resource_key =  coap_build_key_for_resource(unquoted_val, loc, LOCSIZE);

        coap_free(loc);

        if (!(resource = coap_get_resource_from_key(ctx, (unsigned char *)resource_key))) {
          coap_free(resource_key);
          continue; 
        }
        coap_free(resource_key);

        /*Query all the attributes of the endpoint*/
        p = lookup_resource(variables_buf, resource, group, p, bufend, len, offset, lk_type, &group_printed);
        if (p == NULL) continue;
        
      }

      if (lk_type == GP){
        if (!group_printed){
          p = lookup_print_group(group, p, bufend, &len, &offset, lk_type);
        }
      }
    }
  } else { 

    /* Search the list of endpoints */
    RESOURCES_ITER(ctx->resources, r) {

      p = lookup_resource(variables_buf, r, NULL, p, bufend, len, offset, lk_type, 0);
      if (p == NULL) continue;

    }
  }

  result = p - buf;

  if (result == 0){
    p[0] = '\0';
    result = result + 1;
  }

  //Delete the struct
  coap_delete_variable(variables_buf);

  return result;
}

static void
hnd_get_rd(coap_context_t  *ctx,
           struct coap_resource_t *resource UNUSED_PARAM,
           const coap_endpoint_t *local_interface UNUSED_PARAM,
           coap_address_t *peer UNUSED_PARAM,
           coap_pdu_t *request,
           str *token UNUSED_PARAM,
           coap_pdu_t *response) {

  coap_print_status_t result = 0;

  coap_opt_iterator_t opt_iter;
  coap_opt_filter_t filter;
  coap_opt_t *option;
  
  size_t len = 0;
  unsigned char buf[3];
  Option_type type = 0;

  len = response->max_size - response->length;

  /* store path parameters for later use */
  coap_option_filter_clear(filter);
  coap_option_setb(filter, COAP_OPTION_URI_PATH);

  coap_option_iterator_init((coap_pdu_t *)request, &opt_iter, filter);

  while ((option = coap_option_next(&opt_iter))){

    if (strncmp((const char *)coap_opt_value(option), "rd-lookup", 9) == 0){

      option = coap_option_next(&opt_iter);

      if (!option) break;
#if defined (COAP_TEST_ELEMENTS)
      if (coap_opt_size(option)<=1) break;
#endif
      if ((coap_opt_length(option) == 1) && strncmp((const char *)coap_opt_value(option), "d", 1) == 0){
        type = D;
      } else if ((coap_opt_length(option) == 2) && strncmp((const char *)coap_opt_value(option), "ep", 2) == 0){
        type = EP;
      } else if ((coap_opt_length(option) == 3) && strncmp((const char *)coap_opt_value(option), "res", 3) == 0){
        type = RES;
      } else if ((coap_opt_length(option) == 2) && strncmp((const char *)coap_opt_value(option), "gp", 2) == 0){
        type = GP;
/*TODO Remove the 10 (LT) option later. It is only for testing purpose*/
      } else if ((coap_opt_length(option) == 2) && strncmp((const char *)coap_opt_value(option), "lt", 2) == 0){
        type = 10;
      }else {
        response->hdr->code = COAP_RESPONSE_CODE(400);
        return;
      }
       
    } else {
      response->hdr->code = COAP_RESPONSE_CODE(400);
      return;
    }
  }

  response->hdr->code = COAP_RESPONSE_CODE(205);

  coap_add_option(response,
                  COAP_OPTION_CONTENT_TYPE,
                  coap_encode_var_bytes(buf,
                                        COAP_MEDIATYPE_APPLICATION_LINK_FORMAT),
                                        buf);

  /* Manually set payload of response to let lookup() write,
   * into our buffer without copying data. */

  response->data = (unsigned char *)response->hdr + response->length;
  *response->data = COAP_PAYLOAD_START;
  response->data++;
  response->length++;

#if defined (COAP_TEST_ELEMENTS)
  if (type == 0){ /* TESTING PROPOSE: Print all the information in the Resource Directory */
    result = lookup_print_all(ctx, response->data, &len, 0);
  } else if (type == 10){
    result = coap_display_lifetime(ctx, response->data, &len, 0);
  } else {
    result = lookup_function(ctx, request, response->data, len, type);
  }
#else
    result = lookup_function(ctx, request, response->data, len, type);
#endif

  if ((result)  == 0) {
    response->hdr->code = COAP_RESPONSE_CODE(404);
    response->length = sizeof(coap_hdr_t) + response->hdr->token_length;
    return;
  }
 
  response->length += COAP_PRINT_OUTPUT_LENGTH(result);

  return;

}

static void
hnd_post_rd(coap_context_t  *ctx,
            struct coap_resource_t *resource UNUSED_PARAM,
            const coap_endpoint_t *local_interface UNUSED_PARAM,
            coap_address_t *peer,
            coap_pdu_t *request,
            str *token UNUSED_PARAM,
            coap_pdu_t *response) {

  coap_resource_t *r;
  coap_opt_iterator_t opt_iter;
  coap_opt_t *query, *block_opt = NULL; 
  coap_opt_filter_t filter;

  unsigned char loc[LOCSIZE], *uri, *buf, *payload=NULL, block_buf[4];
  size_t loc_size, uri_size, key_size, payload_length;
  str rt = {0, NULL}, lt = {0, NULL}, ep = {0, NULL}, d = {0, NULL}, et = {0, NULL}, con = {0, NULL}; /* store query parameters */
  coap_key_t *resource_key = {0};

  char *cp, *buf_address, *buf_op, seps[] = "=", *ext_addr = NULL;
  int val_offset = 0, delete = 0;
  time_t sec;
  char *address_peer = NULL;
  coap_block1_t *result= NULL;
  char *NAT_addr = NULL;

  /* Got some data, check if block1 option is set. */
  block_opt = coap_check_option(request, COAP_OPTION_BLOCK1, &opt_iter);

  if (block_opt) { 
    /* handle Block1 */
    if (!(result = coap_process_block1(request, response))) return;

  }

  memcpy(loc, RD_ROOT_STR, RD_ROOT_SIZE);

  loc_size = RD_ROOT_SIZE;
  loc[loc_size++] = '/';
  loc[loc_size] = '\0';

  /* store query parameters for later use */

  coap_option_filter_clear(filter);
  coap_option_setb(filter, COAP_OPTION_URI_QUERY);

  coap_option_iterator_init(request, &opt_iter, filter);

  while((query = coap_option_next(&opt_iter))) {

    int length = coap_opt_length(query);

    buf_op = (char *)coap_malloc(length + 1);
    if (!buf_op) {
      return;
    }

    memcpy(buf_op, coap_opt_value(query), length);
    buf_op[length] = '\0';

    cp = strsep (&buf_op, seps);
   
    val_offset = buf_op - cp;

    if ((*cp != '\0') && (cp != NULL)){
      if (buf_op == NULL) {
          response->hdr->code = COAP_RESPONSE_CODE(400);
          coap_free(cp);
          return;
      }

      if (strcmp(cp, "ep") == 0) { 
          ep.s= (unsigned char *) coap_opt_value(query) + val_offset;
          ep.length= strlen(buf_op);        
      } else if (strcmp(cp, "d") == 0) {
          d.s= (unsigned char *) coap_opt_value(query) + val_offset;
          d.length= strlen(buf_op);        
      } else if (strcmp(cp, "et") == 0) {
          et.s= (unsigned char *) coap_opt_value(query) + val_offset;
          et.length= strlen(buf_op);        
      } else if (strcmp(cp, "lt") == 0) {
          lt.s= (unsigned char *) coap_opt_value(query) + val_offset;
          lt.length= strlen(buf_op);        
      } else if (strcmp(cp, "con") == 0) {
          con.s= (unsigned char *) coap_opt_value(query) + val_offset;
          con.length= strlen(buf_op);        
      } else if (strcmp(cp, "rt") == 0) {
          rt.s= (unsigned char *) coap_opt_value(query) + val_offset;
          rt.length= strlen(buf_op);        
      } else {
          debug("hnd_post_rd: cannot find option\n");
          response->hdr->code = COAP_RESPONSE_CODE(400);
          coap_free(cp);
          return;
      }
    }
    coap_free(cp);
  }

  if ((ep.length) && (ep.length<=63)) {   /* client has specified an endpoint name */

    /* try to find the resource from the request URI */        
    resource_key =  coap_build_key_for_resource(ep, loc, LOCSIZE);

    /* If the resource already exist, we delete it and create it again*/
    if (coap_get_resource_from_key(ctx, (unsigned char *)resource_key)!=NULL) {
      delete = 1;
      debug("hnd_post_rd: the resource already exist, we delete it and create a new one\n");
    }

  } else {   /* create response error */
    response->hdr->code = COAP_RESPONSE_CODE(400);
    coap_free(resource_key);
    return;
  }

  /* Create a new uri rd/ep-name */
  uri = (unsigned char *)coap_malloc(LOCSIZE);
  if (!uri) {
    response->hdr->code = COAP_RESPONSE_CODE(503);
    coap_free(resource_key);
    return;
  }  
  memcpy(uri, RD_ROOT_STR, RD_ROOT_SIZE);

  uri_size = RD_ROOT_SIZE;
  uri[uri_size++] = '/';

  memcpy(uri + uri_size, ep.s, min(ep.length, LOCSIZE - uri_size - 1));
  uri_size += min(ep.length, LOCSIZE - uri_size - 1);
  uri[uri_size] = '\0';
  key_size = strlen((const char *)loc);

  r = coap_resource_rd_init(uri, uri_size, loc, key_size, COAP_RESOURCE_FLAGS_RELEASE_URI);

  if (r == NULL){
    response->hdr->code = COAP_RESPONSE_CODE(503);
    coap_free_resource(r);
    coap_free(resource_key);
    return;
  }

  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_resource);
  coap_register_handler(r, COAP_REQUEST_POST, hnd_post_resource);
  coap_register_handler(r, COAP_REQUEST_DELETE, hnd_delete_resource);

  /* Add expiration to the resource */

  unsigned long ltime = 86400;

  if ((lt.length)) {
    char *time_s = NULL, *end = NULL;
    time_s = coap_malloc(lt.length+1);
    if (!time_s) {
      response->hdr->code = COAP_RESPONSE_CODE(503);
      coap_free_resource(r);
      coap_free(resource_key);
      return;
    }
  
    memcpy(time_s, lt.s, lt.length);
    time_s[lt.length] = 0;
    errno = 0; /* To distinguish success/failure after call */

    ltime = strtol((const char *)time_s, &end, 10);

    if ((ltime > UINT_MAX) || (ltime < 60) || (errno == ERANGE && (ltime == LONG_MAX || ltime == 0))
                   || (errno != 0 && ltime == 0)) {
      /* Out of range, create response error */
      debug("hnd_post_rd: lt is out of range\n");
      response->hdr->code = COAP_RESPONSE_CODE(400);
      coap_free_resource(r);
      coap_free(time_s);
      coap_free(resource_key);
      return;
    }

    if (end != (const char *)time_s) {
      coap_add_lifetime(ctx, r,ltime);
    }

    coap_free(time_s);

  } else {
    coap_add_lifetime(ctx, r,ltime);
  }



  /* Add the attributes to the resource */

/*  if (ins.s) {
    buf = (unsigned char *)coap_malloc(ins.length + 2);
    if (buf) {
  */    /* add missing quotes */
 /*     buf[0] = '"';
      memcpy(buf + 1, ins.s, ins.length);
      buf[ins.length + 1] = '"';
      coap_add_attr(r,
                    (unsigned char *)"ins",
                    3,
                    buf,
                    ins.length + 2,
                    COAP_ATTR_FLAGS_RELEASE_VALUE);
    } else {
      response->hdr->code = COAP_RESPONSE_CODE(503);
      return;
    }
  }*/


  if (rt.s) {
    buf = (unsigned char *)coap_malloc(rt.length + 2);
    if (buf) {
      /* add missing quotes */
      buf[0] = '"';
      memcpy(buf + 1, rt.s, rt.length);
      buf[rt.length + 1] = '"';
      coap_add_attr(r,
                    (unsigned char *)"rt",
                    2,
                    buf,
                    rt.length + 2,COAP_ATTR_FLAGS_RELEASE_VALUE);
    } else {
      response->hdr->code = COAP_RESPONSE_CODE(503);
      coap_free_resource(r);
      coap_free(resource_key);
      return;
    }
  }

  if ((d.s) && (d.length<=63)) {
    buf = (unsigned char *)coap_malloc(d.length + 2);
    if (buf) {
      /* add missing quotes */
      buf[0] = '"';
      memcpy(buf + 1, d.s, d.length);
      buf[d.length + 1] = '"';
      coap_add_attr(r,
                    (unsigned char *)"d",
                    1,
                    buf,
                    d.length + 2,COAP_ATTR_FLAGS_RELEASE_VALUE);
    } else {
      response->hdr->code = COAP_RESPONSE_CODE(503);
      coap_free_resource(r);
      coap_free(resource_key);
      return;
    }
  }

  if ((et.s) && (et.length<=63)) {
    buf = (unsigned char *)coap_malloc(et.length + 2);
    if (buf) {
      /* add missing quotes */
      buf[0] = '"';
      memcpy(buf + 1, et.s, et.length);
      buf[et.length + 1] = '"';
      coap_add_attr(r,
                    (unsigned char *)"et",
                    2,
                    buf,
                    et.length + 2,COAP_ATTR_FLAGS_RELEASE_VALUE);
    } else {
      response->hdr->code = COAP_RESPONSE_CODE(503);
      coap_free_resource(r);
      coap_free(resource_key);
      return;
    }
  }

  if ((con.s) && (con.length<=63)) {
    buf = (unsigned char *)coap_malloc(con.length + 2);
    if (buf) {
      /* add missing quotes */
      buf[0] = '"';
      memcpy(buf + 1, con.s, con.length);
      buf[con.length + 1] = '"';
      coap_add_attr(r,
                    (unsigned char *)"con",
                    3,
                    buf,
                    con.length + 2,COAP_ATTR_FLAGS_RELEASE_VALUE);
    } else {
      response->hdr->code = COAP_RESPONSE_CODE(503);
      coap_free_resource(r);
      coap_free(resource_key);
      return;
    } 
  }


  /* read the payload */
  if (block_opt) { 
    if (result){
      payload = result->payload;
    }
  } else {
    /* read the payload */
    if (request->data){
      if (coap_get_data(request, &payload_length, &payload)) {
        if (payload) {
          // add \0 to the end of the payload 
          payload[payload_length-1] = '\0';
        }
      }
    }
  }

  if (payload){
    if (!read_payload(request, r, payload, 0)) {
      /* create response error */
      response->hdr->code = COAP_RESPONSE_CODE(400);
      coap_free_resource(r);
      coap_free(resource_key);
      return;
    }
  }


  if ((buf_address = add_source_address(peer))!= NULL){
    r->A.s= (unsigned char *)buf_address;
    r->A.length= strlen(buf_address);
  } else {
    /* create response error */
    response->hdr->code = COAP_RESPONSE_CODE(503);
      coap_free_resource(r);
      coap_free(resource_key);
      return;
  }

  /* Create rule in the NAT table*/
  if (pcp_nat){

    /* Current time in seconds */
    sec = time(NULL);

    sec = sec + (time_t)ltime;

    address_peer = get_source_address(peer);

    if (coap_find_same_address(ctx, address_peer, sec, &ext_addr)){
      add_NAT_rule(r, ltime, address_peer, ext_addr, sec);
    } else {
      //Copy the NATTING information into the node
      if (ext_addr){
        int len = strlen((char *)ext_addr);

        NAT_addr = (char *) coap_malloc(len +1);//+1 for the zero-terminator
        if (!NAT_addr) return;

        memcpy(NAT_addr, ext_addr, len+1);//+1 to copy the null-terminator

        r->NAT.s= (unsigned char *)NAT_addr;
        r->NAT.length= strlen(NAT_addr);
        r->NAT_lifetime= sec;
      }
    }
    coap_free(address_peer);
  }

  if (delete) {
    coap_delete_resource(ctx, (unsigned char *)resource_key);
  }
  coap_free(resource_key);

  coap_add_resource(ctx, r);

  /* create response */

  response->hdr->code = COAP_RESPONSE_CODE(201);

  /* split path into segments and add Location-Path options */
  unsigned char _b[LOCSIZE];
  unsigned char *b = _b;
  size_t buflen = LOCSIZE;
  int nseg;

  nseg = coap_split_path(loc, key_size, b, &buflen);

  while (nseg--) {
    coap_add_option(response,
                    COAP_OPTION_LOCATION_PATH,
                    coap_opt_length(b),
                    coap_opt_value(b));
    b += COAP_OPT_SIZE(b);
  }

  if (block_opt) { 
    if (result){
      coap_add_option(response,
                      COAP_OPTION_BLOCK1,
                      coap_encode_var_bytes(block_buf,
                             ((result->num) << 4) | result->m << 3 |
                              result->szx), block_buf);
      delete_block(result);
    }
  }

  /*If DEBUG active, print the response */
  if (LOG_DEBUG <= coap_get_log_level()) {
    coap_show_pdu(response);
  }

}

static void
init_resources(coap_context_t *ctx) {
  coap_resource_t *r, *l, *g;


  /* </rd>;rt="core.rd"*/
  r = coap_resource_init(RD_ROOT_STR, RD_ROOT_SIZE, 0);
  coap_register_handler(r, COAP_REQUEST_POST, hnd_post_rd);

  coap_add_attr(r, (unsigned char *)"rt", 2, (unsigned char *)"\"core.rd\"", 9, 0);
  coap_add_attr(r, (unsigned char *)"ct", 2, (unsigned char *)"40", 2, 0);

  coap_add_resource(ctx, r);

  /*</rd-lookup>;rt="core.rd-lookup"*/
  l = coap_resource_init(RD_LOOKUP_STR, RD_LOOKUP_SIZE, 0);
  coap_register_handler(l, COAP_REQUEST_GET, hnd_get_rd);

  coap_add_attr(l, (unsigned char *)"rt", 2, (unsigned char *)"\"core.rd-lookup\"", 16, 0);
  coap_add_attr(l, (unsigned char *)"ct", 2, (unsigned char *)"40", 2, 0);

  coap_add_resource(ctx, l);

  /* </rd-group>;rt="core.rd-group"*/
  g = coap_resource_init(RD_GROUP_STR, RD_GROUP_SIZE, 0);
  coap_register_handler(g, COAP_REQUEST_POST, hnd_post_rd_group);

  coap_add_attr(g, (unsigned char *)"rt", 2, (unsigned char *)"\"core.rd-group\"", 15, 0);
  coap_add_attr(g, (unsigned char *)"ct", 2, (unsigned char *)"40", 2, 0);

  coap_add_resource(ctx, g);

  if (ctx)
    ctx->init_mod_coap_rd = 1;

  coap_lifetime_init(ctx);
}

/**********************************************************/
/***                         MAIN                       ***/
/**********************************************************/

static void
usage( const char *program, const char *version) {
  const char *p;

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf( stderr, "%s v%s -- CoRE Resource Directory implementation\n"
     "(c) 2011-2016 Olaf Bergmann <bergmann@tzi.org>\n\n"
     "usage: %s [-A address] [-p port]\n\n"
     "\t-A address\tinterface address to bind to\n"
     "\t-g address\tmulticast group address\n"
     "\t-p port\t\tlisten on specified port\n"
     "\t-v num\t\tverbosity level (default: 3)\n"
     "\n"
     "examples:\n"
     "\tcoap-rd -A [::1]\n",
     program, version, program );
}

static coap_context_t *
get_context(const char *node, const char *port) {
  coap_context_t *ctx = NULL;
  int s;
  struct addrinfo hints;
  struct addrinfo *result, *rp;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
  hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

  s = getaddrinfo(node, port, &hints, &result);
  if ( s != 0 ) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    return NULL;
  }

  /* iterate through results until success */
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    coap_address_t addr;

    if (rp->ai_addrlen <= sizeof(addr.addr)) {
      coap_address_init(&addr);
      addr.size = rp->ai_addrlen;
      memcpy(&addr.addr, rp->ai_addr, rp->ai_addrlen);

      ctx = coap_new_context(&addr);
      if (ctx) {
        /* TODO: output address:port for successful binding */
        goto finish;
      }
    }
  }

  fprintf(stderr, "no context available for interface '%s'\n", node);

 finish:
  freeaddrinfo(result);
  return ctx;
}

static int
join(coap_context_t *ctx, char *group_name) {
  struct ipv6_mreq mreq;
  struct addrinfo   *reslocal = NULL, *resmulti = NULL, hints, *ainfo;
  int result = -1;

  /* we have to resolve the link-local interface to get the interface id */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_DGRAM;

  result = getaddrinfo("::", NULL, &hints, &reslocal);
  if ( result < 0 ) {
    perror("join: cannot resolve link-local interface");
    goto finish;
  }

  /* get the first suitable interface identifier */
  for (ainfo = reslocal; ainfo != NULL; ainfo = ainfo->ai_next) {
    if ( ainfo->ai_family == AF_INET6 ) {
      mreq.ipv6mr_interface =
              ((struct sockaddr_in6 *)ainfo->ai_addr)->sin6_scope_id;
      break;
    }
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_DGRAM;

  /* resolve the multicast group address */
  result = getaddrinfo(group_name, NULL, &hints, &resmulti);

  if ( result < 0 ) {
    perror("join: cannot resolve multicast address");
    goto finish;
  }

  for (ainfo = resmulti; ainfo != NULL; ainfo = ainfo->ai_next) {
    if ( ainfo->ai_family == AF_INET6 ) {
      mreq.ipv6mr_multiaddr =
        ((struct sockaddr_in6 *)ainfo->ai_addr)->sin6_addr;
      break;
    }
  }

  result = setsockopt(ctx->sockfd,
                      IPPROTO_IPV6, IPV6_JOIN_GROUP,
                      (char *)&mreq, sizeof(mreq) );
  if ( result < 0 )
    perror("join: setsockopt");

 finish:
  freeaddrinfo(resmulti);
  freeaddrinfo(reslocal);

  return result;
}

int
main(int argc, char **argv) {

  coap_context_t  *ctx;
  fd_set readfds;
  struct timeval tv, *timeout;
  int result;
  coap_tick_t now;
  coap_queue_t *nextpdu;
  char addr_str[NI_MAXHOST] = "::";
  char port_str[NI_MAXSERV] = "5683";
  char *group = NULL;
  int opt;

  coap_log_t log_level = LOG_WARNING;


  /*Upload the data from the config file*/
  upload_config_file();

  while ((opt = getopt(argc, argv, "A:g:p:v:")) != -1) {
    switch (opt) {
    case 'A' :
      strncpy(addr_str, optarg, NI_MAXHOST-1);
      addr_str[NI_MAXHOST - 1] = '\0';
      break;
    case 'g' :
      group = optarg;
      break;
    case 'p' :
      strncpy(port_str, optarg, NI_MAXSERV-1);
      port_str[NI_MAXSERV - 1] = '\0';
      break;
    case 'v' :
      log_level = strtol(optarg, NULL, 10);
      break;
    default:
      usage( argv[0], PACKAGE_VERSION );
      exit( 1 );
    }
  }

  if (optind ==1) { /* No options */
    usage( argv[0], PACKAGE_VERSION );
    exit( 1 );
  }

  coap_set_log_level(log_level);

  ctx = get_context(addr_str, port_str);
  if (!ctx)
    return -1;

  if (group)
    join(ctx, group);

  init_resources(ctx);

  signal(SIGINT, handle_sigint);

  while ( !quit ) {

    FD_ZERO(&readfds);
    FD_SET( ctx->sockfd, &readfds );

    nextpdu = coap_peek_next( ctx );

    coap_ticks(&now);
    while ( nextpdu && nextpdu->t <= now ) {
      coap_retransmit( ctx, coap_pop_next( ctx ) );
      nextpdu = coap_peek_next( ctx );
    }

    if ( nextpdu && nextpdu->t <= now + COAP_RESOURCE_CHECK_TIME ) {
      /* set timeout if there is a pdu to send before our automatic
         timeout occurs */
      tv.tv_usec = ((nextpdu->t - now) % COAP_TICKS_PER_SECOND) * 1000000 / COAP_TICKS_PER_SECOND;
      tv.tv_sec = (nextpdu->t - now) / COAP_TICKS_PER_SECOND;
      timeout = &tv;
    } else {
      tv.tv_usec = 0;
      tv.tv_sec = COAP_RESOURCE_CHECK_TIME;
      timeout = &tv;
    }
    result = select( FD_SETSIZE, &readfds, 0, 0, timeout );

    /*remove resources that have tiemout*/

    /* Current time in seconds */
    time_t time_t = time(NULL);

    coap_timeout(ctx, time_t);

    if ( result < 0 ) {     /* error */
      if (errno != EINTR)
        perror("select");
      } else if ( result > 0 ) {  /* read from socket */
        if ( FD_ISSET( ctx->sockfd, &readfds ) ) {
          coap_read( ctx ); /* read received data */
          /* coap_dispatch( ctx );  /\* and dispatch PDUs from receivequeue *\/ */
        }
      } else {            /* timeout */
        /* coap_check_resource_list( ctx ); */
    }
  }

  coap_free_context( ctx );

  return 0;
}
