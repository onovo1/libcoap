# examples/Makefile.am
#
# Copyright (C)      2015 Carsten Schoenert <c.schoenert@t-online.de>
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.

# just enter if 'BUILD_MODCLIENT' is defined
if BUILD_MODCLIENT

# picking up the default warning CFLAGS into AM_CFLAGS
#AM_CFLAGS = $(RE_CFLAGS) $(REW_CFLAGS) -isystem@top_builddir@/include/coap/ $(WARNING_CFLAGS) -std=c99
AM_CFLAGS = -isystem@top_builddir@/include/coap/ $(WARNING_CFLAGS) -std=c99

bin_PROGRAMS = coap-client-mod coap-client coap-server 

coap_client_mod_SOURCES = coap-client-mod.c coap_list.c
coap_client_mod_LDADD = @top_builddir@/.libs/libcoap-$(LIBCOAP_API_VERSION).la

coap_client_SOURCES = client.c coap_list.c
coap_client_LDADD = @top_builddir@/.libs/libcoap-$(LIBCOAP_API_VERSION).la

coap_server_SOURCES = coap-server.c
coap_server_LDADD = @top_builddir@/.libs/libcoap-$(LIBCOAP_API_VERSION).la

else 

# just do nothing if 'BUILD_EXAMPLES' isn't defined
if BUILD_EXAMPLES

# picking up the default warning CFLAGS into AM_CFLAGS
AM_CFLAGS = $(RE_CFLAGS) $(REW_CFLAGS) -isystem$(top_builddir)/include/coap -I$(top_srcdir)/include/coap $(WARNING_CFLAGS) -std=c99
AM_LDFLAGS = $(RE_LIBS) $(REW_LIBS)

# etsi_iot_01 and tiny are missing
bin_PROGRAMS = coap-client coap-server coap-rd

coap_client_SOURCES = client.c coap_list.c
coap_client_LDADD = $(top_builddir)/.libs/libcoap-$(LIBCOAP_API_VERSION).la

coap_server_SOURCES = coap-server.c
coap_server_LDADD = $(top_builddir)/.libs/libcoap-$(LIBCOAP_API_VERSION).la

#coap_rd_SOURCES = coap-rd.c mjson.c rd_list_elements.c
coap_rd_SOURCES = coap-rd.c mjson.c pcp_client.c
coap_rd_LDADD = $(top_builddir)/.libs/libcoap-$(LIBCOAP_API_VERSION).la

# build manuals only if 'BUILD_DOCUMENTATION' is defined
if BUILD_DOCUMENTATION

# building the manpages
TXT5 = coap-client.txt \
       coap-rd.txt \
       coap-server.txt

MAN5 = $(TXT5:%.txt=%.5)

man5_MANS = $(MAN5)

.txt.5:
	$(A2X) --doctype manpage --format manpage $<

CLEANFILES = *.5
endif # BUILD_DOCUMENTATION

endif # BUILD_EXAMPLES

endif # MODCLIENT
