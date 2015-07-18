## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib @SNMP_INCLUDES@
DEFS = @DEFS@ $(LOCAL_OPTS) -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

sbin_PROGRAMS = rsvpd

rsvpd_SOURCES = rsvp_main.c \
	rsvp_decode.c  rsvp_path.c    rsvp_utilities.c \
	rsvp_encode.c  rsvp_resv.c    rsvp_vty.c \
	rsvp_socket.c  rsvp_zebra.c   rsvp_api.c \
	te_api.c te_bw_man.c te_common.c \
	te_lib.c te_crr.c    te_lsp.c \
	te_rdb.c te_tr.c \
	patricia.c messages.c

rsvpdheaderdir = $(pkgincludedir)/rsvpd

noinst_HEADERS =
	rsvp_encode.h    rsvp_socket.h  rsvp.h  te_lib.h \
	rsvp_api.h       rsvp_packet.h  rsvp_utilities.h \
	rsvp_psb.h       rsvp_vty.h     rsvp_decode.h    rsvp_rsb.h \
	rsvp_zebra.h \
	general.h        messages.h     patricia.h \
	te_api.h te_bw_man.h te_common.h te_crr.h te_cspf.h \
	te_frr.h te.h        te_lsp.h    te_rdb.h te_tr.h

rsvpd_LDADD = ../lib/libzebra.la @LIBCAP@

EXTRA_DIST =

examplesdir = $(exampledir)
dist_examples_DATA =
