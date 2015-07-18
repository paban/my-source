# Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ $(LOCAL_OPTS) -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

sbin_PROGRAMS = ldpd

ldpd_SOURCES = \
impl_fib.c impl_ifmgr.c impl_lock.c impl_mm.c impl_mpls.c \
impl_policy.c impl_socket.c impl_timer.c impl_tree.c \
ldp_zebra.c ldp_main.c \
ldp.c ldp_interface.c ldp_vty.c ldp_remote_peer.c l2cc_interface.c \
ldp_addr.c ldp_adj.c \
ldp_attr.c ldp_buf.c ldp_cfg.c ldp_entity.c ldp_fec.c ldp_global.c \
ldp_hello.c ldp_hop.c ldp_hop_list.c ldp_if.c ldp_inet_addr.c \
ldp_init.c ldp_inlabel.c ldp_keepalive.c ldp_label_abort.c \
ldp_label_mapping.c ldp_label_rel_with.c ldp_label_request.c \
ldp_mesg.c ldp_nortel.c ldp_notif.c ldp_outlabel.c \
ldp_pdu_setup.c ldp_peer.c \
ldp_resource.c ldp_session.c ldp_state_funcs.c \
ldp_state_machine.c ldp_tunnel.c ldp_nexthop.c\
mpls_compare.c


noinst_HEADERS = \
ldp_zebra.h \
ldp.h ldp_interface.h ldp_vty.h ldp_remote_peer.h l2cc_interface.h \
ldp_addr.h ldp_adj.h ldp_attr.h ldp_buf.h ldp_cfg.h \
ldp_defaults.h ldp_entity.h ldp_fec.h \
ldp_global.h mpls_handle_type.h ldp_hello.h ldp_hop.h \
ldp_hop_list.h ldp_if.h ldp_inet_addr.h \
ldp_init.h ldp_inlabel.h ldp_keepalive.h ldp_label_abort.h \
ldp_label_mapping.h ldp_label_rel_with.h ldp_label_request.h \
ldp_mesg.h ldp_nortel.h ldp_notif.h ldp_outlabel.h ldp_pdu.h ldp_nexthop.h \
ldp_pdu_setup.h ldp_peer.h mpls_refcnt.h ldp_resource.h \
ldp_session.h ldp_state_machine.h ldp_struct.h ldp_tunnel.h \
mpls_tree_impl.h mpls_mm_impl.h mpls_mpls_impl.h mpls_trace_impl.h \
mpls_assert.h mpls_fib_impl.h mpls_ifmgr_impl.h mpls_list.h mpls_lock_impl.h \
mpls_policy_impl.h mpls_socket_impl.h mpls_timer_impl.h mpls_trace.h \
mpls_struct.h mpls_compare.h mpls_bitfield.h

ldpd_LDADD = -L../lib -lzebra @LIBCAP@

sysconf_DATA = ldpd.conf.sample

EXTRA_DIST = $(sysconf_DATA)

install-sysconfDATA: $(sysconf_DATA)
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)
	@list='$(sysconf_DATA)'; for p in $$list; do \
	  if test -f $(srcdir)/$$p; then \
	    echo " $(INSTALL_SDATA) $(srcdir)/$$p $(DESTDIR)$(sysconfdir)/$$p"; \
	    $(INSTALL_SDATA) $(srcdir)/$$p $(DESTDIR)$(sysconfdir)/$$p; \
	  else if test -f $$p; then \
	    echo " $(INSTALL_SDATA) $$p $(DESTDIR)$(sysconfdir)/$$p"; \
	    $(INSTALL_SDATA) $$p $(DESTDIR)$(sysconfdir)/$$p; \
	  fi; fi; \
	done
