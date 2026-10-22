include $(top_srcdir)/modules.am

SUBDIRS = .
noinst_HEADERS = transport_erspan.h

transport_erspan_la_SOURCES = transport_erspan.c
transport_erspan_la_CFLAGS = -Wall ${MODULE_CFLAGS}
transport_erspan_la_LDFLAGS = -module -avoid-version
transport_erspan_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${PCAP_LIBS}
transport_erspan_laconfdir = $(confdir)
transport_erspan_laconf_DATA = $(top_srcdir)/conf/transport_erspan.xml

mod_LTLIBRARIES = transport_erspan.la
