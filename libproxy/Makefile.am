SUBDIRS = zorp

LIBS = @DEPS_LIBS@ @ZORP_LIBS@
lib_LTLIBRARIES = libzorpproxy.la

libzorpproxy_la_PRO_SOURCES =

libzorpproxy_la_LDFLAGS =	\
	-version-info $(LIBZORP_LT_COMPAT_PL) \
	-release $(LIBZORP_LT_RELEASE)	\
	-export-dynamic

libzorpproxy_la_SOURCES = 		\
	dottransfer.cc			\
	errorloader.cc			\
	transfer2.cc                     \
        $(libzorpproxy_la_PRO_SOURCES)
