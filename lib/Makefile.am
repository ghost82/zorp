SUBDIRS = . zorp

LIBS = @LIBZORP_LIBS@

lib_LTLIBRARIES = libzorp.la

libzorp_la_LDFLAGS = \
	-version-info $(LIBZORP_LT_COMPAT_PL) \
	-release $(LIBZORP_LT_RELEASE) \
	-export-dynamic

libzorp_la_SOURCES = \
	proxy.cc proxystack.cc modules.cc  \
	pycore.cc pysockaddr.cc pypolicy.cc \
	pyproxy.cc pystream.cc \
	zorp.cc \
	authprovider.cc \
	tpsocket.cc dimhash.cc \
	szig.cc \
	pydispatch.cc dispatch.cc \
	attach.cc connection.cc pyattach.cc \
	plugsession.cc  zpython.cc \
	dgram.cc \
	pydict.cc pystruct.cc \
	ifmonitor.cc proxygroup.cc pyproxygroup.cc \
	coredump.cc \
	proxyssl.cc pyx509.cc proxysslhostiface.cc \
	kzorp.cc \
	certchain.cc pyx509chain.cc \
	session.cc

