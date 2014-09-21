Name:                   zorp
Version:                5.0
Release:                1
URL:                    https://www.balabit.com/network-security/zorp-gpl
Source0:                zorp_%{version}.0.tar.gz
Summary:                An advanced protocol analyzing firewall
License:                GPL-2.0
Group:                  System/Daemons
BuildRequires:          binutils-devel
BuildRequires:          automake
BuildRequires:          autoconf
BuildRequires:          libtool
BuildRequires:          gcc-c++
BuildRequires:          libzorpll-5_0-0-devel
BuildRequires:          python-devel
BuildRequires:          binutils-devel
BuildRequires:          glib2-devel
BuildRequires:          zlib-devel
BuildRequires:          gperf

Requires:               zorp-base
Requires:               python-zorp-base
Requires:               py-radix
Requires:               python-pydns
%if 0%{?fedora} || 0%{?rhel} || 0%{?centos}
Requires:               pyOpenSSL
Requires(pre):          shadow-utils
%else
Requires:               python-pyOpenSSL
Requires(pre):          pwdutils
Requires(pre):          shadow
%endif

%{!?__python2: %global __python2 /usr/bin/python2}
%global __python %{__python2}

%{!?python2_sitelib: %global python2_sitelib %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}
%{!?python2_sitearch: %global python2_sitearch %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib(1))")}

BuildRoot:              %{_tmppath}/%{name}-%{version}-build

%description
Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions
are scriptable with the Python based configuration language.

Zorp has been successfully deployed in demanding environments like the
protection of high traffic web sites, or the protection of large intranets.
Since the protocol analysis is strict and many of the common exploits
violate the application protocol they are injected into, a large percentage
of the attacks do not cross a Zorp based firewall even if the given service
is permitted.

%package devel
Summary:                Headers for zorp
Group:                  System/Daemons
Requires:               libzorpll-5_0-0-devel

%description devel
This package provides header files for zorp

%prep
%setup -q -n zorp

%build
./autogen.sh
%configure --disable-werror \
--prefix=/usr \
--mandir=%{_mandir} \
--infodir=%{_datadir}/info \
--with-pidfiledir=%{_localstatedir}/run/zorp/ \
--localstatedir=%{_sharedstatedir}/zorp \
--sysconfdir=%{_sysconfdir}

%install
make DESTDIR=${RPM_BUILD_ROOT} install

%pre
getent group zorp >/dev/null || groupadd -r zorp
getent passwd zorp >/dev/null || useradd -r -g zorp -d /var/run/zorp -s /bin/bash -c "user for Zorp" zorp

%post
ldconfig

%postun
ldconfig

%files
%defattr(-,root,root)

%attr(644,root,root) %{_mandir}/man5/instances.conf.5.gz
%attr(644,root,root) %{_mandir}/man5/policy.py.5.gz
%attr(644,root,root) %{_mandir}/man8/*
%attr(755,root,root) %{_libdir}/zorp/zorp
%attr(755,root,root) %{_sbindir}/zorpctl

%dir %{_libdir}/zorp/tests
%attr(755,root,root) %{_libdir}/zorp/tests/*

%dir %attr(750,root,zorp) %{_sysconfdir}/zorp
%dir %attr(750,zorp,zorp) %{_localstatedir}/run/zorp
%dir %attr(755,root,root) %{_datadir}/zorp
%dir %attr(755,root,root) %{_datadir}/zorp/http
%dir %attr(755,root,root) %{_datadir}/zorp/pop3
%dir %attr(755,root,root) %{_datadir}/zorp/pop3/en
%dir %attr(755,root,root) %{_datadir}/zorp/pop3/hu

%attr(640,root,zorp) /etc/zorp/*
%attr(644,root,root) %{_datadir}/zorp/pop3/en/reject.msg
%attr(644,root,root) %{_datadir}/zorp/pop3/hu/reject.msg
%attr(644,root,root) %{_datadir}/zorp/http/hu/*
%attr(644,root,root) %{_datadir}/zorp/http/en/*
%attr(644,root,root) %{_datadir}/zorp/http/de/*
%attr(644,root,root) %{_datadir}/zorp/moduledist.conf

%dir %{python2_sitelib}/Zorp
%dir %{python2_sitelib}/zorpctl
%attr(755,root,root) %{python2_sitelib}/Zorp/Auth.py
%attr(755,root,root) %{python2_sitelib}/Zorp/AuthDB.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Cache.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Chainer.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Core.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Detector.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Dispatch.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Encryption.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Globals.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Keybridge.py
%attr(755,root,root) %{python2_sitelib}/Zorp/FileLock.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Listener.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Matcher.py
%attr(755,root,root) %{python2_sitelib}/Zorp/NAT.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Proxy.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Pssl.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Receiver.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Router.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Rule.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Resolver.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Service.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Session.py
%attr(755,root,root) %{python2_sitelib}/Zorp/SockAddr.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Stack.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Stream.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Util.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Zorp.py
%attr(755,root,root) %{python2_sitelib}/Zorp/KZorp.py

%attr(755,root,root) %{python2_sitelib}/zorpctl/CommandResults.py
%attr(755,root,root) %{python2_sitelib}/zorpctl/Instances.py
%attr(755,root,root) %{python2_sitelib}/zorpctl/PluginAlgorithms.py
%attr(755,root,root) %{python2_sitelib}/zorpctl/ProcessAlgorithms.py
%attr(755,root,root) %{python2_sitelib}/zorpctl/SZIGMessages.py
%attr(755,root,root) %{python2_sitelib}/zorpctl/szig.py
%attr(755,root,root) %{python2_sitelib}/zorpctl/UInterface.py
%attr(755,root,root) %{python2_sitelib}/zorpctl/utils.py

%if 0%{?fedora} || 0%{?rhel} || 0%{?centos}
%attr(755,root,root) %{python2_sitelib}/Zorp/*.pyc
%attr(755,root,root) %{python2_sitelib}/zorpctl/*.pyc
%attr(755,root,root) %{python2_sitelib}/Zorp/*.pyo
%attr(755,root,root) %{python2_sitelib}/zorpctl/*.pyo
%endif

%config %{_sysconfdir}/zorp/*.sample

%package -n libzorp-5_0-0
Summary:                The runtime library of Zorp
Group:                  System/Daemons

%description -n libzorp-5_0-0
Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions

The library needed to run zorp.

%files -n libzorp-5_0-0
%defattr(-,root,root)
%{_libdir}/libzorp-*.so.*
%{_libdir}/libzorpproxy-*.so.*

%post -n libzorp-5_0-0
ldconfig

%postun -n libzorp-5_0-0
ldconfig

%package -n libzorp-5_0-devel
Summary:                Development files needed to compile Zorp modules
Group:                  System/Daemons

%description -n libzorp-5_0-devel
Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions
are scriptable with the Python based configuration language.

These are the files you need to compile a zorp module.

%files -n libzorp-5_0-devel
%defattr(-,root,root)
%{_includedir}/zorp
%{_libdir}/libzorp.la
%{_libdir}/libzorp.so
%{_libdir}/libzorpproxy.la
%{_libdir}/libzorpproxy.so
%{_libdir}/pkgconfig/libzorp.pc
%{_libdir}/pkgconfig/libzorpproxy.pc
%{_datadir}/zorp/moduledist.conf

%package base
Summary:                Base files for zorp
Group:                  System/Daemons

%description base
Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions

Common files for Zorp and kZorp.

%config %{_sysconfdir}/zorp/zorpctl.conf

%files base
%attr(755,root,root) %{_mandir}/man5/zorpctl.conf.5.gz

%package -n python-zorp-base
Summary:                Base files for zorp
Group:                  System/Daemons

%description -n python-zorp-base
Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions

Common python files for Zorp and kZorp.

%files -n python-zorp-base
%attr(755,root,root) %{python2_sitelib}/Zorp/Base.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Common.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Config.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Exceptions.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Instance.py
%attr(755,root,root) %{python2_sitelib}/Zorp/InstancesConf.py
%attr(755,root,root) %{python2_sitelib}/Zorp/ResolverCache.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Subnet.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Zone.py
%attr(755,root,root) %{python2_sitelib}/Zorp/__init__.py
%attr(755,root,root) %{python2_sitelib}/zorpctl/__init__.py
%attr(755,root,root) %{python2_sitelib}/zorpctl/ZorpctlConf.py

%package modules
Summary:                Zorp proxy modules
Group:                  System/Daemons

%description modules

Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions
are scriptable with the Python based configuration language.

This package includes proxies for the protocols: FINGER, FTP, HTTP,
SSL, TELNET, WHOIS, and two general modules ANYPY and PLUG.

%files modules
%defattr(-,root,root)
%dir %{_libdir}/zorp/
%{_libdir}/zorp/lib*.so*
%{_libdir}/zorp/lib*.la

%dir %attr(755,root,root) %{_datadir}/zorp/http/de
%dir %attr(755,root,root) %{_datadir}/zorp/http/en
%dir %attr(755,root,root) %{_datadir}/zorp/http/hu
%attr(644,root,root) %{_datadir}/zorp/http/en/*.html
%attr(644,root,root) %{_datadir}/zorp/http/de/*.html
%attr(644,root,root) %{_datadir}/zorp/http/hu/*.html

%attr(755,root,root) %{python2_sitelib}/Zorp/AnyPy.py
%attr(755,root,root) %{python2_sitelib}/Zorp/APR.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Finger.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Ftp.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Http.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Plug.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Pop3.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Smtp.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Telnet.py
%attr(755,root,root) %{python2_sitelib}/Zorp/Whois.py
%package -n python-kzorp
Summary:                Python bindings for kZorp.
Group:                  System/Daemons

%description -n python-kzorp
Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions

General python bindings for kzorp.

%files -n python-kzorp
%dir %{python2_sitelib}/kzorp
%attr(755,root,root) %{python2_sitelib}/kzorp/*.py

%if 0%{?fedora} || 0%{?rhel} || 0%{?centos}
%attr(755,root,root) %{python2_sitelib}/kzorp/*.pyc
%attr(755,root,root) %{python2_sitelib}/kzorp/*.pyo
%endif

%package munin-plugins
Summary:                Munin monitoring plugins for Zorp
Group:                  System/Daemons
Requires:               munin-node


%description munin-plugins

Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions
are scriptable with the Python based configuration language.
 
This package contains plugins for the Munin monitoring tool.

%files munin-plugins
%dir %{_datadir}/munin/
%dir %{_datadir}/munin/plugins/
%attr(755,root,root) %{_datadir}/munin/plugins/*
%dir %{_sysconfdir}/munin
%dir %{_sysconfdir}/munin/plugin-conf.d
%attr(644,root,root) %{_sysconfdir}/munin/plugin-conf.d/*


%package nagios-plugins
Summary:                Nagios monitoring plugins for Zorp
Group:                  System/Daemons
Requires:               nrpe

%description nagios-plugins

Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions
are scriptable with the Python based configuration language.
 
This package contains plugins for the Nagios monitoring tool.

%files nagios-plugins
%dir %{_sysconfdir}/sudoers.d
%attr(440,root,root) %{_sysconfdir}/sudoers.d/zorp_nagios_plugins
%dir %{_sysconfdir}/nagios
%dir %{_sysconfdir}/nagios/nrpe.d
%attr(644,root,root) %{_sysconfdir}/nagios/nrpe.d/zorp.cfg
%dir %{_libdir}/nagios
%dir %{_libdir}/nagios/plugins
%attr(755,root,root) %{_libdir}/nagios/plugins/*

%package -n kzorp 
Summary:                Python bindings for kzorp.
Group:                  System/Daemons

%description -n kzorp
Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions

Standalone daemon that handles zones and updates dynamic zones.

%files -n kzorp
%attr(755,root,root) %{_sbindir}/kzorpd
%attr(755,root,root) %{_sbindir}/kzorp-client

%changelog
* Wed Mar 4 2015 BalaBit Development Team <devel@balabit.hu> - 5.0.0
- Fixed several packaging warings and errors
