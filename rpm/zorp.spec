Name:                   zorp
Version:                5.0
Release:                1
URL:                    https://www.balabit.com/network-security/zorp-gpl
Source0:                zorp_%{version}.0.tar.gz
Summary:                BalaBit Zorp proxy firewall
License:                GPL-2.0
Group:                  System/Daemons
BuildRequires:          libzorpll-devel
BuildRequires:          python-devel
BuildRequires:          binutils-devel
BuildRequires:          automake
BuildRequires:          autoconf
BuildRequires:          libcap-devel
BuildRequires:          glib2-devel
BuildRequires:          zlib-devel
BuildRequires:          binutils-devel
BuildRequires:          automake
BuildRequires:          autoconf
BuildRequires:          libtool
BuildRequires:          gcc-c++


%if 0%{?fedora} || 0%{?centos}
BuildRequires:          pyOpenSSL
%else
BuildRequires:          python-pyOpenSSL
BuildRequires:          libtre-devel
%endif

BuildRequires:          gperf
#BuildRequires:         python-radix
#Requires:              python-radix
#Requires:              python-pydns

%if 0%{?fedora} || 0%{?centos}
Requires:               pyOpenSSL
%else
Requires:               python-pyOpenSSL
Requires:               libtre-devel
Requires(pre):          pwdutils
%endif


BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
BalaBit Zorp is a proxy based firewall

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
%configure --disable-werror --enable-debug

%install
make DESTDIR=${RPM_BUILD_ROOT} install
mkdir -p %{buildroot}/usr/var/run/zorp
rm %{buildroot}/usr/lib/pkgconfig/*

%pre
getent group zorp >/dev/null || groupadd -r zorp
getent passwd zorp >/dev/null || useradd -r -g zorp -d /var/run/zorp -s /bin/bash -c "user for Zorp" zorp
exit 0

%post
ldconfig

%postun
ldconfig


%files
%defattr(-,root,root)
%dir %attr(750,root,zorp) /etc/zorp
%dir %attr(750,zorp,zorp) /usr/var
%dir %attr(750,zorp,zorp) /usr/var/run
%dir %attr(750,zorp,zorp) /usr/var/run/zorp
%dir %attr(755,root,root) /usr/lib/zorp
%dir %attr(755,root,root) /usr/lib/zorp/tests
%dir %attr(755,root,root) /usr/share/zorp
%dir %attr(755,root,root) /usr/share/zorp/http
%dir %attr(755,root,root) /usr/share/zorp/http/de
%dir %attr(755,root,root) /usr/share/zorp/http/en
%dir %attr(755,root,root) /usr/share/zorp/http/hu
%dir %attr(755,root,root) /usr/share/zorp/pop3
%dir %attr(755,root,root) /usr/share/zorp/pop3/en
%dir %attr(755,root,root) /usr/share/zorp/pop3/hu

%dir %attr(755,root,root) /etc/munin
%dir %attr(755,root,root) /etc/nagios
%dir %attr(755,root,root) /usr/lib/nagios
%dir %attr(755,root,root) /usr/lib/nagios/plugins
%dir %attr(755,root,root) /usr/share/munin

%dir %attr(755,root,root) /etc/munin/plugin-conf.d/
%dir %attr(755,root,root) /etc/nagios/nrpe.d/
%dir %attr(755,root,root) /etc/sudoers.d/
%dir %attr(755,root,root) /usr/share/munin/plugins

%dir %attr(755,root,root) /usr/include/zorp
%dir %attr(755,root,root) /usr/lib/zorp
%attr(644,root,root) /usr/include/zorp/*

%attr(640,root,zorp) /etc/zorp/*
%attr(755,root,root) /usr/lib/libzorp-*
%attr(644,root,root) /usr/share/zorp/pop3/en/reject.msg
%attr(644,root,root) /usr/share/zorp/pop3/hu/reject.msg
%attr(644,root,root) /usr/share/zorp/http/hu/*
%attr(644,root,root) /usr/share/zorp/http/en/*
%attr(644,root,root) /usr/share/zorp/http/de/*
%attr(644,root,root) /usr/share/zorp/moduledist.conf
%attr(755,root,root) /usr/sbin/*
%attr(755,root,root) /usr/lib/zorp/zorp
%attr(755,root,root) /usr/lib/zorp/lib*.so*
%attr(755,root,root) /usr/lib/zorp/tests/*
%attr(644,root,root) %{_mandir}/man5/*
%attr(644,root,root) %{_mandir}/man8/*

%attr(755,root,root) /etc/munin/plugin-conf.d/munin_zorp.conf
%attr(755,root,root) /etc/nagios/nrpe.d/zorp.cfg
%attr(755,root,root) /etc/sudoers.d/zorp_nagios_plugins

%attr(755,root,root) /usr/lib/*
%attr(755,root,root) /usr/lib/nagios/plugins/*
%attr(755,root,root) /usr/lib/python2.7/site-packages/Zorp/*
%attr(755,root,root) /usr/lib/python2.7/site-packages/kzorp/*
%attr(755,root,root) /usr/lib/python2.7/site-packages/zorpctl/*
%attr(755,root,root) /usr/lib/zorp/*

%attr(755,root,root) /usr/sbin/*
%attr(755,root,root) /usr/share/man/man5/*
%attr(755,root,root) /usr/share/man/man8/*
%attr(755,root,root) /usr/share/munin/plugins/*
%attr(755,root,root) /usr/share/zorp/*



%changelog
