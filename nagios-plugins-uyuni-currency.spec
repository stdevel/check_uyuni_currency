Name:           nagios-plugins-uyuni-currency
Version:        0.7.0
Release:        1%{?dist}
Summary:        A Nagios / Icinga plugin for checking patch currency of hosts managed by Uyuni

Group:          Applications/System
License:        GPL
URL:            https://github.com/stdevel/check_uyuni_currency
Source0:        nagios-plugins-uyuni-currency-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

#BuildRequires:
#Requires:       python-requests

%description
This package contains a Nagios / Icinga plugin for checking patch currency of hosts managed by Uyuni or SUSE Multi-Linux Manager.

Check out the GitHub page for further information: https://github.com/stdevel/check_uyuni_currency

%prep
%setup -q

%build
#change /usr/lib64 to /usr/lib if we're on i686
%ifarch i686
sed -i -e "s/usr\/lib64/usr\/lib/" check_uyuni_currency.cfg
%endif

%install
install -m 0755 -d %{buildroot}%{_libdir}/nagios/plugins/
install -m 0755 check_uyuni_currency.py %{buildroot}%{_libdir}/nagios/plugins/check_uyuni_currency/check_uyuni_currency.py
%if 0%{?el7}
        install -m 0755 -d %{buildroot}%{_sysconfdir}/nrpe.d/
        install -m 0755 check_uyuni_currency.cfg  %{buildroot}%{_sysconfdir}/nrpe.d/check_uyuni_currency.cfg
%else
        install -m 0755 -d %{buildroot}%{_sysconfdir}/nagios/plugins.d/
        install -m 0755 check_uyuni_currency.cfg  %{buildroot}%{_sysconfdir}/nagios/plugins.d/check_uyuni_currency.cfg
%endif



%clean
rm -rf $RPM_BUILD_ROOT

%files
%if 0%{?el7}
        %config %{_sysconfdir}/nrpe.d/check_uyuni_currency.cfg
%else
        %config %{_sysconfdir}/nagios/plugins.d/check_uyuni_currency.cfg
%endif
%{_libdir}/nagios/plugins/check_uyuni_currency/check_uyuni_currency.py
%{_libdir}/nagios/plugins/check_repodata/uyuni.py
%{_libdir}/nagios/plugins/check_repodata/exceptions.py


%changelog
* Mon Aug 25 2025 Christian Stankowic <info@cstan.io> - 0.7.0-1
- Ported to Python 3

* Fri Oct 14 2016 Christian Stankowic <info@stankowic-development.net> - 0.5.0-1
- First release
