Name:           ldaplist
Version:        %{ldaplist_version}
Release:        %{?ldaplist_release}%{!?ldaplist_release:ZWIEGNET.1.el10}
Summary:        LDAP directory listing utility for OpenLDAP and Active Directory
License:        GPL-2.0-only
URL:            https://github.com/azwieg103/ldaplist
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  gcc, make, openldap-devel, cyrus-sasl-devel, krb5-devel, pkgconf-pkg-config
Requires:       openldap, cyrus-sasl-lib, cyrus-sasl-gssapi, krb5-libs
%description
A C-based LDAP listing utility for OpenLDAP and Microsoft Active Directory,
supporting simple binds and Kerberos/GSSAPI authentication.
%prep
%setup -q -n ldaplist
%build
%make_build
%check
%make_build check
%install
%make_install PREFIX=%{_prefix}
%files
%{_bindir}/ldaplist
%{_mandir}/man1/ldaplist.1*
%license LICENSE
