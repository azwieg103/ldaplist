# ldaplist

A read-only, C-based LDAP directory listing utility for Linux. `ldaplist` provides a Solaris-style command-line interface for querying OpenLDAP and Microsoft Active Directory.

The client uses OpenLDAP `libldap` directly; it does not shell out to `ldapsearch`.

## Features

- LDAPv3 connections over LDAP or LDAPS.
- Kerberos/GSSAPI authentication by default, using the current Kerberos credential cache.
- Optional simple bind, anonymous bind, and password-file authentication.
- Automatic discovery of LDAP settings from readable OpenLDAP client configuration, readable SSSD domain settings, Kerberos realm configuration, the host DNS domain, and LDAP DNS SRV records.
- Recursive searches below the discovered LDAP base DN; no fixed `ou=People` or `ou=Groups` layout is required.
- POSIX LDAP and common Active Directory object-class filters.
- People, SUDOers, Groups, automount, and password-policy listings.
- Keyed database lookups and detailed LDAP entry output.
- People results sorted by UID, case-insensitively, with duplicate UIDs suppressed.
- People table columns sized to the longest value in each result set. Header, separator, and every row share the same column boundaries; values are not truncated.
- Entries beneath any OU named `terminated` are excluded from listings and keyed lookups, at any depth and regardless of case.
- Optional named connection profiles; normal use does not require creating a configuration file.
- AlmaLinux 10 x86_64 RPM and source RPM releases published through GitHub Actions.

## Quick start

If the workstation already has a valid Kerberos ticket and LDAP discovery is configured:

```bash
klist
ldaplist
```

With explicit server and domain settings:

```bash
kinit user@EXAMPLE.COM
ldaplist -h ldap.example.com -M example.com
```

With no arguments, `ldaplist` displays the People table.

## Command syntax

```text
ldaplist [-dlv] [-h server[:port]] [-M domainName] [-N profileName]
         [-a authenticationMethod] [-P certifPath] [-D bindDN]
         [-w bindPassword|-W|-j passwdFile] [-t]
         [-p|-s|-g|-u|-y] [database [key]...]
```

### Options

| Option | Description |
|---|---|
| `-d` | Enable LDAP library diagnostics. |
| `-l` | Display detailed output: the entry DN and all attributes returned by the directory. |
| `-v` | Print connection and search diagnostics. |
| `-h server[:port]` | LDAP server or LDAP URI. Port 636 selects LDAPS when a host and port are supplied. |
| `-M domainName` | DNS domain (converted to a base DN) or explicit base DN such as `dc=example,dc=com`. |
| `-N profileName` | Load an optional profile from `/etc/ldaplist/profiles/NAME.conf`. |
| `-a method` | Authentication: `kerberos` (default), `gssapi`, `simple`, `bind`, or `anonymous`. |
| `-P certifPath` | CA certificate file or directory used for certificate verification. |
| `-D bindDN` | Bind distinguished name for simple authentication. |
| `-w password` | Supply a bind password as an argument. Avoid where possible because arguments may be visible to other local users or saved in shell history. |
| `-W` | Prompt for a password without echoing it. Selects simple bind unless an authentication method was explicitly supplied. |
| `-j passwdFile` | Read the password from the first line of a file. Protect the file with restrictive permissions. |
| `-t` | Request table output. Table output is already the default; this option remains for compatibility. |
| `-p` | List People. |
| `-s` | List SUDOers. |
| `-g` | List Groups. |
| `-u` | List automount maps. |
| `-y` | List password-policy entries. |
| `-V` | Print the program version. |
| `-?` | Display command help. |

The listing selectors can be combined. If no selector or positional database is supplied, People is selected by default. The People table contains `uid`, `firstname`, `lastname`, `mail`, and `mobile`.

## Examples

### People

```bash
# Default People listing
ldaplist

# List People explicitly
ldaplist -p

# Look up one user and display the complete LDAP entry
ldaplist -l passwd alice

# Keyed passwd lookup form
ldaplist passwd -u alice -l
```

The detailed form prints the full distinguished name followed by every attribute and value returned by the LDAP server. Multi-valued attributes appear on separate lines. The directory's access controls determine which attributes are visible.

### Other databases

```bash
# SUDOers
ldaplist -s

# Groups
ldaplist -g

# Automount maps
ldaplist -u

# Password policies
ldaplist -y

# Combine listing selectors
ldaplist -p -s -g -u -y
```

### Explicit connection settings

```bash
ldaplist -h ldap.example.com -M example.com -p
ldaplist -h ldaps://ldap.example.com:636 -M dc=example,dc=com -g
```

### Simple bind

Kerberos/GSSAPI is preferred for workstation SSO. For a simple bind, specify a bind DN and use `-W` to enter the password interactively:

```bash
ldaplist -h ldaps://ldap.example.com:636 -M example.com \
  -D 'uid=reader,ou=People,dc=example,dc=com' -W -p
```

A password can also be read from a file:

```bash
chmod 600 "$HOME/.ldaplist.pass"
ldaplist -h ldaps://ldap.example.com:636 -M example.com \
  -D 'uid=reader,ou=People,dc=example,dc=com' \
  -j "$HOME/.ldaplist.pass" -p
```

Use LDAPS and a trusted CA for simple binds. Avoid `-w` on shared systems because command-line arguments can be exposed through process inspection and shell history.

## Authentication

### Kerberos/GSSAPI (default)

The default authentication method is Kerberos/GSSAPI. The program uses the current credential cache; it does not prompt for a password.

```bash
kinit user@EXAMPLE.COM
klist
ldaplist -h ldap.example.com -M example.com
```

The LDAP service must support SASL GSSAPI, and DNS, time synchronization, realm configuration, and service principals must be correct. The explicit `-a gssapi` method is also accepted.

### Simple bind

Use `-D` with `-W`, `-w`, or `-j`. A password supplied through these options requires a bind DN. When `-W`, `-w`, or `-j` is used without an explicit `-a` option, simple bind is selected automatically.

### Anonymous bind

Use `-a anonymous` only when the directory permits anonymous searches.

## Automatic discovery

When explicit settings are not supplied, ldaplist attempts to discover connection information from:

1. `LDAPLIST_BASE_DN` and `LDAPLIST_DOMAIN` environment overrides.
2. Readable `/etc/openldap/ldap.conf` and `/etc/ldap/ldap.conf` settings (`BASE`, `URI`, and `TLS_CACERT`).
3. Readable SSSD domain settings in `/etc/sssd/sssd.conf` (`ldap_uri`, `ad_server`, `ldap_search_base`, `ad_domain`, and `ldap_tls_cacert`).
4. The Kerberos `default_realm` in `/etc/krb5.conf`.
5. The DNS suffix of the local hostname.
6. LDAP DNS SRV records: first `_ldap._tcp.dc._msdcs.DOMAIN`, then `_ldap._tcp.DOMAIN`.

SSSD configuration is often readable only by root. ldaplist uses it only when readable, does not read SSSD private databases or bind credentials, and does not require SSSD configuration to be accessible. Discovery is best-effort; use `-h` and `-M` to override it when necessary.

## Search scope, schemas, and exclusions

By default, searches run recursively below the discovered base DN. The utility does not assume that every directory has Unix-specific `ou=People` or `ou=Groups` containers.

Default object-class filters:

| Listing | LDAP filter |
|---|---|
| People | POSIX accounts or AD person/user objects |
| SUDOers | `objectClass=sudoRole` |
| Groups | POSIX groups or AD group objects |
| Automount | `objectClass=automount` |
| Password policies | OpenLDAP `pwdPolicy` or AD `msDS-PasswordSettings` |

### Terminated OU exclusion

Any entry whose distinguished name contains an OU RDN named `terminated` is excluded. The comparison is case-insensitive and applies at any depth, across People, Groups, SUDOers, automount, password policies, keyed database searches, and detailed `-l` output. The exclusion is based on the OU in the DN; another attribute containing the word `terminated` does not trigger it.

### People attributes and sorting

The People table reads `uid`, `givenName`, `sn`, `mail`, and `mobile`. If `uid` is empty, the client falls back to `sAMAccountName`, which supports common AD user entries. Results are sorted by UID without regard to case, and duplicate UIDs are suppressed.

Each People table column expands to fit its longest value in the current result set. The header, separator, and all result rows use those same widths, so long email addresses or other values do not shift the following columns or get truncated.

### Groups

The current Groups listing includes entries with a `gidNumber` attribute. Native AD groups without `gidNumber` are not included in this POSIX-oriented group view. The members column displays member values returned by the directory.

### OpenLDAP and Active Directory notes

Common OpenLDAP schemas include `posixAccount` for People, `posixGroup` for Groups, `sudoRole` for SUDOers, and `automount` for automount maps.

Active Directory commonly uses `CN=Users` or custom OU layouts rather than Unix-oriented People and Groups OUs. The People filter also matches AD person/user objects, and `sAMAccountName` is used as a fallback for `uid`. POSIX fields such as `uidNumber`, `gidNumber`, `homeDirectory`, and `loginShell` require the corresponding Unix/RFC2307 attributes to exist in the directory.

## Configuration

Configuration files are optional. A normal user can run ldaplist without creating an application-specific configuration file.

### Environment variables

| Variable | Purpose |
|---|---|
| `LDAPURI` | LDAP URI or server URI. |
| `LDAPLIST_BASE_DN` | Explicit LDAP search base DN. |
| `LDAPLIST_DOMAIN` | DNS domain used to derive the base DN. |
| `LDAPLIST_PEOPLE_OU` | Optional subtree restriction for People searches. |
| `LDAPLIST_SUDOERS_OU` | Optional subtree restriction for SUDOers searches. |
| `LDAPLIST_GROUPS_OU` | Optional subtree restriction for Groups searches. |
| `LDAPLIST_AUTOMOUNT_OU` | Optional subtree restriction for automount searches. |
| `LDAPLIST_POLICIES_OU` | Optional subtree restriction for password-policy searches. |

OU override values are relative RDNs, for example `ou=UnixUsers`. Without an OU override, the search uses the discovered base DN.

### Named profiles

Optional profiles are read from:

```text
/etc/ldaplist/profiles/NAME.conf
```

Supported keys are:

```ini
server=ldap.example.com
port=636
domain=example.com
base_dn=dc=example,dc=com
auth=kerberos
bind_dn=uid=reader,ou=People,dc=example,dc=com
ca_file=/etc/pki/tls/certs/ldap-ca.pem
```

Select a profile with `-N NAME`. Profiles are not required for normal use. Do not put plaintext passwords in profiles.

## Build from source (AlmaLinux 10)

Install the build dependencies:

```bash
sudo dnf install -y gcc make openldap-devel cyrus-sasl-devel \
  cyrus-sasl-gssapi krb5-devel pkgconf-pkg-config
```

Build, run the smoke checks, and install:

```bash
make
make check
sudo make install
```

The Makefile installs the executable to `/usr/bin/ldaplist` and the manual page to `/usr/share/man/man1/ldaplist.1`.

## RPM packages and releases

The primary build target is AlmaLinux 10 x86_64. GitHub Actions builds and tests the RPM, then publishes the binary RPM, source RPM, and debug RPMs as a GitHub Release when the workflow succeeds.

- Repository: [github.com/azwieg103/ldaplist](https://github.com/azwieg103/ldaplist)
- Releases: [Download RPM packages](https://github.com/azwieg103/ldaplist/releases)

Install a downloaded RPM with:

```bash
sudo rpm -Uvh ldaplist-*.x86_64.rpm
```

## Security

- Prefer Kerberos/GSSAPI for workstation authentication.
- Use LDAPS and trusted CA validation for simple binds.
- Protect password files with mode `0600`.
- Avoid putting passwords in command-line arguments.
- Use least-privilege, read-only LDAP credentials.
- ldaplist performs directory searches only; it does not modify LDAP entries.

## Manual page

After installation:

```bash
man ldaplist
```

## License

GNU General Public License version 2 only (`GPL-2.0-only`). See [LICENSE](LICENSE).
