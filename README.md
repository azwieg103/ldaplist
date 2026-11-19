# ldaplist

A C-based open-source LDAP listing utility for Linux. This project implements a Solaris-style `ldaplist` interface for OpenLDAP and Microsoft Active Directory.

**Initial release status:** command-line client, OU search paths, authentication integration, Makefile, RPM packaging, and GitHub Actions release automation are included. Test against a non-production directory before production deployment; AD schemas and OU layouts vary.

## Features
- C implementation using OpenLDAP `libldap` (no shelling out to ldapsearch).
- LDAPv3; LDAP and LDAPS URIs.
- Kerberos/GSSAPI SSO by default, using the workstation credential cache; simple bind remains available with `-W`, `-w`, or `-j`.
- Unprivileged automatic discovery from readable OpenLDAP client configuration, readable SSSD domain settings, Kerberos realm configuration, host DNS domain, and LDAP DNS SRV records.
- Searches discover directory objects below the base DN rather than assuming every directory uses Unix-specific `ou=People` and `ou=Groups` containers.
- **Entries located anywhere beneath an OU whose name is `terminated` are excluded from all listing and keyed lookup results.** The exclusion applies to People, Groups, SUDOers, automount, password policies, and detailed `-l` output.
- Password file support (`-j`); prefer it over `-w`.
- Independent OU selectors: People, SUDOers, Groups, automount.
- Pipe-delimited tables by default for People, Groups, SUDOers, automount maps, and password policies.
- `ldaplist` with no arguments defaults to the People table; `-l database key` displays the full DN and all returned LDAP attributes.
- AlmaLinux 10 x86_64 RPM and source RPM, published as GitHub Releases after successful CI.

## Syntax

```text
ldaplist [-dlv] [-h LDAP_server[:serverPort]] [-M domainName] [-N profileName] [-a authenticationMethod] [-P certifPath] [-D bindDN] [-w bindPassword] [-W] [-j passwdFile] [-t] [-p|-s|-g|-u|-y] [database [key]...]
```

| Option | Meaning |
|---|---|
| `-d` | LDAP library diagnostics |
| `-l` | Long/detail output: DN followed by every returned LDAP attribute |
| `-v` | Verbose connection and search diagnostics |
| `-h` | LDAP host, optionally with port; 636 selects LDAPS |
| `-M` | DNS domain (converted to a base DN) or explicit base DN |
| `-N` | Named profile in `/etc/ldaplist/profiles/NAME.conf` |
| `-a` | `kerberos` (default), `simple`, `bind`, `anonymous`, or `gssapi` |
| `-P` | CA certificate file or directory; verification is required |
| `-D` | Bind DN |
| `-w` | Bind password (visible in process arguments; avoid when possible) |
| `-W` | Prompt for a bind password without echoing it; selects simple bind unless `-a` was explicitly supplied |
| `-j` | Read password from first line of a file |
| `-t` | Table output (now the default; retained for compatibility) |
| `-p` | Search People |
| `-s` | Search SUDOers |
| `-g` | Search Groups |
| `-u` | Search automount maps |
| `-V` | Version; `-?` help |

With no selector or positional database, `ldaplist` displays the People table. The `-p`, `-g`, `-s`, `-u`, and `-y` selectors display pipe-delimited tables; selectors can be combined. `-t` remains accepted as a compatibility flag but is no longer required. Use `-l passwd USER` (or `-l people USER`) for the full LDAP entry: its DN and all attributes returned by the directory, one attribute per line. The directory's access controls determine which attributes are visible. By default, searches run below the discovered base DN and filter for matching object classes. Entries in any subtree beneath an OU named `terminated` are always excluded. Set an `LDAPLIST_*_OU` environment variable to further restrict a search to a particular subtree. The People table columns are `uid`, `firstname`, `lastname`, `mail`, and `mobile`.

## Kerberos SSO on Linux

Use the workstation's existing Kerberos credentials:

```bash
kinit user@EXAMPLE.COM
klist
ldaplist -h ldap.example.com -M example.com -p
ldaplist -h ldap.example.com -M example.com -a gssapi -p -t
```

Kerberos/GSSAPI is the default authentication method. The client uses SASL GSSAPI and the current credential cache, so no password prompt or `-a kerberos` is needed. The LDAP server must support GSSAPI. Use `-a simple -D 'bind DN' -W` for an interactive, no-echo password prompt. Supplying `-D` with `-W`, `-w`, or `-j` selects simple bind automatically unless `-a` was explicitly set. DNS, time synchronization, realm configuration, and service principals must be correct.

## Simple bind

```bash
install -m 0600 /dev/null "$HOME/.ldaplist.pass"
# Add the password securely with an editor.
ldaplist -h dc1.example.com:636 -M example.com \
  -D 'CN=LDAP Reader,OU=Service Accounts,DC=example,DC=com' -W -p
```

Use LDAPS and a trusted CA for simple binds. Do not use `-w` on shared systems: command-line arguments may be visible through process inspection and shell history.

## Examples

```bash
ldaplist -h ldap.example.com -M example.com
ldaplist -l passwd alice
ldaplist passwd -u alice -l
ldaplist -h ldap.example.com -M example.com -s
ldaplist -h ldap.example.com -M example.com -g
ldaplist -h ldap.example.com -M example.com -u
ldaplist -h ldap.example.com -M example.com passwd jdoe
ldaplist -h ldap.example.com -M example.com groups engineering
ldaplist -h ldap.example.com -M example.com -p -s -g -u
```

## OU and schema configuration

Searches run recursively below the discovered base DN by default. People matches POSIX accounts and AD user objects; Groups matches POSIX groups and AD groups; SUDOers and automount match their respective schema object classes. **Entries beneath any OU named `terminated` are excluded globally, regardless of which listing selector or keyed database lookup is used.** The OU name match is case-insensitive. **Current Groups output is limited to entries that have a `gidNumber` attribute** (the POSIX/RFC2307-style group view); groups without `gidNumber`, including some native AD groups, are omitted. The `members` column displays the member values returned by the directory. Directory layouts and schemas vary, so use the existing `LDAPLIST_*_OU` overrides when you need to limit a search to a subtree.

Environment overrides:
- `LDAPLIST_BASE_DN`, `LDAPLIST_DOMAIN`, `LDAPURI`
- `LDAPLIST_PEOPLE_OU`, `LDAPLIST_SUDOERS_OU`, `LDAPLIST_GROUPS_OU`, `LDAPLIST_AUTOMOUNT_OU`

OU override values are relative RDNs such as `ou=UnixUsers`. Set `LDAPLIST_BASE_DN=dc=example,dc=com` or use `-M example.com`.

Profiles are optional key/value files at `/etc/ldaplist/profiles/NAME.conf`; they are not required for normal use. Supported keys: `server`, `port`, `domain`, `base_dn`, `auth`, `bind_dn`, and `ca_file`. Restrict profile and password-file permissions.

### OpenLDAP
Common schemas: `inetOrgPerson` plus `posixAccount` for People, `posixGroup` for Groups, `sudoRole` for SUDOers, and `automountMap`/`automount` for automount maps.

### Active Directory
AD commonly uses `CN=Users` or custom OUs instead of these Unix-oriented OU names. Create matching OUs or configure the OU overrides. AD attributes `givenName`, `sn`, `mail`, and `mobile` are read directly. Classic passwd fields `uidNumber`, `gidNumber`, `homeDirectory`, and `loginShell` require RFC2307/Unix attributes or an equivalent schema mapping. Full AD `member` DN expansion and schema-specific output are future enhancements.

## Build from source (AlmaLinux 10)

```bash
sudo dnf install -y gcc make openldap-devel cyrus-sasl-devel krb5-devel pkgconf-pkg-config
make
make check
sudo make install
```

## RPM releases

Pushes to `main` affecting source, packaging, scripts, or the workflow trigger an AlmaLinux 10 build. CI runs smoke tests, creates binary and source RPMs, and publishes a GitHub Release only after success. Release numbers follow `ZWIEGNET.N.el10`, incrementing for each build of a given version.

Primary target: AlmaLinux 10 x86_64. Intended EL10 compatibility includes RHEL, Rocky Linux, Oracle Linux, and CentOS Stream; those distributions are not individually tested.

## Security
- Prefer Kerberos/GSSAPI for workstation SSO.
- Use LDAPS and trusted CA validation for simple binds.
- Password files should be mode 0600.
- Run with least-privilege read-only directory credentials.
- The utility performs LDAP searches only; it does not modify directory data.

## License
GNU General Public License version 2 only (GPL-2.0-only). See [LICENSE](LICENSE).
