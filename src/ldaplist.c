#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <ldap.h>
#include <sys/time.h>
#include <sasl/sasl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <pwd.h>
#include <netdb.h>
#include <resolv.h>
#include <arpa/nameser.h>

#define VERSION "1.0.0"
typedef struct { const char *host,*domain,*profile,*auth,*cert,*dn,*pw,*pwfile,*base; int port,debug,verbose,table,long_output,p,s,g,u,y; } Opt;
static void usage(FILE *f) {
 fprintf(f,"ldaplist %s\nUsage: ldaplist [-dlv] [-h server[:port]] [-M domainName] [-N profileName] [-a authenticationMethod] [-P certifPath] [-D bindDN] [-w bindPassword|-W|-j passwdFile] [-t] [-p|-s|-g|-u|-y] [database [key]...]\n\n-d debug  -l classic output  -v verbose  -h server[:port]  -M domain/base DN\n-N profile  -a kerberos(default)|simple|gssapi|anonymous  -P CA file/dir  -D bind DN\n-w password  -W prompt for password  -j password file  -t People table  -p People  -s SUDOers  -g Groups  -u automount  -y password policies\n-V version  -? help\n",VERSION);
}
static char *trim(char *s){while(isspace((unsigned char)*s))s++;char *e=s+strlen(s);while(e>s&&isspace((unsigned char)e[-1]))*--e=0;return s;}
static void domain_dn(const char *d,char *out,size_t n){
 if(!d||!*d)return;if(strchr(d,'=')){snprintf(out,n,"%s",d);return;}
 char *copy=strdup(d),*save=NULL,*p=strtok_r(copy,".",&save);out[0]=0;
 while(p){if(*out)strncat(out,",",n-strlen(out)-1);strncat(out,"dc=",n-strlen(out)-1);strncat(out,p,n-strlen(out)-1);p=strtok_r(NULL,".",&save);}free(copy);
}
static void profile(const char *name,Opt *o){
 if(!name)return;char path[PATH_MAX];snprintf(path,sizeof(path),"/etc/ldaplist/profiles/%s.conf",name);FILE *f=fopen(path,"r");
 if(!f){fprintf(stderr,"ldaplist: cannot open profile %s\n",path);exit(2);}char *line=NULL;size_t cap=0;
 while(getline(&line,&cap,f)>0){char *p=trim(line);if(!*p||*p=='#')continue;char *eq=strchr(p,'=');if(!eq)continue;*eq++=0;char *k=trim(p),*v=trim(eq);
 if(!strcmp(k,"server"))o->host=strdup(v);else if(!strcmp(k,"port"))o->port=atoi(v);else if(!strcmp(k,"domain"))o->domain=strdup(v);else if(!strcmp(k,"base_dn"))o->base=strdup(v);else if(!strcmp(k,"auth"))o->auth=strdup(v);else if(!strcmp(k,"bind_dn"))o->dn=strdup(v);else if(!strcmp(k,"ca_file"))o->cert=strdup(v);}
 free(line);fclose(f);
}

/* Discover only non-secret client settings. SSSD bind credentials are never read. */
static void set_if_empty(const char **dst,const char *value){
 if(value&&*value&&!*dst)*dst=strdup(value);
}
static void read_ldap_client_config(Opt *o){
 const char *paths[]={"/etc/openldap/ldap.conf","/etc/ldap/ldap.conf",NULL};
 for(int i=0;paths[i];i++){
  FILE *f=fopen(paths[i],"r");if(!f)continue;
  char *line=NULL;size_t cap=0;
  while(getline(&line,&cap,f)>0){
   char *p=trim(line);if(!*p||*p=='#')continue;
   char *sp=p;while(*sp&&!isspace((unsigned char)*sp))sp++;
   if(!*sp)continue;*sp++=0;sp=trim(sp);
   if(!strcasecmp(p,"BASE"))set_if_empty(&o->base,sp);
   else if(!strcasecmp(p,"URI"))set_if_empty(&o->host,sp);
   else if(!strcasecmp(p,"TLS_CACERT"))set_if_empty(&o->cert,sp);
  }
  free(line);fclose(f);
 }
}
static void read_sssd_config(Opt *o){
 FILE *f=fopen("/etc/sssd/sssd.conf","r");if(!f)return;
 char *line=NULL;size_t cap=0;int in_domain=0;
 while(getline(&line,&cap,f)>0){
  char *p=trim(line);if(!*p||*p=='#'||*p==';')continue;
  if(*p=='['){in_domain=!strncasecmp(p,"[domain/",8);continue;}
  if(!in_domain)continue;
  char *eq=strchr(p,'=');if(!eq)continue;*eq++=0;
  char *k=trim(p),*v=trim(eq);
  if(!strcasecmp(k,"ldap_uri")||!strcasecmp(k,"ad_server"))set_if_empty(&o->host,v);
  else if(!strcasecmp(k,"ldap_search_base"))set_if_empty(&o->base,v);
  else if(!strcasecmp(k,"ad_domain"))set_if_empty(&o->domain,v);
  else if(!strcasecmp(k,"ldap_tls_cacert"))set_if_empty(&o->cert,v);
 }
 free(line);fclose(f);
}
static void discover_krb_realm(char *realm,size_t n){
 FILE *f=fopen("/etc/krb5.conf","r");if(!f)return;
 char *line=NULL;size_t cap=0;int in_libdefaults=0;
 while(getline(&line,&cap,f)>0){
  char *p=trim(line);if(!*p||*p=='#'||*p==';')continue;
  if(*p=='['){in_libdefaults=!strncasecmp(p,"[libdefaults]",13);continue;}
  if(in_libdefaults){char *eq=strchr(p,'=');if(!eq)continue;*eq++=0;
   if(!strcasecmp(trim(p),"default_realm")){snprintf(realm,n,"%s",trim(eq));break;}}
 }
 free(line);fclose(f);
}
static int dns_srv(const char *name,char *uri,size_t n){
 unsigned char answer[NS_PACKETSZ];int len=res_query(name,ns_c_in,ns_t_srv,answer,sizeof(answer));
 if(len<0)return 0;ns_msg msg;if(ns_initparse(answer,len,&msg)<0)return 0;
 int count=ns_msg_count(msg,ns_s_an);unsigned best=65536;char target[NS_MAXDNAME]="";unsigned port=389;
 for(int i=0;i<count;i++){ns_rr rr;if(ns_parserr(&msg,ns_s_an,i,&rr)<0)continue;
  const unsigned char *r=ns_rr_rdata(rr);unsigned pri=ns_get16(r),pt=ns_get16(r+4);
  char host[NS_MAXDNAME];if(ns_name_uncompress(answer,answer+len,r+6,host,sizeof(host))<0)continue;
  if(pri<best&&strcmp(host,".")){best=pri;port=pt;snprintf(target,sizeof(target),"%s",host);}
 }
 if(!*target)return 0;size_t z=strlen(target);if(z&&target[z-1]=='.')target[z-1]=0;
 snprintf(uri,n,"%s://%s:%u",port==636?"ldaps":"ldap",target,port);return 1;
}
static void discover_defaults(Opt *o){
 /* Explicit environment overrides are useful for containers and per-user setups. */
 if(!o->base){const char *b=getenv("LDAPLIST_BASE_DN");if(b&&*b)o->base=b;}
 if(!o->domain){const char *d=getenv("LDAPLIST_DOMAIN");if(d&&*d)o->domain=d;}
 read_ldap_client_config(o);
 read_sssd_config(o);
 char realm[256]="";
 if(!o->domain&&!o->base){discover_krb_realm(realm,sizeof(realm));if(*realm)o->domain=realm;}
 if(!o->domain&&!o->base){
  char hn[256];if(gethostname(hn,sizeof(hn))==0){hn[sizeof(hn)-1]=0;char *dot=strchr(hn,'.');if(dot&&dot[1])o->domain=strdup(dot+1);}
 }
 if(!o->host){
  const char *uri=getenv("LDAPURI");if(uri&&*uri)o->host=uri;
 }
 if(!o->host&&o->domain){
  char q[512],uri[1024]={0};snprintf(q,sizeof(q),"_ldap._tcp.dc._msdcs.%s",o->domain);
  if(!dns_srv(q,uri,sizeof(uri))){snprintf(q,sizeof(q),"_ldap._tcp.%s",o->domain);dns_srv(q,uri,sizeof(uri));}
  if(*uri)o->host=strdup(uri);
 }
}
static const char *search_filter(int kind){
 switch(kind){
 case 0:return "(|(objectClass=posixAccount)(&(objectCategory=person)(objectClass=user)))";
 case 1:return "(objectClass=sudoRole)";
 case 2:return "(|(objectClass=posixGroup)(objectCategory=group))";
 case 3:return "(objectClass=automount)";
 default:return "(|(objectClass=pwdPolicy)(objectClass=msDS-PasswordSettings))";
 }
}
static void make_search_dn(char *out,size_t n,const char *base,const char *ou){
 if(ou&&*ou)snprintf(out,n,"%s,%s",ou,base);else snprintf(out,n,"%s",base);
}

static int interact(LDAP *ld,unsigned flags,void *defaults,void *in){
 (void)ld;(void)flags;(void)defaults;sasl_interact_t *i=in;
 for(;i->id!=SASL_CB_LIST_END;i++){i->result="";i->len=0;}return LDAP_SUCCESS;
}
static char *attr(LDAP *ld,LDAPMessage *e,const char *a){
 struct berval **v=ldap_get_values_len(ld,e,a);char *s=(v&&v[0])?strndup(v[0]->bv_val,v[0]->bv_len):strdup("");if(v)ldap_value_free_len(v);
 if(!*s&&!strcasecmp(a,"uid")){free(s);v=ldap_get_values_len(ld,e,"sAMAccountName");s=(v&&v[0])?strndup(v[0]->bv_val,v[0]->bv_len):strdup("");if(v)ldap_value_free_len(v);}return s;
}
static void table_header(void){ printf("| %-12s | %-16s | %-20s | %-32s | %-16s |\n","uid","firstname","lastname","mail","mobile"); puts("|--------------|------------------|----------------------|----------------------------------|------------------|"); }
static void table_row(const char *uid,const char *gn,const char *sn,const char *mail,const char *mob){ printf("| %-12.12s | %-16.16s | %-20.20s | %-32.32s | %-16.16s |\n",uid,gn,sn,mail,mob); }
static void table_header_kind(int kind){
 if(kind==1)puts("| name                     | users                        | hosts                        | commands                                  |");
 else if(kind==2)puts("| group                    | gidNumber    | members                                          |");
 else if(kind==3)puts("| automountKey                     | automountInformation                                               |");
 else puts("| policy                           | precedence   | minimumLength             |");
}
static void print_long_entry(LDAP *ld,LDAPMessage *e){
 char *dn=ldap_get_dn(ld,e);printf("dn: %s\n",dn?dn:"");if(dn)ldap_memfree(dn);
 BerElement *ber=NULL;for(char *name=ldap_first_attribute(ld,e,&ber);name;name=ldap_next_attribute(ld,e,ber)){
  struct berval **vals=ldap_get_values_len(ld,e,name);
  if(vals){for(int i=0;vals[i];i++)printf("%s: %.*s\n",name,(int)vals[i]->bv_len,vals[i]->bv_val);ldap_value_free_len(vals);}
  ldap_memfree(name);
 }if(ber)ber_free(ber,0);
}
static void print_kind_table_row(LDAP *ld,LDAPMessage *e,int kind){
 char *a=NULL,*b=NULL,*c=NULL,*d=NULL;
 if(kind==1){a=attr(ld,e,"cn");b=attr(ld,e,"sudoUser");c=attr(ld,e,"sudoHost");d=attr(ld,e,"sudoCommand");printf("| %-24.24s | %-28.28s | %-28.28s | %-40.40s |\n",a,b,c,d);}
 else if(kind==2){a=attr(ld,e,"cn");b=attr(ld,e,"gidNumber");c=attr(ld,e,"memberUid");if(!*c){free(c);c=attr(ld,e,"member");}printf("| %-24.24s | %-12.12s | %-48.48s |\n",a,b,c);}
 else if(kind==3){a=attr(ld,e,"automountKey");b=attr(ld,e,"automountInformation");printf("| %-32.32s | %-64.64s |\n",a,b);}
 else {a=attr(ld,e,"cn");b=attr(ld,e,"msDS-PasswordSettingsPrecedence");c=attr(ld,e,"msDS-MinimumPasswordLength");if(!*c){free(c);c=attr(ld,e,"pwdMinLength");}printf("| %-32.32s | %-12.12s | %-24.24s |\n",a,b,c);}
 free(a);free(b);free(c);free(d);
}
static void print_entry(LDAP *ld,LDAPMessage *e,int kind,int table);
static LDAP *sort_ld;
static int uid_compare(const void *ap,const void *bp){
 LDAPMessage *a=*(LDAPMessage * const *)ap,*b=*(LDAPMessage * const *)bp;
 char *ua=attr(sort_ld,a,"uid"),*ub=attr(sort_ld,b,"uid");
 int c=strcasecmp(ua,ub);if(!c)c=strcmp(ua,ub);free(ua);free(ub);return c;
}
static void print_people_sorted(LDAP *ld,LDAPMessage *res,int table){
 size_t n=0,cap=32;LDAPMessage **entries=malloc(cap*sizeof(*entries));
 if(!entries){for(LDAPMessage *e=ldap_first_entry(ld,res);e;e=ldap_next_entry(ld,e))print_entry(ld,e,0,table);return;}
 for(LDAPMessage *e=ldap_first_entry(ld,res);e;e=ldap_next_entry(ld,e)){
  char *uid=attr(ld,e,"uid");int is_user=*uid!='\0';free(uid);if(!is_user)continue;
  if(n==cap){cap*=2;LDAPMessage **tmp=realloc(entries,cap*sizeof(*entries));if(!tmp){free(entries);for(LDAPMessage *x=ldap_first_entry(ld,res);x;x=ldap_next_entry(ld,x))print_entry(ld,x,0,table);return;}entries=tmp;}
  entries[n++]=e;
 }
 sort_ld=ld;qsort(entries,n,sizeof(*entries),uid_compare);
 for(size_t i=0;i<n;i++){
  if(i){char *prev=attr(ld,entries[i-1],"uid"),*cur=attr(ld,entries[i],"uid");int duplicate=!strcasecmp(prev,cur);free(prev);free(cur);if(duplicate)continue;}
  print_entry(ld,entries[i],0,table);
 }
 free(entries);
}
static void print_entry(LDAP *ld,LDAPMessage *e,int kind,int table){
 char *uid=attr(ld,e,"uid"),*gn=attr(ld,e,"givenName"),*sn=attr(ld,e,"sn"),*mail=attr(ld,e,"mail"),*mob=attr(ld,e,"mobile");
 if(kind==0&&table){if(*uid)table_row(uid,gn,sn,mail,mob);}
 else if(kind==0){char *un=attr(ld,e,"uidNumber"),*gnn=attr(ld,e,"gidNumber"),*gecos=attr(ld,e,"gecos"),*home=attr(ld,e,"homeDirectory"),*shell=attr(ld,e,"loginShell");printf("%s:%s:%s:%s:%s:%s\n",uid,un,gnn,*gecos?gecos:gn,home,shell);free(un);free(gnn);free(gecos);free(home);free(shell);}
 else if(table)print_kind_table_row(ld,e,kind);
 else print_long_entry(ld,e);
 free(uid);free(gn);free(sn);free(mail);free(mob);
}
static void esc_filter(const char *in,char *out,size_t n){
 size_t j=0;for(size_t i=0;in[i]&&j+4<n;i++){unsigned char c=(unsigned char)in[i];if(c=='*'||c=='('||c==')'||c=='\\'||c==0){int z=snprintf(out+j,n-j,"\\%02x",c);if(z<0)break;j+=(size_t)z;}else out[j++]=(char)c;}out[j]=0;
}
int main(int argc,char **argv){
 Opt o={.port=389,.auth="kerberos"};int c,auth_explicit=0,prompt_pw=0,pw_owned=0;
 while((c=getopt(argc,argv,"dlvh:M:N:a:P:D:w:Wj:tpsguyV?"))!=-1)switch(c){
 case 'd':o.debug=1;break;case 'l':o.long_output=1;break;case 'v':o.verbose=1;break;case 'h':o.host=optarg;break;case 'M':o.domain=optarg;break;case 'N':o.profile=optarg;break;case 'a':o.auth=optarg;auth_explicit=1;break;case 'P':o.cert=optarg;break;case 'D':o.dn=optarg;break;case 'w':o.pw=optarg;break;case 'W':prompt_pw=1;break;case 'j':o.pwfile=optarg;break;case 't':o.table=1;break;case 'p':o.p=1;break;case 's':o.s=1;break;case 'g':o.g=1;break;case 'u':o.u=1;break;case 'y':o.y=1;break;case 'V':puts("ldaplist " VERSION);return 0;default:usage(c=='?'?stdout:stderr);return c=='?'?0:2;}
 profile(o.profile,&o);
 discover_defaults(&o);\n if(!o.long_output)o.table=1;
 if(prompt_pw){
  if(auth_explicit && strcasecmp(o.auth,"simple") && strcasecmp(o.auth,"bind")){
   fputs("ldaplist: -W cannot be combined with a non-simple -a method\n",stderr);return 2;
  }
  char *entered=getpass("LDAP password: ");
  if(!entered){fputs("ldaplist: unable to read password\n",stderr);return 2;}
  o.pw=strdup(entered);if(!o.pw){fputs("ldaplist: out of memory\n",stderr);return 2;}pw_owned=1;
  if(!auth_explicit)o.auth="simple";
 }
 if(o.pwfile){FILE *f=fopen(o.pwfile,"r");if(!f){perror("password file");return 2;}char *line=NULL;size_t n=0;if(getline(&line,&n,f)<0){fclose(f);free(line);return 2;}fclose(f);line[strcspn(line,"\r\n")]=0;o.pw=line;}
 if((o.pw||o.pwfile)&&!auth_explicit)o.auth="simple";
 if(o.pw&&!o.dn){fputs("ldaplist: -w/-W/-j requires -D\n",stderr);return 2;}
 char uri[1024]={0},host[768];const char *envuri=getenv("LDAPURI");
 if(o.host&&strstr(o.host,"://"))snprintf(uri,sizeof(uri),"%s",o.host);
 else if(o.host){snprintf(host,sizeof(host),"%s",o.host);char *colon=strrchr(host,':');if(colon&&strchr(host,']')==NULL){*colon++=0;o.port=atoi(colon);}snprintf(uri,sizeof(uri),"%s://%s:%d",o.port==636?"ldaps":"ldap",host,o.port);}
 else if(o.host&&strstr(o.host,"://"))snprintf(uri,sizeof(uri),"%s",o.host);
 else if(envuri&&*envuri)snprintf(uri,sizeof(uri),"%s",envuri);
 char base[2048]={0};if(o.base)snprintf(base,sizeof(base),"%s",o.base);else domain_dn(o.domain,base,sizeof(base));
 if(!*base){fputs("ldaplist: unable to discover LDAP base DN; use -M DOMAIN or LDAPLIST_BASE_DN\n",stderr);return 2;}
 if(!*uri){fputs("ldaplist: unable to discover LDAP server; configure LDAPURI, SSSD, or DNS SRV (_ldap._tcp)\n",stderr);return 2;}
 if(o.cert){if(access(o.cert,R_OK)){perror("CA certificate path");return 2;}setenv(strstr(o.cert,".pem")||strstr(o.cert,".crt")?"LDAPTLS_CACERT":"LDAPTLS_CACERTDIR",o.cert,1);setenv("LDAPTLS_REQCERT","demand",1);}
 LDAP *ld=NULL;int rc=ldap_initialize(&ld,uri);if(rc!=LDAP_SUCCESS){fprintf(stderr,"%s\n",ldap_err2string(rc));return 1;}
 int ver=LDAP_VERSION3;ldap_set_option(ld,LDAP_OPT_PROTOCOL_VERSION,&ver);ldap_set_option(ld,LDAP_OPT_REFERRALS,LDAP_OPT_OFF);struct timeval tv={10,0};ldap_set_option(ld,LDAP_OPT_NETWORK_TIMEOUT,&tv);
 if(o.debug){int on=1;ldap_set_option(NULL,LDAP_OPT_DEBUG_LEVEL,&on);}
 if(!strcasecmp(o.auth,"kerberos")||!strcasecmp(o.auth,"gssapi"))rc=ldap_sasl_interactive_bind_s(ld,NULL,"GSSAPI",NULL,NULL,LDAP_SASL_QUIET,interact,NULL);
 else if(!strcasecmp(o.auth,"anonymous"))rc=ldap_sasl_bind_s(ld,NULL,LDAP_SASL_SIMPLE,NULL,NULL,NULL,NULL);
 else if(!strcasecmp(o.auth,"simple")||!strcasecmp(o.auth,"bind")){struct berval cred={o.pw?strlen(o.pw):0,o.pw?(char*)o.pw:""};rc=ldap_sasl_bind_s(ld,o.dn,LDAP_SASL_SIMPLE,&cred,NULL,NULL,NULL);}
 else {fprintf(stderr,"unsupported auth method: %s\n",o.auth);ldap_unbind_ext_s(ld,NULL,NULL);return 2;}
 if(rc!=LDAP_SUCCESS){fprintf(stderr,"LDAP authentication failed: %s\n",ldap_err2string(rc));ldap_unbind_ext_s(ld,NULL,NULL);return 1;}
 if(o.verbose)fprintf(stderr,"Connected to %s; base DN %s; auth %s\n",uri,base,o.auth);
 const char *ous[]={"","","","",""};const char *envs[]={"LDAPLIST_PEOPLE_OU","LDAPLIST_SUDOERS_OU","LDAPLIST_GROUPS_OU","LDAPLIST_AUTOMOUNT_OU","LDAPLIST_POLICIES_OU"};int kinds[]={0,1,2,3,4};int flags[]={o.p,o.s,o.g,o.u,o.y};int selected=o.p||o.s||o.g||o.u||o.y,err=0;
 if(!selected&&optind>=argc){o.p=1;flags[0]=1;selected=1;}
 for(int i=0;i<5;i++)if(flags[i]){char dn[2300];const char *ou=getenv(envs[i]);make_search_dn(dn,sizeof(dn),base,ou&&*ou?ou:ous[i]);LDAPMessage *res=NULL;
 rc=ldap_search_ext_s(ld,dn,LDAP_SCOPE_SUBTREE,search_filter(i),NULL,0,NULL,NULL,&tv,0,&res);
 if(rc!=LDAP_SUCCESS){fprintf(stderr,"Search %s: %s\n",dn,ldap_err2string(rc));err=1;continue;}if(i==0&&o.table)table_header();
 if(kinds[i]==0){if(o.long_output){for(LDAPMessage *e=ldap_first_entry(ld,res);e;e=ldap_next_entry(ld,e))print_long_entry(ld,e);}else print_people_sorted(ld,res,o.table);}
 else {if(o.table)table_header_kind(kinds[i]); for(LDAPMessage *e=ldap_first_entry(ld,res);e;e=ldap_next_entry(ld,e)) {
 if(kinds[i]==4){
  if(o.table)print_kind_table_row(ld,e,4);else print_long_entry(ld,e);
 }else print_entry(ld,e,kinds[i],o.table);
 }}ldap_msgfree(res);}
 if(!selected){if(optind>=argc){usage(stderr);ldap_unbind_ext_s(ld,NULL,NULL);return 2;}const char *db=argv[optind++];int k=-1;const char *ou=NULL,*a="cn";
 if(!strcasecmp(db,"passwd")||!strcasecmp(db,"people")){k=0;ou=ous[0];a="uid";}else if(!strcasecmp(db,"sudoers")){k=1;ou=ous[1];}else if(!strcasecmp(db,"group")||!strcasecmp(db,"groups")){k=2;ou=ous[2];}else if(!strcasecmp(db,"automount")){k=3;ou=ous[3];a="automountKey";}
 if(k<0){fprintf(stderr,"unsupported database: %s\n",db);ldap_unbind_ext_s(ld,NULL,NULL);return 2;}
 char dn[2300],filter[8192];const char *dbou=getenv(k==0?"LDAPLIST_PEOPLE_OU":k==1?"LDAPLIST_SUDOERS_OU":k==2?"LDAPLIST_GROUPS_OU":"LDAPLIST_AUTOMOUNT_OU");make_search_dn(dn,sizeof(dn),base,dbou&&*dbou?dbou:ou);
 if(optind<argc){size_t used=(size_t)snprintf(filter,sizeof(filter),"(|");for(;optind<argc;optind++){char x[2048];esc_filter(argv[optind],x,sizeof(x));int z=snprintf(filter+used,sizeof(filter)-used,"(%s=%s)",a,x);if(z>0&&(size_t)z<sizeof(filter)-used)used+=(size_t)z;}snprintf(filter+used,sizeof(filter)-used,")");}else snprintf(filter,sizeof(filter),"%s",search_filter(k));
 LDAPMessage *res=NULL;rc=ldap_search_ext_s(ld,dn,LDAP_SCOPE_SUBTREE,filter,NULL,0,NULL,NULL,&tv,0,&res);if(rc!=LDAP_SUCCESS){fprintf(stderr,"Search failed: %s\n",ldap_err2string(rc));err=1;}else{if(k==0&&o.table)table_header();if(k==0){if(o.long_output){for(LDAPMessage *e=ldap_first_entry(ld,res);e;e=ldap_next_entry(ld,e))print_long_entry(ld,e);}else print_people_sorted(ld,res,o.table);}else {if(o.table)table_header_kind(k);for(LDAPMessage *e=ldap_first_entry(ld,res);e;e=ldap_next_entry(ld,e))print_entry(ld,e,k,o.table);}ldap_msgfree(res);}}
 ldap_unbind_ext_s(ld,NULL,NULL);if((o.pwfile||pw_owned)&&o.pw){memset((char*)o.pw,0,strlen(o.pw));free((char*)o.pw);}return err?1:0;
}
