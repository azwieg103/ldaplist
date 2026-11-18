#define _POSIX_C_SOURCE 200809L
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

#define VERSION "1.0.0"
typedef struct { const char *host,*domain,*profile,*auth,*cert,*dn,*pw,*pwfile,*base; int port,debug,verbose,table,p,s,g,u,y; } Opt;
static void usage(FILE *f) {
 fprintf(f,"ldaplist %s\nUsage: ldaplist [-dlv] [-h server[:port]] [-M domainName] [-N profileName] [-a authenticationMethod] [-P certifPath] [-D bindDN] [-w bindPassword|-j passwdFile] [-t] [-p|-s|-g|-u|-y] [database [key]...]\n\n-d debug  -l classic output  -v verbose  -h server[:port]  -M domain/base DN\n-N profile  -a simple|kerberos|gssapi|anonymous  -P CA file/dir  -D bind DN\n-w password  -j password file  -t People table  -p People  -s SUDOers  -g Groups  -u automount  -y password policies\n-V version  -? help\n",VERSION);
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
static int interact(LDAP *ld,unsigned flags,void *defaults,void *in){
 (void)ld;(void)flags;(void)defaults;sasl_interact_t *i=in;
 for(;i->id!=SASL_CB_LIST_END;i++){i->result="";i->len=0;}return LDAP_SUCCESS;
}
static char *attr(LDAP *ld,LDAPMessage *e,const char *a){
 struct berval **v=ldap_get_values_len(ld,e,a);char *s=(v&&v[0])?strndup(v[0]->bv_val,v[0]->bv_len):strdup("");if(v)ldap_value_free_len(v);return s;
}
static void print_entry(LDAP *ld,LDAPMessage *e,int kind,int table){
 char *uid=attr(ld,e,"uid"),*gn=attr(ld,e,"givenName"),*sn=attr(ld,e,"sn"),*mail=attr(ld,e,"mail"),*mob=attr(ld,e,"mobile");
 if(kind==0&&table)printf("%s\t%s\t%s\t%s\t%s\n",uid,gn,sn,mail,mob);
 else if(kind==0){char *un=attr(ld,e,"uidNumber"),*gnn=attr(ld,e,"gidNumber"),*gecos=attr(ld,e,"gecos"),*home=attr(ld,e,"homeDirectory"),*shell=attr(ld,e,"loginShell");printf("%s:%s:%s:%s:%s:%s\n",uid,un,gnn,*gecos?gecos:gn,home,shell);free(un);free(gnn);free(gecos);free(home);free(shell);}
 else {char *dn=ldap_get_dn(ld,e);puts(dn?dn:"");if(kind==1){char *x=attr(ld,e,"sudoUser");if(*x)printf("  sudoUser: %s\n",x);free(x);}if(kind==2){char *x=attr(ld,e,"memberUid");if(*x)printf("  memberUid: %s\n",x);free(x);}if(kind==3){char *k=attr(ld,e,"automountKey"),*v=attr(ld,e,"automountInformation");printf("%s %s\n",k,v);free(k);free(v);}if(dn)ldap_memfree(dn);}
 free(uid);free(gn);free(sn);free(mail);free(mob);
}
static void esc_filter(const char *in,char *out,size_t n){
 size_t j=0;for(size_t i=0;in[i]&&j+4<n;i++){unsigned char c=(unsigned char)in[i];if(c=='*'||c=='('||c==')'||c=='\\'||c==0){int z=snprintf(out+j,n-j,"\\%02x",c);if(z<0)break;j+=(size_t)z;}else out[j++]=(char)c;}out[j]=0;
}
int main(int argc,char **argv){
 Opt o={.port=389,.auth="simple"};int c;
 while((c=getopt(argc,argv,"dlvh:M:N:a:P:D:w:j:tpsguyV?"))!=-1)switch(c){
 case 'd':o.debug=1;break;case 'l':break;case 'v':o.verbose=1;break;case 'h':o.host=optarg;break;case 'M':o.domain=optarg;break;case 'N':o.profile=optarg;break;case 'a':o.auth=optarg;break;case 'P':o.cert=optarg;break;case 'D':o.dn=optarg;break;case 'w':o.pw=optarg;break;case 'j':o.pwfile=optarg;break;case 't':o.table=1;break;case 'p':o.p=1;break;case 's':o.s=1;break;case 'g':o.g=1;break;case 'u':o.u=1;break;case 'y':o.y=1;break;case 'V':puts("ldaplist " VERSION);return 0;default:usage(c=='?'?stdout:stderr);return c=='?'?0:2;}
 profile(o.profile,&o);
 if(o.pwfile){FILE *f=fopen(o.pwfile,"r");if(!f){perror("password file");return 2;}char *line=NULL;size_t n=0;if(getline(&line,&n,f)<0){fclose(f);free(line);return 2;}fclose(f);line[strcspn(line,"\r\n")]=0;o.pw=line;}
 if(o.pw&&!o.dn){fputs("ldaplist: -w/-j requires -D\n",stderr);return 2;}
 char uri[1024],host[768];const char *envuri=getenv("LDAPURI");
 if(o.host){snprintf(host,sizeof(host),"%s",o.host);char *colon=strrchr(host,':');if(colon&&strchr(host,']')==NULL){*colon++=0;o.port=atoi(colon);}snprintf(uri,sizeof(uri),"%s://%s:%d",o.port==636?"ldaps":"ldap",host,o.port);}
 else snprintf(uri,sizeof(uri),"%s",envuri&&*envuri?envuri:"ldap://localhost:389");
 char base[2048]={0};if(o.base)snprintf(base,sizeof(base),"%s",o.base);else if(getenv("LDAPLIST_BASE_DN"))snprintf(base,sizeof(base),"%s",getenv("LDAPLIST_BASE_DN"));else domain_dn(o.domain?o.domain:getenv("LDAPLIST_DOMAIN"),base,sizeof(base));
 if(!*base){fputs("ldaplist: specify -M DOMAIN or LDAPLIST_BASE_DN\n",stderr);return 2;}
 if(o.cert){if(access(o.cert,R_OK)){perror("CA certificate path");return 2;}setenv(strstr(o.cert,".pem")||strstr(o.cert,".crt")?"LDAPTLS_CACERT":"LDAPTLS_CACERTDIR",o.cert,1);setenv("LDAPTLS_REQCERT","demand",1);}
 LDAP *ld=NULL;int rc=ldap_initialize(&ld,uri);if(rc!=LDAP_SUCCESS){fprintf(stderr,"%s\n",ldap_err2string(rc));return 1;}
 int ver=LDAP_VERSION3;ldap_set_option(ld,LDAP_OPT_PROTOCOL_VERSION,&ver);ldap_set_option(ld,LDAP_OPT_REFERRALS,LDAP_OPT_OFF);struct timeval tv={10,0};ldap_set_option(ld,LDAP_OPT_NETWORK_TIMEOUT,&tv);
 if(o.debug){int on=LDAP_DEBUG_TRACE;ldap_set_option(NULL,LDAP_OPT_DEBUG_LEVEL,&on);}
 if(!strcasecmp(o.auth,"kerberos")||!strcasecmp(o.auth,"gssapi"))rc=ldap_sasl_interactive_bind_s(ld,NULL,"GSSAPI",NULL,NULL,LDAP_SASL_QUIET,interact,NULL);
 else if(!strcasecmp(o.auth,"anonymous"))rc=ldap_sasl_bind_s(ld,NULL,LDAP_SASL_SIMPLE,NULL,NULL,NULL,NULL);
 else if(!strcasecmp(o.auth,"simple")||!strcasecmp(o.auth,"bind")){struct berval cred={o.pw?strlen(o.pw):0,o.pw?(char*)o.pw:""};rc=ldap_sasl_bind_s(ld,o.dn,LDAP_SASL_SIMPLE,&cred,NULL,NULL,NULL);}
 else {fprintf(stderr,"unsupported auth method: %s\n",o.auth);ldap_unbind_ext_s(ld,NULL,NULL);return 2;}
 if(rc!=LDAP_SUCCESS){fprintf(stderr,"LDAP authentication failed: %s\n",ldap_err2string(rc));ldap_unbind_ext_s(ld,NULL,NULL);return 1;}
 if(o.verbose)fprintf(stderr,"Connected to %s; base DN %s; auth %s\n",uri,base,o.auth);
 const char *ous[]={"ou=People","ou=SUDOers","ou=Groups","ou=automount","ou=policies"};const char *envs[]={"LDAPLIST_PEOPLE_OU","LDAPLIST_SUDOERS_OU","LDAPLIST_GROUPS_OU","LDAPLIST_AUTOMOUNT_OU","LDAPLIST_POLICIES_OU"};int kinds[]={0,1,2,3,4};int flags[]={o.p,o.s,o.g,o.u,o.y};int selected=o.p||o.s||o.g||o.u||o.y,err=0;
 for(int i=0;i<5;i++)if(flags[i]){char dn[2300];const char *ou=getenv(envs[i]);snprintf(dn,sizeof(dn),"%s,%s",ou&&*ou?ou:ous[i],base);LDAPMessage *res=NULL;
 rc=ldap_search_ext_s(ld,dn,LDAP_SCOPE_SUBTREE,"(objectClass=*)",NULL,0,NULL,NULL,&tv,0,&res);
 if(rc!=LDAP_SUCCESS){fprintf(stderr,"Search %s: %s\n",dn,ldap_err2string(rc));err=1;continue;}if(i==0&&o.table)puts("uid\tfirstname\tlastname\tmail\tmobile");
 for(LDAPMessage *e=ldap_first_entry(ld,res);e;e=ldap_next_entry(ld,e)){
 if(kinds[i]==4){
  char *entrydn=ldap_get_dn(ld,e);puts(entrydn?entrydn:"");if(entrydn)ldap_memfree(entrydn);
  const char *attrs[]={"cn","pwdAttribute","pwdMinAge","pwdMaxAge","pwdInHistory","pwdCheckQuality","pwdMinLength","pwdExpireWarning","pwdGraceAuthNLimit","pwdLockout","pwdLockoutDuration","pwdMaxFailure","pwdFailureCountInterval","pwdMustChange","pwdAllowUserChange","pwdSafeModify","msDS-PasswordSettingsPrecedence","msDS-PasswordReversibleEncryptionEnabled","msDS-PasswordHistoryLength","msDS-PasswordComplexityEnabled","msDS-MinimumPasswordLength","msDS-MinimumPasswordAge","msDS-MaximumPasswordAge","msDS-LockoutThreshold","msDS-LockoutDuration","msDS-LockoutObservationWindow",NULL};
  for(int ai=0;attrs[ai];ai++){char *v=attr(ld,e,attrs[ai]);if(*v)printf("  %s: %s\n",attrs[ai],v);free(v);}
 }else print_entry(ld,e,kinds[i],o.table);
 }ldap_msgfree(res);}
 if(!selected){if(optind>=argc){usage(stderr);ldap_unbind_ext_s(ld,NULL,NULL);return 2;}const char *db=argv[optind++];int k=-1;const char *ou=NULL,*a="cn";
 if(!strcasecmp(db,"passwd")||!strcasecmp(db,"people")){k=0;ou=ous[0];a="uid";}else if(!strcasecmp(db,"sudoers")){k=1;ou=ous[1];}else if(!strcasecmp(db,"group")||!strcasecmp(db,"groups")){k=2;ou=ous[2];}else if(!strcasecmp(db,"automount")){k=3;ou=ous[3];a="automountKey";}
 if(k<0){fprintf(stderr,"unsupported database: %s\n",db);ldap_unbind_ext_s(ld,NULL,NULL);return 2;}
 char dn[2300],filter[8192];snprintf(dn,sizeof(dn),"%s,%s",ou,base);
 if(optind<argc){size_t used=(size_t)snprintf(filter,sizeof(filter),"(|");for(;optind<argc;optind++){char x[2048];esc_filter(argv[optind],x,sizeof(x));int z=snprintf(filter+used,sizeof(filter)-used,"(%s=%s)",a,x);if(z>0&&(size_t)z<sizeof(filter)-used)used+=(size_t)z;}snprintf(filter+used,sizeof(filter)-used,")");}else snprintf(filter,sizeof(filter),"(objectClass=*)");
 LDAPMessage *res=NULL;rc=ldap_search_ext_s(ld,dn,LDAP_SCOPE_SUBTREE,filter,NULL,0,NULL,NULL,&tv,0,&res);if(rc!=LDAP_SUCCESS){fprintf(stderr,"Search failed: %s\n",ldap_err2string(rc));err=1;}else{if(k==0&&o.table)puts("uid\tfirstname\tlastname\tmail\tmobile");for(LDAPMessage *e=ldap_first_entry(ld,res);e;e=ldap_next_entry(ld,e))print_entry(ld,e,k,o.table);ldap_msgfree(res);}}
 ldap_unbind_ext_s(ld,NULL,NULL);if(o.pwfile&&o.pw){memset((char*)o.pw,0,strlen(o.pw));free((char*)o.pw);}return err?1:0;
}
