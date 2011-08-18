/* smbkrb5pwd.c - Overlay for managing Samba and MIT Kerberos passwords */
/* $OpenLDAP: pkg/ldap/contrib/slapd-modules/smbk5pwd/smbk5pwd.c,v 1.17.2.16 2009/08/17 21:49:00 quanah Exp $ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2004-2009 The OpenLDAP Foundation.
 * Portions Copyright 2004-2005 by Howard Chu, Symas Corp.
 * Other portions Copyright 2010 Opinsys.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * Support for table-driven configuration added by Pierangelo Masarati.
 * Support for sambaPwdMustChange and sambaPwdCanChange added by Marco D'Ettorre.
 *
 * Modified to support MIT Kerberos by Opinsys.
 * Renamed the module from smbk5pwd to smbkrb5pwd.
 */

#include <portable.h>

#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef SLAPD_OVER_SMBKRB5PWD
#define SLAPD_OVER_SMBKRB5PWD SLAPD_MOD_DYNAMIC
#endif

#ifdef SLAPD_OVER_SMBKRB5PWD

#include <slap.h>

#include "config.h"

#include <krb5/krb5.h>
#include <kadm5/admin.h>

#define KRB5_KEYTAB "/etc/ldap/slapd.d/openldap-krb5.keytab"

static AttributeDescription *ad_objectclass;
static AttributeDescription *ad_uid;

#ifdef HAVE_GNUTLS
#include <gcrypt.h>
typedef unsigned char DES_cblock[8];
#else
#include <openssl/des.h>
#include <openssl/md4.h>
#endif
#include "ldap_utf8.h"

static AttributeDescription *ad_sambaLMPassword;
static AttributeDescription *ad_sambaNTPassword;
static AttributeDescription *ad_sambaPwdLastSet;
static AttributeDescription *ad_sambaPwdMustChange;
static AttributeDescription *ad_sambaPwdCanChange;
static ObjectClass *oc_sambaSamAccount;

/* Per-instance configuration information */
typedef struct smbkrb5pwd_t {
	unsigned	mode;
#define	SMBKRB5PWD_F_KRB5	(0x1U)
#define	SMBKRB5PWD_F_SAMBA	(0x2U)

#define SMBKRB5PWD_DO_KRB5(pi)	((pi)->mode & SMBKRB5PWD_F_KRB5)
#define SMBKRB5PWD_DO_SAMBA(pi)	((pi)->mode & SMBKRB5PWD_F_SAMBA)

	/* How many seconds before forcing a password change? */
	time_t	smb_must_change;
	/* How many seconds after allowing a password change? */
	time_t  smb_can_change;
	char    *kerberos_realm;
	char    *admin_princstr;
	ldap_pvt_thread_mutex_t krb5_mutex;
	ObjectClass *oc_requiredObjectclass;
} smbkrb5pwd_t;

static const unsigned SMBKRB5PWD_F_ALL	=
	0
	| SMBKRB5PWD_F_KRB5
	| SMBKRB5PWD_F_SAMBA
;

static int smbkrb5pwd_modules_init( smbkrb5pwd_t *pi );

static const char hex[] = "0123456789abcdef";

/* From liblutil/passwd.c... */
static void lmPasswd_to_key(
	const char *lmPasswd,
	DES_cblock *key)
{
	const unsigned char *lpw = (const unsigned char *)lmPasswd;
	unsigned char *k = (unsigned char *)key;

	/* make room for parity bits */
	k[0] = lpw[0];
	k[1] = ((lpw[0]&0x01)<<7) | (lpw[1]>>1);
	k[2] = ((lpw[1]&0x03)<<6) | (lpw[2]>>2);
	k[3] = ((lpw[2]&0x07)<<5) | (lpw[3]>>3);
	k[4] = ((lpw[3]&0x0F)<<4) | (lpw[4]>>4);
	k[5] = ((lpw[4]&0x1F)<<3) | (lpw[5]>>5);
	k[6] = ((lpw[5]&0x3F)<<2) | (lpw[6]>>6);
	k[7] = ((lpw[6]&0x7F)<<1);

#ifdef HAVE_OPENSSL
	des_set_odd_parity( key );
#endif
}

#define MAX_PWLEN 256
#define	HASHLEN	16

static void hexify(
	const char in[HASHLEN],
	struct berval *out)
{
	int i;
	char *a;
	unsigned char *b;

	out->bv_val = ch_malloc(HASHLEN*2 + 1);
	out->bv_len = HASHLEN*2;

	a = out->bv_val;
	b = (unsigned char *)in;
	for (i=0; i<HASHLEN; i++) {
		*a++ = hex[*b >> 4];
		*a++ = hex[*b++ & 0x0f];
	}
	*a++ = '\0';
}

static void lmhash(
	struct berval *passwd,
	struct berval *hash)
{
	char UcasePassword[15];
	DES_cblock key;
	DES_cblock StdText = "KGS!@#$%";
	DES_cblock hbuf[2];
#ifdef HAVE_OPENSSL
	DES_key_schedule schedule;
#elif defined(HAVE_GNUTLS)
	gcry_cipher_hd_t h = NULL;
	gcry_error_t err;

	err = gcry_cipher_open( &h, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CBC, 0 );
	if ( err ) return;
#endif

	strncpy( UcasePassword, passwd->bv_val, 14 );
	UcasePassword[14] = '\0';
	ldap_pvt_str2upper( UcasePassword );

	lmPasswd_to_key( UcasePassword, &key );
#ifdef HAVE_GNUTLS
	err = gcry_cipher_setkey( h, &key, sizeof(key) );
	if ( err == 0 ) {
		err = gcry_cipher_encrypt( h, &hbuf[0], sizeof(key), &StdText, sizeof(key) );
		if ( err == 0 ) {
			gcry_cipher_reset( h );
			lmPasswd_to_key( &UcasePassword[7], &key );
			err = gcry_cipher_setkey( h, &key, sizeof(key) );
			if ( err == 0 ) {
				err = gcry_cipher_encrypt( h, &hbuf[1], sizeof(key), &StdText, sizeof(key) );
			}
		}
		gcry_cipher_close( h );
	}
#elif defined(HAVE_OPENSSL)
	des_set_key_unchecked( &key, schedule );
	des_ecb_encrypt( &StdText, &hbuf[0], schedule , DES_ENCRYPT );

	lmPasswd_to_key( &UcasePassword[7], &key );
	des_set_key_unchecked( &key, schedule );
	des_ecb_encrypt( &StdText, &hbuf[1], schedule , DES_ENCRYPT );
#endif

	hexify( (char *)hbuf, hash );
}

static void nthash(
	struct berval *passwd,
	struct berval *hash)
{
	/* Windows currently only allows 14 character passwords, but
	 * may support up to 256 in the future. We assume this means
	 * 256 UCS2 characters, not 256 bytes...
	 */
	char hbuf[HASHLEN];
#ifdef HAVE_OPENSSL
	MD4_CTX ctx;
#endif

	if (passwd->bv_len > MAX_PWLEN*2)
		passwd->bv_len = MAX_PWLEN*2;

#ifdef HAVE_OPENSSL
	MD4_Init( &ctx );
	MD4_Update( &ctx, passwd->bv_val, passwd->bv_len );
	MD4_Final( (unsigned char *)hbuf, &ctx );
#elif defined(HAVE_GNUTLS)
	gcry_md_hash_buffer(GCRY_MD_MD4, hbuf, passwd->bv_val, passwd->bv_len );
#endif

	hexify( hbuf, hash );
}

static int
lookup_admin_princstr(
	char *kerberos_realm,
	char **admin_princstr)
{
	char fqdn[NI_MAXHOST] = "";
	char hostname[HOST_NAME_MAX+1];
	struct addrinfo *host_addr;
	int rc;

	rc = -1;
	if (gethostname(hostname, HOST_NAME_MAX+1)     ||
	    getaddrinfo(hostname, NULL, NULL, &host_addr)) {
		Log0(LDAP_DEBUG_ANY, LDAP_LEVEL_NOTICE,
		     "smbkrb5pwd : an error occurred in gethostname()"
		     " or getaddrinfo(), check your dns settings\n");
		goto error;
	}

	if (getnameinfo(host_addr->ai_addr, host_addr->ai_addrlen, fqdn,
			NI_MAXHOST, NULL, 0, 0)) {
		Log0(LDAP_DEBUG_ANY, LDAP_LEVEL_NOTICE,
		     "smbkrb5pwd : an error occurred in getnameinfo(),"
		     " check your dns settings\n");
		goto error_with_host_addr;
	}

	size_t princstr_size = sizeof("smbkrb5pwd/")
			       + strlen(fqdn)
			       + sizeof("@")
			       + strlen(kerberos_realm) + 1;
	if (*admin_princstr)
		free(*admin_princstr);
	if ((*admin_princstr = malloc(princstr_size)) == NULL)
		goto error_with_host_addr;
	snprintf(*admin_princstr, princstr_size, "smbkrb5pwd/%s@%s", fqdn,
		 kerberos_realm);
	rc = 0;

error_with_host_addr:
	freeaddrinfo(host_addr);
error:
	return rc;
}

static int krb5_set_passwd(
	Operation *op,
	req_pwdexop_s *qpw,
	Entry *e,
	smbkrb5pwd_t *pi)
{
	void *kadm5_handle;
	kadm5_config_params params;
	kadm5_principal_ent_rec princ;
	kadm5_ret_t retval;
	krb5_context context;
	Attribute *a_objectclass, *a_uid;
	char *user_uid, *user_password, *user_princstr;
	int rc;
	size_t user_princstr_size;

	if (!access_allowed(op, e, slap_schema.si_ad_userPassword, NULL,
			    ACL_WRITE, NULL))
		return LDAP_INSUFFICIENT_ACCESS;

	rc = LDAP_LOCAL_ERROR;

	if (ldap_pvt_thread_mutex_trylock(&pi->krb5_mutex)) {
		/* this should happen only very rarely,
		 * we want to track these */
		Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_NOTICE,
	     	     "smbkrb5pwd %s : lock contention on kerberos mutex\n",
	     	     op->o_log_prefix);
		if (ldap_pvt_thread_mutex_lock(&pi->krb5_mutex)) {
			Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_NOTICE,
			     "smbkrb5pwd %s : failed to grab kerberos mutex\n",
			     op->o_log_prefix);
			rc = LDAP_CONNECT_ERROR;
			goto finish;
		}
	}

	kadm5_handle = NULL;
	memset(&princ, 0, sizeof(princ));
	memset(&params, 0, sizeof(params));
	princ.principal = NULL;

	/* Find the uid of the user - this is used to generate the kerberos
	 * principal for the user */

	/* XXX add user information to all error messages */

	a_uid = attr_find(e->e_attrs, ad_uid);
	if (!a_uid) {
		Log2(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR,
		      "smbkrb5pwd %s : could not find uid in entry: %s\n",
		      op->o_log_prefix,
		      ldap_err2string(LDAP_NO_SUCH_ATTRIBUTE));
		rc = LDAP_NO_SUCH_ATTRIBUTE;
		goto mitkrb_error_with_mutex_lock;
	}

	user_uid = a_uid->a_vals[0].bv_val;
	user_password = qpw->rs_new.bv_val;

	retval = kadm5_init_krb5_context(&context);
	if (retval) {
		Log3(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR,
		     "smbkrb5pwd %s : kadm5_init_krb5_context() failed"
		     " for user %s: %s\n",
		     op->o_log_prefix, user_uid, error_message(retval));
		rc = LDAP_CONNECT_ERROR;
		goto mitkrb_error_with_mutex_lock;
	}

	params.mask |= KADM5_CONFIG_REALM;
	params.realm = pi->kerberos_realm;
	retval = kadm5_init_with_skey(context, pi->admin_princstr, KRB5_KEYTAB,
				      KADM5_ADMIN_SERVICE, &params,
				      KADM5_STRUCT_VERSION,
				      KADM5_API_VERSION_3, NULL,
				      &kadm5_handle);
	if (retval) {
		Log3(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR,
		      "smbkrb5pwd %s : kadm5_init_with_skey() failed"
		      " for user %s: %s\n",
		      op->o_log_prefix, user_uid, error_message(retval));
		rc = LDAP_CONNECT_ERROR;
		goto mitkrb_error_with_context;
	}

	user_princstr_size = strlen(user_uid)
			     + sizeof("@")
			     + strlen(pi->kerberos_realm);
	if ((user_princstr = malloc(user_princstr_size)) == NULL) {
		rc = LDAP_CONNECT_ERROR;
		goto mitkrb_error_with_kadm5_handle;
	}
	snprintf(user_princstr, user_princstr_size, "%s@%s", user_uid,
		 pi->kerberos_realm);

	retval = krb5_parse_name(context, user_princstr, &princ.principal);
	if (retval) {
		Log3(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR,
		     "smbkrb5pwd %s : krb5_parse_name() failed"
		     " for user %s: %s\n",
		     op->o_log_prefix, user_princstr, error_message(retval));
		rc = LDAP_CONNECT_ERROR;
		goto mitkrb_error_with_user_princstr;
	}

	long create_mask = KADM5_PRINCIPAL|KADM5_MAX_LIFE|KADM5_ATTRIBUTES;
	princ.attributes |= KRB5_KDB_REQUIRES_PRE_AUTH;
	retval = kadm5_create_principal(kadm5_handle, &princ, create_mask,
					user_password);
	if (retval == KADM5_OK) {
		Log2(LDAP_DEBUG_ANY, LDAP_LEVEL_NOTICE,
		     "smbkrb5pwd %s : created principal for user %s\n",
		     op->o_log_prefix, user_princstr);
		rc = LDAP_SUCCESS;
	} else if (retval == KADM5_DUP) {
		/* principal exists, only change password */
		retval = kadm5_chpass_principal(kadm5_handle, princ.principal,
						user_password);
		if (retval) {
			Log3(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR,
			     "smbkrb5pwd %s : kadm5_chpass_principal() failed "
			     "for user %s: %s\n",
			     op->o_log_prefix, user_princstr,
			     error_message(retval));
			rc = LDAP_CONNECT_ERROR;
			goto mitkrb_error_with_princ;
		} else {
			Log2(LDAP_DEBUG_ANY, LDAP_LEVEL_NOTICE,
			     "smbkrb5pwd %s : changed password for user %s\n",
			     op->o_log_prefix, user_princstr);
			rc = LDAP_SUCCESS;
		}
	} else {
		Log3(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR,
		     "smbkrb5pwd %s : Problem creating principal for user %s: "
		     "%s\n", op->o_log_prefix, user_princstr,
		     error_message(retval));
		rc = LDAP_CONNECT_ERROR;
		goto mitkrb_error_with_princ;
	}

mitkrb_error_with_princ:
	krb5_free_principal(context, princ.principal);
mitkrb_error_with_kadm5_handle:
	kadm5_destroy(kadm5_handle);
mitkrb_error_with_user_princstr:
	free(user_princstr);
mitkrb_error_with_context:
	krb5_free_context(context);
mitkrb_error_with_mutex_lock:
	ldap_pvt_thread_mutex_unlock(&pi->krb5_mutex);
finish:
	return rc;
}

static int smbkrb5pwd_exop_passwd(
	Operation *op,
	SlapReply *rs)
{
	int rc, rc_krb5;
	req_pwdexop_s *qpw = &op->oq_pwdexop;
	Entry *e;
	Modifications *ml;
	slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;
	smbkrb5pwd_t *pi = on->on_bi.bi_private;
	char term;

	/* Not the operation we expected, pass it on... */
	if ( ber_bvcmp( &slap_EXOP_MODIFY_PASSWD, &op->ore_reqoid ) ) {
		return SLAP_CB_CONTINUE;
	}

	op->o_bd->bd_info = (BackendInfo *)on->on_info;
	rc = be_entry_get_rw( op, &op->o_req_ndn, NULL, NULL, 0, &e );
	if ( rc != LDAP_SUCCESS ) return rc;

	term = qpw->rs_new.bv_val[qpw->rs_new.bv_len];
	qpw->rs_new.bv_val[qpw->rs_new.bv_len] = '\0';

	rc = SLAP_CB_CONTINUE;
	if (pi->oc_requiredObjectclass &&
	    !is_entry_objectclass(e, pi->oc_requiredObjectclass, 0)) {
		Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_NOTICE,
	     	     "smbkrb5pwd %s : an entry is not of required"
		     " objectClass\n",
	     	     op->o_log_prefix);
		rc = LDAP_PARAM_ERROR;
		goto finish;
	}

	if (SMBKRB5PWD_DO_KRB5(pi)) {
		/* if this fails, do not bother with samba,
		   because passwords should be kept in sync */
		rc_krb5 = krb5_set_passwd(op, qpw, e, pi);
		if (rc_krb5 != LDAP_SUCCESS) {
			rc = rc_krb5;
			goto finish;
		}
	}

	/* Samba stuff */
	if ( SMBKRB5PWD_DO_SAMBA( pi ) && is_entry_objectclass(e, oc_sambaSamAccount, 0 ) ) {
		struct berval *keys;
		ber_len_t j,l;
		wchar_t *wcs, wc;
		char *c, *d;
		struct berval pwd;
		
		/* Expand incoming UTF8 string to UCS4 */
		l = ldap_utf8_chars(qpw->rs_new.bv_val);
		wcs = ch_malloc((l+1) * sizeof(wchar_t));

		ldap_x_utf8s_to_wcs( wcs, qpw->rs_new.bv_val, l );
		
		/* Truncate UCS4 to UCS2 */
		c = (char *)wcs;
		for (j=0; j<l; j++) {
			wc = wcs[j];
			*c++ = wc & 0xff;
			*c++ = (wc >> 8) & 0xff;
		}
		*c++ = 0;
		pwd.bv_val = (char *)wcs;
		pwd.bv_len = l * 2;

		ml = ch_malloc(sizeof(Modifications));
		if (!qpw->rs_modtail) qpw->rs_modtail = &ml->sml_next;
		ml->sml_next = qpw->rs_mods;
		qpw->rs_mods = ml;

		keys = ch_malloc( 2 * sizeof(struct berval) );
		BER_BVZERO( &keys[1] );
		nthash( &pwd, keys );
		
		ml->sml_desc = ad_sambaNTPassword;
		ml->sml_op = LDAP_MOD_REPLACE;
#ifdef SLAP_MOD_INTERNAL
		ml->sml_flags = SLAP_MOD_INTERNAL;
#endif
		ml->sml_numvals = 1;
		ml->sml_values = keys;
		ml->sml_nvalues = NULL;

		/* Truncate UCS2 to 8-bit ASCII */
		c = pwd.bv_val+1;
		d = pwd.bv_val+2;
		for (j=1; j<l; j++) {
			*c++ = *d++;
			d++;
		}
		pwd.bv_len /= 2;
		pwd.bv_val[pwd.bv_len] = '\0';

		ml = ch_malloc(sizeof(Modifications));
		ml->sml_next = qpw->rs_mods;
		qpw->rs_mods = ml;

		keys = ch_malloc( 2 * sizeof(struct berval) );
		BER_BVZERO( &keys[1] );
		lmhash( &pwd, keys );
		
		ml->sml_desc = ad_sambaLMPassword;
		ml->sml_op = LDAP_MOD_REPLACE;
#ifdef SLAP_MOD_INTERNAL
		ml->sml_flags = SLAP_MOD_INTERNAL;
#endif
		ml->sml_numvals = 1;
		ml->sml_values = keys;
		ml->sml_nvalues = NULL;

		ch_free(wcs);

		ml = ch_malloc(sizeof(Modifications));
		ml->sml_next = qpw->rs_mods;
		qpw->rs_mods = ml;

		keys = ch_malloc( 2 * sizeof(struct berval) );
		keys[0].bv_val = ch_malloc( LDAP_PVT_INTTYPE_CHARS(long) );
		keys[0].bv_len = snprintf(keys[0].bv_val,
			LDAP_PVT_INTTYPE_CHARS(long),
			"%ld", slap_get_time());
		BER_BVZERO( &keys[1] );
		
		ml->sml_desc = ad_sambaPwdLastSet;
		ml->sml_op = LDAP_MOD_REPLACE;
#ifdef SLAP_MOD_INTERNAL
		ml->sml_flags = SLAP_MOD_INTERNAL;
#endif
		ml->sml_numvals = 1;
		ml->sml_values = keys;
		ml->sml_nvalues = NULL;

		if (pi->smb_must_change)
		{
			ml = ch_malloc(sizeof(Modifications));
			ml->sml_next = qpw->rs_mods;
			qpw->rs_mods = ml;

			keys = ch_malloc( 2 * sizeof(struct berval) );
			keys[0].bv_val = ch_malloc( LDAP_PVT_INTTYPE_CHARS(long) );
			keys[0].bv_len = snprintf(keys[0].bv_val,
					LDAP_PVT_INTTYPE_CHARS(long),
					"%ld", slap_get_time() + pi->smb_must_change);
			BER_BVZERO( &keys[1] );

			ml->sml_desc = ad_sambaPwdMustChange;
			ml->sml_op = LDAP_MOD_REPLACE;
#ifdef SLAP_MOD_INTERNAL
			ml->sml_flags = SLAP_MOD_INTERNAL;
#endif
			ml->sml_numvals = 1;
			ml->sml_values = keys;
			ml->sml_nvalues = NULL;
		}

		if (pi->smb_can_change)
		{
			ml = ch_malloc(sizeof(Modifications));
			ml->sml_next = qpw->rs_mods;
			qpw->rs_mods = ml;

			keys = ch_malloc( 2 * sizeof(struct berval) );
			keys[0].bv_val = ch_malloc( LDAP_PVT_INTTYPE_CHARS(long) );
			keys[0].bv_len = snprintf(keys[0].bv_val,
					LDAP_PVT_INTTYPE_CHARS(long),
					"%ld", slap_get_time() + pi->smb_can_change);
			BER_BVZERO( &keys[1] );

			ml->sml_desc = ad_sambaPwdCanChange;
			ml->sml_op = LDAP_MOD_REPLACE;
#ifdef SLAP_MOD_INTERNAL
			ml->sml_flags = SLAP_MOD_INTERNAL;
#endif
			ml->sml_numvals = 1;
			ml->sml_values = keys;
			ml->sml_nvalues = NULL;
		}
	}
finish:
	be_entry_release_r( op, e );
	qpw->rs_new.bv_val[qpw->rs_new.bv_len] = term;

	return rc;
}

static slap_overinst smbkrb5pwd;

/* back-config stuff */
enum {
	PC_SMB_MUST_CHANGE = 1,
	PC_SMB_CAN_CHANGE,
	PC_SMB_ENABLE,
	PC_SMB_KRB5REALM,
	PC_SMB_REQUIREDCLASS,
};

static ConfigDriver smbkrb5pwd_cf_func;

/*
 * NOTE: uses OID arcs OLcfgCtAt:1 and OLcfgCtOc:1
 */

static ConfigTable smbkrb5pwd_cfats[] = {
	{ "smbkrb5pwd-enable", "arg",
		2, 0, 0, ARG_MAGIC|PC_SMB_ENABLE, smbkrb5pwd_cf_func,
		"( OLcfgCtAt:1.1 NAME 'olcSmbKrb5PwdEnable' "
		"DESC 'Modules to be enabled' "
		"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "smbkrb5pwd-must-change", "time",
		2, 2, 0, ARG_MAGIC|ARG_INT|PC_SMB_MUST_CHANGE, smbkrb5pwd_cf_func,
		"( OLcfgCtAt:1.2 NAME 'olcSmbKrb5PwdMustChange' "
		"DESC 'Credentials validity interval' "
		"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "smbkrb5pwd-can-change", "time",
		2, 2, 0, ARG_MAGIC|ARG_INT|PC_SMB_CAN_CHANGE, smbkrb5pwd_cf_func,
		"( OLcfgCtAt:1.3 NAME 'olcSmbKrb5PwdCanChange' "
		"DESC 'Credentials minimum validity interval' "
		"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "smbkrb5pwd-krb5realm", "arg",
		2, 2, 0, ARG_MAGIC|ARG_STRING|PC_SMB_KRB5REALM, smbkrb5pwd_cf_func,
		"( OLcfgCtAt:1.4 NAME 'olcSmbKrb5PwdKrb5Realm' "
		"DESC 'Kerberos5 realm' "
		"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "smbkrb5pwd-requiredclass", "arg",
		2, 2, 0, ARG_MAGIC|ARG_STRING|PC_SMB_REQUIREDCLASS,
		smbkrb5pwd_cf_func,
		"( OLcfgCtAt:1.5 NAME 'olcSmbKrb5PwdRequiredClass' "
		"DESC 'Required objectClass' "
		"SYNTAX OMsDirectoryString )", NULL, NULL },

	{ NULL, NULL, 0, 0, 0, ARG_IGNORED }
};

static ConfigOCs smbkrb5pwd_cfocs[] = {
	{ "( OLcfgCtOc:1.1 "
		"NAME 'olcSmbKrb5PwdConfig' "
		"DESC 'smbkrb5pwd overlay configuration' "
		"SUP olcOverlayConfig "
		"MAY ( "
			"olcSmbKrb5PwdEnable "
			"$ olcSmbKrb5PwdMustChange "
			"$ olcSmbKrb5PwdCanChange "
			"$ olcSmbKrb5PwdKrb5Realm "
			"$ olcSmbKrb5PwdRequiredClass "
		") )", Cft_Overlay, smbkrb5pwd_cfats },

	{ NULL, 0, NULL }
};

/*
 * add here other functionalities; handle their initialization
 * as appropriate in smbkrb5pwd_modules_init().
 */
static slap_verbmasks smbkrb5pwd_modules[] = {
	{ BER_BVC( "krb5" ),		SMBKRB5PWD_F_KRB5  },
	{ BER_BVC( "samba" ),		SMBKRB5PWD_F_SAMBA },
	{ BER_BVNULL,			-1 }
};

static int
smbkrb5pwd_cf_func( ConfigArgs *c )
{
	slap_overinst	*on = (slap_overinst *)c->bi;

	int		rc = 0;
	smbkrb5pwd_t	*pi = on->on_bi.bi_private;

	if ( c->op == SLAP_CONFIG_EMIT ) {
		switch( c->type ) {
		case PC_SMB_MUST_CHANGE:
			c->value_int = pi->smb_must_change;
			break;

		case PC_SMB_CAN_CHANGE:
			c->value_int = pi->smb_can_change;
			break;

		case PC_SMB_ENABLE:
			c->rvalue_vals = NULL;
			if ( pi->mode ) {
				mask_to_verbs( smbkrb5pwd_modules, pi->mode, &c->rvalue_vals );
				if ( c->rvalue_vals == NULL ) {
					rc = 1;
				}
			}
			break;

		default:
			assert( 0 );
			rc = 1;
		}
		return rc;

	} else if ( c->op == LDAP_MOD_DELETE ) {
		switch( c->type ) {
		case PC_SMB_MUST_CHANGE:
			break;

                case PC_SMB_CAN_CHANGE:
                        break;

		case PC_SMB_ENABLE:
			if ( !c->line ) {
				pi->mode = 0;

			} else {
				slap_mask_t	m;

				m = verb_to_mask( c->line, smbkrb5pwd_modules );
				pi->mode &= ~m;
			}
			break;

		default:
			assert( 0 );
			rc = 1;
		}
		return rc;
	}

	switch( c->type ) {
	case PC_SMB_MUST_CHANGE:
		if ( c->value_int < 0 ) {
			Debug( LDAP_DEBUG_ANY, "%s: smbkrb5pwd: "
				"<%s> invalid negative value \"%d\".",
				c->log, c->argv[ 0 ], 0 );
			return 1;
		}
		pi->smb_must_change = c->value_int;
		break;

        case PC_SMB_CAN_CHANGE:
                if ( c->value_int < 0 ) {
                        Debug( LDAP_DEBUG_ANY, "%s: smbkrb5pwd: "
                                "<%s> invalid negative value \"%d\".",
                                c->log, c->argv[ 0 ], 0 );
                        return 1;
                }
                pi->smb_can_change = c->value_int;
                break;

	case PC_SMB_ENABLE: {
		slap_mask_t	mode = pi->mode, m;

		rc = verbs_to_mask( c->argc, c->argv, smbkrb5pwd_modules, &m );
		if ( rc > 0 ) {
			Debug( LDAP_DEBUG_ANY, "%s: smbkrb5pwd: "
				"<%s> unknown module \"%s\".\n",
				c->log, c->argv[ 0 ], c->argv[ rc ] );
			return 1;
		}

		/* we can hijack the smbkrb5pwd_t structure because
		 * from within the configuration, this is the only
		 * active thread. */
		pi->mode |= m;

		{
			BackendDB	db = *c->be;

			/* Re-initialize the module, because
			 * the configuration might have changed */
			db.bd_info = (BackendInfo *)on;
			rc = smbkrb5pwd_modules_init( pi );
			if ( rc ) {
				pi->mode = mode;
				return 1;
			}
		}

		} break;

	case PC_SMB_KRB5REALM: {
		if (pi->kerberos_realm)
			free(pi->kerberos_realm);
		if ((pi->kerberos_realm = strdup(c->value_string)) == NULL)
			return 1;
		rc = lookup_admin_princstr(pi->kerberos_realm,
					   &pi->admin_princstr);
		if (rc)
			return rc;
		Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
		     "smbkrb5pwd : using admin principal %s\n",
		      pi->admin_princstr);
		break;
	}

	case PC_SMB_REQUIREDCLASS: {
		if (!(pi->oc_requiredObjectclass = oc_find(c->value_string))) {
			Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
			     "smbkrb5pwd : could not find required "
			     "objectclass %s\n",
			     c->value_string);
			return 1;
		}
		break;
	}
	default:
		assert( 0 );
		return 1;
	}
	return rc;
}

static int
smbkrb5pwd_modules_init( smbkrb5pwd_t *pi )
{
	static struct {
		const char		*name;
		AttributeDescription	**adp;
	}
        krb5_ad[] = {
		{ "uid",			&ad_uid },
		{ NULL }
	},
	samba_ad[] = {
		{ "sambaLMPassword",		&ad_sambaLMPassword },
		{ "sambaNTPassword",		&ad_sambaNTPassword },
		{ "sambaPwdLastSet",		&ad_sambaPwdLastSet },
		{ "sambaPwdMustChange",		&ad_sambaPwdMustChange },
		{ "sambaPwdCanChange",		&ad_sambaPwdCanChange },
		{ NULL }
	},
	dummy_ad;

	/* this is to silence the unused var warning */
	dummy_ad.name = NULL;

	if ( SMBKRB5PWD_DO_KRB5( pi ) ) {
		int i, rc;
		for ( i = 0; krb5_ad[ i ].name != NULL; i++ ) {
			const char      *text;

			*(krb5_ad[ i ].adp) = NULL;

			rc = slap_str2ad( krb5_ad[ i ].name, krb5_ad[ i ].adp, &text );
			if ( rc != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_ANY, "smbk5pwd: "
					"unable to find \"%s\" attributeType: %s (%d).\n",
					krb5_ad[ i ].name, text, rc );
				return rc;
			}
		}
	}

	if ( SMBKRB5PWD_DO_SAMBA( pi ) && oc_sambaSamAccount == NULL ) {
		int		i, rc;

		oc_sambaSamAccount = oc_find( "sambaSamAccount" );
		if ( !oc_sambaSamAccount ) {
			Debug( LDAP_DEBUG_ANY, "smbkrb5pwd: "
				"unable to find \"sambaSamAccount\" objectClass.\n",
				0, 0, 0 );
			return -1;
		}

		for ( i = 0; samba_ad[ i ].name != NULL; i++ ) {
			const char	*text;

			*(samba_ad[ i ].adp) = NULL;

			rc = slap_str2ad( samba_ad[ i ].name, samba_ad[ i ].adp, &text );
			if ( rc != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_ANY, "smbkrb5pwd: "
					"unable to find \"%s\" attributeType: %s (%d).\n",
					samba_ad[ i ].name, text, rc );
				oc_sambaSamAccount = NULL;
				return rc;
			}
		}
	}

	return 0;
}

static int
smbkrb5pwd_db_init(BackendDB *be, ConfigReply *cr)
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	smbkrb5pwd_t	*pi;

	pi = ch_calloc( 1, sizeof( smbkrb5pwd_t ) );
	if ( pi == NULL ) {
		return 1;
	}
	pi->admin_princstr = NULL;
	pi->kerberos_realm = NULL;
	pi->oc_requiredObjectclass = NULL;
	ldap_pvt_thread_mutex_init(&pi->krb5_mutex);

	on->on_bi.bi_private = (void *)pi;

	return 0;
}

static int
smbkrb5pwd_db_open(BackendDB *be, ConfigReply *cr)
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	smbkrb5pwd_t	*pi = (smbkrb5pwd_t *)on->on_bi.bi_private;

	int	rc;

	if ( pi->mode == 0 ) {
		pi->mode = SMBKRB5PWD_F_ALL;
	}

	rc = smbkrb5pwd_modules_init( pi );
	if ( rc ) {
		return rc;
	}

	return 0;
}

static int
smbkrb5pwd_db_destroy(BackendDB *be, ConfigReply *cr)
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	smbkrb5pwd_t	*pi = (smbkrb5pwd_t *)on->on_bi.bi_private;

	if ( pi ) {
		ch_free( pi );
	}

	return 0;
}

int
smbkrb5pwd_initialize(void)
{
	int		rc;

	smbkrb5pwd.on_bi.bi_type = "smbkrb5pwd";

	smbkrb5pwd.on_bi.bi_db_init = smbkrb5pwd_db_init;
	smbkrb5pwd.on_bi.bi_db_open = smbkrb5pwd_db_open;
	smbkrb5pwd.on_bi.bi_db_destroy = smbkrb5pwd_db_destroy;

	smbkrb5pwd.on_bi.bi_extended = smbkrb5pwd_exop_passwd;
    
	smbkrb5pwd.on_bi.bi_cf_ocs = smbkrb5pwd_cfocs;

	rc = config_register_schema( smbkrb5pwd_cfats, smbkrb5pwd_cfocs );
	if ( rc ) {
		return rc;
	}

	return overlay_register( &smbkrb5pwd );
}

#if SLAPD_OVER_SMBKRB5PWD == SLAPD_MOD_DYNAMIC
int init_module(int argc, char *argv[]) {
	return smbkrb5pwd_initialize();
}
#endif

#endif /* defined(SLAPD_OVER_SMBKRB5PWD) */
