# $OpenLDAP: pkg/ldap/contrib/slapd-modules/smbk5pwd/Makefile,v 1.1.6.4 2009/10/02 21:16:53 quanah Exp $
# This work is part of OpenLDAP Software <http://www.openldap.org/>.
#
# Copyright 1998-2009 The OpenLDAP Foundation.
# Copyright 2004 Howard Chu, Symas Corp. All Rights Reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted only as authorized by the OpenLDAP
# Public License.
#
# A copy of this license is available in the file LICENSE in the
# top-level directory of the distribution or, alternatively, at
# <http://www.OpenLDAP.org/license.html>.

LDAP_SRC=../../..
LDAP_BUILD=$(LDAP_SRC)
LDAP_INC=-I$(LDAP_BUILD)/include -I$(LDAP_SRC)/include -I$(LDAP_SRC)/servers/slapd
LDAP_LIB=$(LDAP_BUILD)/libraries/libldap_r/libldap_r.la \
	$(LDAP_BUILD)/libraries/liblber/liblber.la

SSL_INC=
SSL_LIB=-lcrypto

LIBTOOL=$(LDAP_BUILD)/libtool
CC=gcc
OPT=-g -O2
CLNT_OPT=-DSMBKRB5PWD_KADM5_CLNT
SRV_OPT=-DSMBKRB5PWD_KADM5_SRV

MIT_KRB5_INC=-I/usr/include/mit-krb5
MIT_KRB5_LIB=-L/usr/lib/$(shell gcc -print-multiarch)/mit-krb5 -lkrb5

DEFS=
INCS=$(LDAP_INC) $(MIT_KRB5_INC) $(SSL_INC)
LIBS=$(LDAP_LIB) $(MIT_KRB5_LIB) $(SSL_LIB)

MIT_KRB5_SRV_LIB=-lkadm5srv_mit
MIT_KRB5_CLNT_LIB=-lkadm5clnt_mit

prefix=/usr/local
ldap_subdir=/openldap

libdir=$(prefix)/lib
libexecdir=$(prefix)/libexec
moduledir=$(libexecdir)$(ldap_subdir)

.PHONY: all
all:	smbkrb5pwd.la smbkrb5pwd_srv.la

smbkrb5pwd.lo:	smbkrb5pwd.c
	$(LIBTOOL) --mode=compile $(CC) $(CLNT_OPT) $(OPT) $(DEFS) $(INCS) -c $?

smbkrb5pwd.la:	smbkrb5pwd.lo
	$(LIBTOOL) --mode=link $(CC) $(MIT_KRB5_CLNT_LIB) $(OPT) -version-info 0:1:0 \
	-rpath $(moduledir) -module -o $@ $? $(LIBS) $(MIT_KRB5_CLNT_LIB)

smbkrb5pwd_srv.lo:	smbkrb5pwd.c
	$(LIBTOOL) --mode=compile $(CC) $(SRV_OPT) $(OPT) $(DEFS) $(INCS) -c smbkrb5pwd.c -o smbkrb5pwd_srv.o

smbkrb5pwd_srv.la:	smbkrb5pwd_srv.lo
	$(LIBTOOL) --mode=link $(CC)  $(MIT_KRB5_SRV_LIB) $(OPT) -version-info 0:0:0 \
	-rpath $(moduledir) -module -o $@ $? $(LIBS) $(MIT_KRB5_SRV_LIB)

.PHONY: clean
clean:
	rm -f smbkrb5pwd.lo smbkrb5pwd.la smbkrb5pwd_srv.lo smbkrb5pwd_srv.la

.PHONY: install
install: smbkrb5pwd.la
	mkdir -p $(DESTDIR)$(moduledir)
	$(LIBTOOL) --mode=install cp smbkrb5pwd.la $(DESTDIR)$(moduledir)
	$(LIBTOOL) --mode=install cp smbkrb5pwd_srv.la $(DESTDIR)$(moduledir)
