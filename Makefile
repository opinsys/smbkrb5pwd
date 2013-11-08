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

LIBTOOL=../../../debian/build/libtool
OPT=-g -O2
CLNT_OPT=-DSMBKRB5PWD_KADM5_CLNT
SRV_OPT=-DSMBKRB5PWD_KADM5_SRV
CC=gcc

SSL_INC=
LDAP_INC=-I../../../include -I../../../servers/slapd -I../../../../../include -I../../../../../servers/slapd -I../../../debian/build/include
INCS=$(LDAP_INC) $(SSL_INC)

KRB5_LIB=-lkrb5
MIT_KRB5_SRV_LIB=-lkadm5srv_mit
MIT_KRB5_CLNT_LIB=-lkadm5clnt_mit
SSL_LIB=-lcrypto
LDAP_LIB=-L../../../debian/build/libraries/libldap_r/.libs -lldap_r \
	 -L../../../debian/build/libraries/liblber/.libs -llber
LIBS=$(LDAP_LIB) $(KRB5_LIB) $(SSL_LIB)

prefix=/usr/local
exec_prefix=$(prefix)
ldap_subdir=/openldap

libdir=$(exec_prefix)/lib
libexecdir=$(exec_prefix)/libexec
#moduledir = $(libexecdir)$(ldap_subdir)
moduledir = /usr/lib/ldap

all:	smbkrb5pwd.la smbkrb5pwd_srv.la


smbkrb5pwd.lo:	smbkrb5pwd.c
	$(LIBTOOL) --mode=compile $(CC) $(CLNT_OPT) $(OPT) $(DEFS) $(INCS) -c $?

smbkrb5pwd.la:	smbkrb5pwd.lo
	$(LIBTOOL) --mode=link $(CC) $(MIT_KRB5_CLNT_LIB) $(OPT) -version-info 0:0:0 \
	-rpath $(moduledir) -module -o $@ $? $(LIBS) $(MIT_KRB5_CLNT_LIB)

smbkrb5pwd_srv.lo:	smbkrb5pwd.c
	$(LIBTOOL) --mode=compile $(CC) $(SRV_OPT) $(OPT) $(DEFS) $(INCS) -c smbkrb5pwd.c -o smbkrb5pwd_srv.o

smbkrb5pwd_srv.la:	smbkrb5pwd_srv.lo
	$(LIBTOOL) --mode=link $(CC)  $(MIT_KRB5_SRV_LIB) $(OPT) -version-info 0:0:0 \
	-rpath $(moduledir) -module -o $@ $? $(LIBS) $(MIT_KRB5_SRV_LIB)


clean:
	rm -f smbkrb5pwd.lo smbkrb5pwd.la smbkrb5pwd_srv.lo smbkrb5pwd_srv.la

install: smbkrb5pwd.la
	mkdir -p $(DESTDIR)/$(SMBKRB5PWD_PREFIXDIR)$(moduledir)
	$(LIBTOOL) --mode=install cp smbkrb5pwd.la $(DESTDIR)/$(SMBKRB5PWD_PREFIXDIR)$(moduledir)
	$(LIBTOOL) --mode=install cp smbkrb5pwd_srv.la $(DESTDIR)/$(SMBKRB5PWD_PREFIXDIR)$(moduledir)
