#
# Makefile for x86_64-specific library files.
#

CFLAGS_csum-partial.o := -funroll-loops

obj-y := io.o

lib-y := csum-partial.o csum-copy.o csum-wrappers.o delay.o \
	usercopy.o getuser.o putuser.o  \
	thunk.o clear_page.o copy_page.o bitstr.o
lib-y += memcpy.o memmove.o memset.o copy_user.o

lib-$(CONFIG_HAVE_DEC_LOCK) += dec_and_lock.o
