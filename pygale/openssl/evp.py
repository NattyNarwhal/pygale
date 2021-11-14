#!/usr/bin/env python
#
# $Id: evp.py,v 1.2 2006/07/02 02:30:22 jtr Exp $
#

import opensslc
try:
  import _evpc as evpc
except ImportError:
  import evpc
import rsa
import wrap


class MD(wrap.Wrapper):
	def __init__(self, ptr = None):
		wrap.Wrapper.__init__(self, ptr)

	

class MD_CTX(wrap.Wrapper):
	def __init__(self, ptr = None):
		wrap.Wrapper.__init__(self, ptr, evpc.EVP_MD_CTX_new, evpc.EVP_MD_CTX_free)


	def SignInit(self, type):
		evpc.EVP_SignInit(self.ptr, type.ptr)


	def SignUpdate(self, signature_data):
		evpc.EVP_SignUpdate(self.ptr, signature_data, len(signature_data))


	def SignFinal(self, key):
		return evpc.python_EVP_SignFinal(self.ptr, key.ptr)


	def VerifyInit(self, type):
		evpc.EVP_VerifyInit(self.ptr, type.ptr)


	def VerifyUpdate(self, signed_data):
		evpc.EVP_VerifyUpdate(self.ptr, signed_data, len(signed_data))


	def VerifyFinal(self, signature, key):
		return evpc.EVP_VerifyFinal(self.ptr, signature, len(signature), key.ptr)



class PKEY(wrap.Wrapper):
	def __init__(self, ptr = None):
		attr_dict = \
		{
			'rsa': (evpc.EVP_PKEY_get0_RSA, evpc.EVP_PKEY_set1_RSA, rsa.RSA),
		}
		wrap.Wrapper.__init__(self, ptr, evpc.EVP_PKEY_new, evpc.EVP_PKEY_free, attr_dict)


	def assign_RSA(self, rsa_key): 
		evpc.EVP_PKEY_assign_RSA(self.ptr, rsa_key.ptr)
		rsa_key.free_ptr = 0



class CIPHER(wrap.Wrapper):
	def __init__(self, ptr = None):
		wrap.Wrapper.__init__(self, ptr)



class CIPHER_CTX(wrap.Wrapper):
	def __init__(self, ptr = None):
		wrap.Wrapper.__init__(self, ptr, evpc.EVP_CIPHER_CTX_new, evpc.EVP_CIPHER_CTX_free)


	def SealInit(self, type, public_keys):
		return evpc.python_EVP_SealInit(self.ptr, type.ptr, public_keys)


	def SealUpdate(self, unencrypted_data):
		return evpc.python_EVP_SealUpdate(self.ptr, unencrypted_data)


	def SealFinal(self):
		return evpc.python_EVP_SealFinal(self.ptr)


	def OpenInit(self, type, encrypted_key, iv, private_key):
		return evpc.EVP_OpenInit(self.ptr, type.ptr, encrypted_key, len(encrypted_key), iv, private_key.ptr)


	def OpenUpdate(self, encrypted_data):
		return evpc.python_EVP_OpenUpdate(self.ptr, encrypted_data)


	def OpenFinal(self):
		return evpc.python_EVP_OpenFinal(self.ptr)


def md5():
	return MD(evpc.EVP_md5())


def des_ede3_cbc():
	return CIPHER(evpc.EVP_des_ede3_cbc())


