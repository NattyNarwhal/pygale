#!/usr/bin/env python

import openssl
import openssl.evp
import openssl.rsa
import openssl.bn
import gale_pack

PRIVATE_MAGIC = 'h\023\000\001'
PRIVATE_MAGIC2 = 'h\023\000\003'
PRIVATE_MAGIC3 = 'GALE\000\002'
GALE_RSA_MODULUS_BITS = 1024
GALE_RSA_MODULUS_LEN = ((GALE_RSA_MODULUS_BITS + 7) / 8)
GALE_RSA_PRIME_BITS = ((GALE_RSA_MODULUS_BITS + 1) / 2)
GALE_RSA_PRIME_LEN = ((GALE_RSA_PRIME_BITS + 7) / 8)
GALE_ENCRYPTED_KEY_LEN = GALE_RSA_MODULUS_LEN
GALE_SIGNATURE_LEN = GALE_RSA_MODULUS_LEN

def import_privkey(key, rsa):
        # _ga_import_priv
        (magic, key) = gale_pack.pop_data(key, len(PRIVATE_MAGIC))
        if PRIVATE_MAGIC == magic:
                version = 1
                (keyname, key) = gale_pack.pop_nulltermstr(key)
        elif PRIVATE_MAGIC2 == magic:
                version = 2
                (keyname, key) = gale_pack.pop_lenstr(key, chars=1)
        else:
		version = 3
		(more_magic, key) = gale_pack.pop_data(key, len(PRIVATE_MAGIC3) - len(PRIVATE_MAGIC))
		magic = magic + more_magic
		if magic != PRIVATE_MAGIC3:
			return
		(keyname, key) = gale_pack.pop_lenstr(key, chars=1)
		fraglist = gale_pack.group_to_FragList(key, 1)
		big_num = openssl.bn.bin2bn(fraglist.get_binary_first('rsa.modulus'))
		rsa.n = openssl.bn.bin2bn(fraglist.get_binary_first('rsa.modulus'))
		rsa.e = openssl.bn.bin2bn(fraglist.get_binary_first('rsa.exponent'))
		rsa.d = openssl.bn.bin2bn(fraglist.get_binary_first('rsa.private.exponent'))
		prime_data = fraglist.get_binary_first('rsa.private.prime')
		rsa.p = openssl.bn.bin2bn(prime_data[:GALE_RSA_PRIME_LEN])
		rsa.q = openssl.bn.bin2bn(prime_data[GALE_RSA_PRIME_LEN:])
		prime_data = fraglist.get_binary_first('rsa.private.prime.exponent')
		rsa.dmp1 = openssl.bn.bin2bn(prime_data[:GALE_RSA_PRIME_LEN])
		rsa.dmq1 = openssl.bn.bin2bn(prime_data[GALE_RSA_PRIME_LEN:])
		rsa.iqmp = openssl.bn.bin2bn(fraglist.get_binary_first('rsa.private.coefficient'))
		return



        (bits, key) = gale_pack.pop_int(key)
        (modulus, key) = gale_pack.pop_rle(key, GALE_RSA_MODULUS_LEN)
	rsa.n = openssl.bn.bin2bn(modulus, len(modulus), rsa.n.this)
	print '1', rsa.n.d
        (pubexp, key) = gale_pack.pop_rle(key, GALE_RSA_MODULUS_LEN)
	rsa.e = openssl.bn.bin2bn(pubexp, len(pubexp), rsa.e.this)
        (exp, key) = gale_pack.pop_rle(key, GALE_RSA_MODULUS_LEN)
	rsa.d = openssl.bn.bin2bn(exp, len(exp), rsa.d.this)
        (prime, key) = gale_pack.pop_rle(key, GALE_RSA_PRIME_LEN * 2)
	rsa.p = openssl.bn.bin2bn(prime, GALE_RSA_PRIME_LEN, rsa.p.this)
	rsa.q = openssl.bn.bin2bn(prime[GALE_RSA_PRIME_LEN:], GALE_RSA_PRIME_LEN, rsa.q.this)
        (primeexp, key) = gale_pack.pop_rle(key, GALE_RSA_PRIME_LEN * 2)
	rsa.dmp1 = openssl.bn.bin2bn(primeexp, GALE_RSA_PRIME_LEN, rsa.dmp1.this)
	rsa.dmq1 = openssl.bn.bin2bn(primeexp[GALE_RSA_PRIME_LEN:], GALE_RSA_PRIME_LEN, rsa.dmq1.this)
        (coef, key) = gale_pack.pop_rle(key, GALE_RSA_PRIME_LEN)
	rsa.iqmp = openssl.bn.bin2bn(coef, GALE_RSA_PRIME_LEN, rsa.iqmp.this)
	print '2', rsa.n.d


def import_pubkey(key, rsa):
        (magic, key) = gale_pack.pop_data(key, len(PRIVATE_MAGIC3))
	(namelen, key) = gale_pack.pop_int(key)
        (pubkeyname, key) = gale_pack.pop_string(key, namelen, chars=1)
	fraglist = gale_pack.group_to_FragList(key, 1)
	rsa.n = openssl.bn.bin2bn(fraglist.get_binary_first('rsa.modulus'))
	rsa.e = openssl.bn.bin2bn(fraglist.get_binary_first('rsa.exponent'))
	rsa.d = openssl.bn.bin2bn(fraglist.get_binary_first('rsa.private.exponent'))
	prime_data = fraglist.get_binary_first('rsa.private.prime')
	rsa.p = openssl.bn.bin2bn(prime_data[:GALE_RSA_PRIME_LEN])
	rsa.q = openssl.bn.bin2bn(prime_data[GALE_RSA_PRIME_LEN:])
	prime_data = fraglist.get_binary_first('rsa.private.prime.exponent')
	rsa.dmp1 = openssl.bn.bin2bn(prime_data[:GALE_RSA_PRIME_LEN])
	rsa.dmq1 = openssl.bn.bin2bn(prime_data[GALE_RSA_PRIME_LEN:])
	rsa.iqmp = openssl.bn.bin2bn(fraglist.get_binary_first('rsa.private.coefficient'))


key_file = open('/home/calvin/src/gale/cb@scrollwheel.ca.gpri', 'rb')
priv_key = openssl.evp.PKEY()
priv_key.assign_RSA(openssl.rsa.RSA())
key_data = key_file.read()
key_file.close()
import_privkey(key_data, priv_key.rsa)
key_file = open('/home/calvin/src/gale/cb@scrollwheel.ca.gpub', 'r')
pub_key = openssl.evp.PKEY()
pub_key.assign_RSA(openssl.rsa.RSA())
pub_data = key_file.read()
key_file.close()
import_pubkey(key_data, pub_key.rsa)
context = openssl.evp.MD_CTX()
context.SignInit(openssl.evp.md5())
context.SignUpdate('foobar')
signature = context.SignFinal(priv_key)
context = openssl.evp.MD_CTX()
context.VerifyInit(openssl.evp.md5())
context.VerifyUpdate('foobar')
result  = context.VerifyFinal(signature, pub_key)
context = openssl.evp.CIPHER_CTX()
(iv, encrypted_keys) = context.SealInit(openssl.evp.des_ede3_cbc(), [pub_key])
result = context.SealUpdate('foo')
encrypted_data = context.SealFinal()
result = context.OpenInit(openssl.evp.des_ede3_cbc(), encrypted_keys[0], iv, priv_key)
result = context.OpenUpdate(encrypted_data)
result = context.OpenFinal()
priv_key = None
key_data = None
key_file = None
pub_data = None
context = None
signature = None
result = None
iv = None
encrypted_keys = None
