import time, string
import pygale, gale_pack, authcache
import openssl.evp
from gale_const import *

SIG_MAGIC = 'h\023\001\000'
KEY_MAGIC = 'h\023\000\000'
KEY_MAGIC2 = 'h\023\000\002'
KEY_MAGIC3 = 'GALE'
SUBVERSION = '\000\001'
DEBUG = 0

class Key:
	def __init__(self, name=None):
		self.__pubkey = None
		self.__privkey = None
		self.__comment = None
		self.__keyname = name
		self.__data = None
		self.__links_to_me = []
		# dangermouse
		self.__members = []
		self.__verified = 0
		self.__redirect = None

	def destroy(self):
		# Not yet in use
		# The lists are the most important ones
		self.__links_to_me = []
		self.__members = []
		self.__pubkey = None
		self.__privkey = None
		self.__comment = None
		self.__keyname = name
		self.__data = None
		self.__redirect = None
	
	def __repr__(self):
		s = 'Key <%s>' % self.__keyname
		if self.__privkey:
			s = s + ' private'
		if self.__pubkey:
			s = s + ' public'
		if self.__members:
			s = s + ' members%s' % `self.__members`
		if self.__comment:
			s = s + ' [%s]' % self.__comment
		if self.__links_to_me:
			s = s + ' (%s)' % string.join(self.__links_to_me, ',')
		return s
	__str__ = __repr__
	
	# These functions operate on the original name of the key object
	def name(self):
		return self.__keyname
	def setname(self, name):
		self.__keyname = name
	
	def comment(self):
		return self.__comment
	def setcomment(self, comment):
		self.__comment = comment
	
	def public(self):
		return self.__pubkey
	def setpublic(self, pub):
		self.__pubkey = pub

	def private(self):
		return self.__privkey
	def setprivate(self, priv):
		self.__privkey = priv
	
	def trusted(self):
		return self.__trusted
	def settrusted(self, trust):
		self.__trusted = trust
	
	def data(self):
		return self.__data
	def setdata(self, data):
		self.__data = data
	
	def set_links(self, list_of_names):
		self.__links_to_me = list_of_names
	def get_links_to_me(self):
		return self.__links_to_me

	def members(self):
		return self.__members
	def set_members(self, list_of_members):
		self.__members = list_of_members

	def verified(self):
		return self.__verified
	def set_verified(self, v=1):
		self.__verified = v

	def redirect(self):
		return self.__redirect
	def set_redirect(self, r):
		self.__redirect = r

# ------------------------------------------------------------
# Routines for signature verification 
# ------------------------------------------------------------

def flip_local_key_part(keyname):
	"""Take a key name in the form "*.test@ofb.net", flip the local
	part, and return something like "test.*@ofb.net" """
	i = string.rfind(keyname, '@')
	if i == -1:
		# Must be a domain key
		return keyname
	localparts = string.split(keyname[:i], '.')
	localparts.reverse()
	domain = keyname[i:]
	return string.join(localparts, '.') + domain

# Returns (or calls the callback with) the name of the key
# Import a key from a binary representation of the key structure
def import_pubkey(keyobj, callback, trust=0):
	if DEBUG > 2: print '--> Starting import_pubkey'
	keydata = keyobj.data()
	# _ga_import_pub
	# Back up the key to verify its signature, later
	save = keydata
	(magic, keydata) = gale_pack.pop_data(keydata, len(KEY_MAGIC))
	if KEY_MAGIC == magic:
		version = 1
	elif KEY_MAGIC2 == magic:
		version = 2
	elif KEY_MAGIC3 == magic:
		(subversion, keydata) = gale_pack.pop_data(keydata,
			len(SUBVERSION))
		if SUBVERSION == subversion:
			version = 3
		else:
			pygale.call_error_handler('Unsupported version 3 key format')
			keyobj.setpublic(None)
			keyobj.set_verified(0)
			callback(keyobj)
			return
	else:
		pygale.call_error_handler('Unsupported public key (bad magic)')
		keyobj.setpublic(None)
		keyobj.set_verified(0)
		callback(keyobj)
		return
	# version must be <= 3 at this point
	if DEBUG >= 3: print 'Public key version:', version

	if version > 1:
		(namelen, keydata) = gale_pack.pop_int(keydata)
		(pubkeyname, keydata) = gale_pack.pop_string(keydata, namelen,
			chars=1)
	else:	# version == 1
		(pubkeyname, keydata) = gale_pack.pop_nulltermstr(keydata)
	pubkeyname = flip_local_key_part(pubkeyname)
	if DEBUG > 2: print 'Unpacking public key named:', pubkeyname
	keyobj.setname(pubkeyname)
	if DEBUG > 2: print 'Setting name in %s to %s' % (`keyobj`, pubkeyname)
	keyobj.settrusted(trust)

	if len(keydata) == 0:
		if DEBUG: print 'Found stub key for', pubkeyname
		keyobj.setpublic(None)
		callback(keyobj)
		return

	# Otherwise, deal with a non-stub key
	# Special-case for different version keys.  Version 3 is the key with
	# fragments in it, which Dan introduced in 0.91b.
	if version == 3:
		fraglist = gale_pack.group_to_FragList(keydata, DAN_IS_STOOPID=1)

		# Verify key if it's signed
		if fraglist.has_key('security/signature'):
			# deal with only the first security/signature fragment
			sig = fraglist.get_binary_first('security/signature')
			(sig_len, sig) = gale_pack.pop_int(sig)
			(signature, sig) = gale_pack.pop_data(sig, sig_len)
			msg_data = sig
			new_fragments = gale_pack.group_to_FragList(sig)
			fraglist.update(new_fragments)
		else:
			signature = ''
			# TODO
			# This hacky setting of msg_data is to fix the bug later on
			# where we try to call decode_sig with msg_data.  I need to
			# dig into key formats more to find the right thing to do.
			msg_data = ''

		# TODO dangermouse
		# Redirects should not be handled here since the field contains
		# a *location* and not a key name
		if fraglist.get_text('key.redirect'):
			# Handle a key redirection: the field contains a *location*
			keyobj.set_redirect(fraglist.get_text_first('key.redirect'))

		# Use only the first instance of each fragment if it exists
		comment = fraglist.get_text_first('key.owner', 'Unspecified owner')
		time_sign = fraglist.get_time_first('key.signed', 0)
		time_expire = fraglist.get_time_first('key.expires', 0)
		rsa_keybits = fraglist.get_int_first('rsa.bits', 0)
		rsa_modulus = fraglist.get_binary_first('rsa.modulus', '')
		rsa_exponent = fraglist.get_binary_first('rsa.exponent', '')

		# Set the list of key members but do not look them up at this
		# point
		if fraglist.has_key('key.member'):
			keyobj.set_members(fraglist.get_text('key.member'))
		# Done unpacking version 3 key

	# Version 1 or 2 keys are packed binary data.
	elif version == 1 or version == 2:
		if version == 2:
			(comment, keydata) = gale_pack.pop_lenstr(keydata, chars=1)
		else:
			(comment, keydata) = gale_pack.pop_nulltermstr(keydata)
		if DEBUG > 2: print 'Found comment:', comment

		(rsa_keybits, keydata) = gale_pack.pop_int(keydata)
		(rsa_modulus, keydata) = gale_pack.pop_rle(keydata,
			GALE_RSA_MODULUS_LEN)
		(rsa_exponent, keydata) = gale_pack.pop_rle(keydata,
			GALE_RSA_MODULUS_LEN)
		if rsa_keybits > GALE_RSA_MODULUS_BITS:
			pygale.call_error_handler(
				'bad public key bit size %i' % rsa_keybits)
			keyobj.setpublic(None)
			keyobj.set_verified(0)
			callback(keyobj)
			return

		if version > 1 and keydata:
			(time_sign, keydata) = gale_pack.pop_time(keydata)
			(time_expire, keydata) = gale_pack.pop_time(keydata)
			if DEBUG > 2: print 'Key signed at:', time_sign.ctime()
			if DEBUG > 2: print 'Key expires at:', time_expire.ctime()
#			if time_expire <= time.time():
#				pygale.call_error_handler('found expired key for %s' %
#					pubkeyname)
#				callback(None)
#				return
		else:
			# no key timestamp checking in version 1
			pass
		signature = keydata

		# Done unpacking version 1 or version 2 key
	else:
		# unsupported version
		pygale.call_error_handler('unsupported key version: %i' %
			version)
		keyobj.setpublic(None)
		keyobj.set_verified(0)
		callback(keyobj)
		return
	
	# TODO: check for expired keys

	keyobj.setcomment(comment)
	if rsa_keybits:
		pubkey = openssl.evp.PKEY()
		pubkey.assign_RSA(openssl.rsa.RSA())
		pubkey.rsa.n = openssl.bn.bin2bn(rsa_modulus)
		pubkey.rsa.e = openssl.bn.bin2bn(rsa_exponent)
		keyobj.setpublic(pubkey)
	else:
		# No public key bits in this key
		keyobj.setpublic(None)

	# Import and validate the signature on this public key
	if not keyobj.trusted():
		if DEBUG > 2: print 'import_pubkey: Verifying sig'
		if version < 3:
			msg_data = save[:-len(keydata)]
		if not signature or not msg_data:
			pygale.call_error_handler('unsigned key %s' % keyobj.name())
			keyobj.setpublic(None)
			keyobj.set_verified(0)
			callback(keyobj)
			return
		decode_sig(signature, msg_data, lambda k, u=keyobj, c=callback:
			decode_done(k, u, c))

	else:
		if DEBUG: print 'Key is trusted; not verifying'
		keyobj.set_verified(1)
		callback(keyobj)
		return

# Maybe this ought to be called verify() instead
def decode_sig(sig, msg_data, callback):
	if DEBUG > 2: print '--> Starting decode_sig'

	keyobj = Key()
	if DEBUG > 2: print 'Creating keyobj', keyobj

	# _ga_import_sig
	(magic, sig) = gale_pack.pop_data(sig, len(SIG_MAGIC))
	if SIG_MAGIC != magic:
		pygale.call_error_handler("invalid signature format")
		keyobj.set_verified(0)
		callback(keyobj)
		return
	(siglen, sig) = gale_pack.pop_int(sig)
	if siglen > GALE_SIGNATURE_LEN:
		pygale.call_error_handler('invalid signature format')
		keyobj.set_verified(0)
		callback(keyobj)
		return
	(sigdata, sig) = gale_pack.pop_data(sig, siglen)

	# These are the keybits doing the signing
	(keydata, sig) = gale_pack.pop_data(sig, len(sig))
	keyobj.setdata(keydata)
		
	# Try to find a public key for this signature
	if DEBUG > 2: print 'decode_sig: importing key'
	import_pubkey(keyobj, lambda k, d=sigdata,
		m=msg_data, c=callback: decode_sig2(k, d, m, c))

def decode_done(key, upper_key, callback):
	if not key.verified():
		if DEBUG > 2: print 'decode_done: cannot use %s to verify %s' %\
			(key.name(), upper_key.name())
		pygale.call_error_handler('unable to verify signature %s' %
			key.name())
		callback(key)
		return
	if DEBUG > 1: print 'decode_done: key %s verified key %s' % (key.name(),
		upper_key.name())
	upper_key.set_verified(1)
	if DEBUG > 2: print 'decode_done: adding %s to memory cache' %\
		upper_key.name()
	authcache.add_to_memory_cache(upper_key)
	callback(upper_key)
	return

# The second part of decoding a signature
def decode_sig2(key, sigdata, msg_data, callback):
	# TODO
#	if key.public() is None:
#		pygale.call_error_handler('unable to parse public key')
#		callback(key)
#		return

	if DEBUG > 2: print 'decode_sig2: found key', key.name()
	if key.public() is not None:
		# We have the key right here
		if DEBUG > 2: print 'decode_sig2: have key, verifying'
		if verify_sig(key, sigdata, msg_data):
			if DEBUG > 2: print 'decode_sig2: verification OK'
			key.set_verified(1)
			callback(key)
			return
	else:
		if DEBUG > 2:
			print 'decode_sig2: ... but it has no key bits (%s)' %\
				key.name()
	
	# We don't know the public key (or it failed to verify the message),
	# so try the authcache
	cachedkey = authcache.get_key(key.name())
	if cachedkey and cachedkey.public():
		if verify_sig(cachedkey, sigdata, msg_data):
			# It verifies OK
			assert cachedkey.verified()
			callback(cachedkey)
			return

	# If it's not in the memory cache, try finding it on disk
	authcache.find_pubkey_fromdisk(key, lambda key, d=sigdata, m=msg_data,
		c=callback: decode_sig3(key, d, m, c))

# The third part of decoding a signature
def decode_sig3(key, sigdata, msg_data, callback):
	if DEBUG > 2: print 'decode_sig3: key', key.name()
	if key.public() is not None:
		# We found it on disk; see if it verifies
		if verify_sig(key, sigdata, msg_data):
			if DEBUG > 2: print 'decode_sig3: verifies OK'
			key.set_verified(1)
			authcache.add_to_memory_cache(key)
			callback(key)
			return

	# Otherwise, we can't find it (or it doesn't verify the puff)
	# Try (gasp) AKD
	if DEBUG: print 'decode_sig3: uh oh, we have to do AKD on', key.name()
	authcache.find_pubkey_akd(key, lambda key, d=sigdata, m=msg_data,
		c=callback: decode_sig4(key, d, m, c))

# The fourth step in decoding a signature
def decode_sig4(key, sigdata, msg_data, callback):
	if key.public() is not None:
		if DEBUG: print 'decode_sig4: key found', key.name()
		# We found something via AKD
		if verify_sig(key, sigdata, msg_data):
			# And it verifies!
			if DEBUG: print 'decode_sig4: %s verifies OK' % key.name()
			key.set_verified(1)
			authcache.save_pubkey_todisk(key)
			callback(key)
			return
		else:
			if DEBUG: print 'decode_sig4: %s does not verify' % key.name()
			key.setpublic(None)
			key.set_verified(0)
			callback(key)
			return
	else:
		# Otherwise, give up!
		if DEBUG: print 'decode_sig4: no key found for', key.name()
		pygale.call_error_handler("Warning: no public key for %s" %
			key.name())
		key.set_verified(0)
		callback(key)
		return

# This verifies a single chunk
def verify_sig(key, sigdata, msg_data):
	"""Return 1 iff the sigdata is the signed message digest for msg_data,
	signed with the key key"""
	if DEBUG > 2: print 'verify_sig: verifying sig with key %s (%s)' %\
		(key, key.name())
	if key.trusted():
		if DEBUG > 2: print 'verify_sig: trusted key'
		key.set_verified(1)
		return 1
	assert key.public()

	context = openssl.evp.MD_CTX()
	context.VerifyInit(openssl.evp.md5())
	context.VerifyUpdate(msg_data)
	retval = context.VerifyFinal(sigdata, key.public())
	if retval != 1:
		pygale.call_error_handler(
			'signature %s does not verify (key mismatch?)' % key.name())
		return 0
	else:
		return 1
