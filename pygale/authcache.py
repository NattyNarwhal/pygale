"""
pygale.authcache


"""
import os, time, select, string, tempfile, sys, traceback
from types import *
import pygale, gale_pack, sign, gale_env, engine, userinfo
import openssl.evp
from gale_const import *

GALE_DIR = gale_env.get('GALE_DIR',
    os.path.join(userinfo.home_dir, '.gale'))
DEBUG = 0
PRIVATE_MAGIC = 'h\023\000\001'
PRIVATE_MAGIC2 = 'h\023\000\003'
PRIVATE_MAGIC3 = 'GALE'
SUBVERSION = '\000\002'

KEY_RESPONSE_CAT = '_gale.key.'
OLD_KEY_RESPONSE_CAT = '@%s/auth/key/%s/'
KEY_REQUEST_CAT = '_gale.query.'
OLD_KEY_REQUEST_CAT = '@%s/auth/query/%s/'

NORMAL = 0
TRUSTED = 1

# Timeout for AKD requests (in milliseconds)
AKD_TIMEOUT = 30000
# Time between AKD requests for same key (in seconds)
AKD_INTERVAL = 60

# ----------------------------------------------------------------------
# Collector abstract data type
class NullValueClass: pass
NullValue = NullValueClass()

class Collector:
  def __init__(self, inputs):
    """Inputs is the list of items for which outputs need to be
    collected"""
    self.__inputs = inputs
    self.__values = {}
    for item in inputs:
      self.__values[item] = NullValue
  
  def setoutput(self, input, output):
    """Set this output for this input"""
    if DEBUG > 1:
      print 'COLL: set[%s] = %s' % (input, output)
    self.__values[input] = output
  
  def done(self):
    """Return 1 iff the collector has collected outputs for all its
    inputs"""
    for item in self.__values.keys():
      if self.__values[item] == NullValue:
        return 0
    if DEBUG > 1:
      print 'COLL: done'
    return 1
  
  def getvalues(self):
    """Return a list of outputs corresponding to my list of inputs"""
    return map(lambda x, d=self.__values: d[x], self.__inputs)

# Request a set of keys.  Use the first key to return.
class AnyCollector:
  "Done as soon as any input receives an output"
  def __init__(self, keynames):
    """Inputs is the list of items for which outputs need to be
    collected"""
    self.__inputs = keynames
    self.__values = {}
    self.__done = 0 # after done once, ignore remaining outputs
    for item in keynames:
      self.__values[item] = NullValue
  
  def setoutput(self, keyname, keyobj):
    """Set this output for this input"""
    if self.__done: return
    if DEBUG > 1:
      print 'ANYCOLL: set[%s] = %s' % (keyname, keyobj)
    self.__values[keyname] = keyobj
  
  def done(self):
    """Return 1 iff the collector has collected at least one
    output"""
    if self.__done:
      # If already done, don't fire again
      return 0
    for item in self.__values.keys():
      if self.__values[item] is not None and\
        self.__values[item] != NullValue:
        self.__done = 1
        if DEBUG > 1:
          print 'ANYCOLL: done (with something)'
        return 1
    values = self.__values.values()
    if NullValue not in values:
      # Means we got a response from everything, even if each one
      # was None
      if DEBUG > 1:
        pygale.call_debug_handler('ANYCOLL: done (with None)')
      return 1
    if DEBUG > 1:
      pygale.call_debug_handler('ANYCOLL: not done... still waiting')
    return 0
  
  def getvalue(self):
    """Return the first output"""
    values = self.__values.values()
    goodvalues = filter(lambda x: x is not None and x != NullValue,
      values)
    if not goodvalues:
      goodvalues = filter(lambda x: x != NullValue, values)
    return goodvalues[0]

# ----------------------------------------------------------------------
class KeyCacheClass:
  def __init__(self):
    self.__keys = {}    # in-memory key cache
    self.__last_akd = {}  # Time we did last AKD request for key
    self.__keychain = {}  # List of callbacks waiting for a key
  def set(self, name, val):
    self.__keys[name] = val
  def get(self, name):
    return self.__keys[name]
  def __len__(self):
    return len(self.__keys)
  def has_key(self, name):
    return self.__keys.has_key(name)

  def get_key(self, name):
    # TODO: check for newer on-disk version
    if self.__keys.has_key(name):
      return self.__keys[name]
    else:
      return None

  def add_to_memory_cache(self, keyobj):
    self.__keys[keyobj.name()] = keyobj

  # AKD
  def find_pubkey_akd(self, keyobj, callback):
    name = keyobj.name()
    if DEBUG:
      pygale.call_debug_handler('Finding public key via AKD: %s' % name)
    if '@' in name:
      i = string.find(name, '@')
      domain = name[i+1:]
      user = name[:i]
    else:
      # Hmm, we can't request a domain key without the user
      # Invalid key name
      keyobj.setpublic(None)
      callback(keyobj)
      return
    if ':' in name:
      keyobj.setpublic(None)
      pygale.call_error_handler(
        'Ignoring AKD request for %s with colon' % name)
      callback(keyobj)
      return

    # First see when was the last time we did AKD for this key
    if self.__last_akd.has_key(name):
      last_checked = self.__last_akd[name]
      now = time.time()
      if now - last_checked < AKD_INTERVAL:
        # Chain requests
        if DEBUG:
          pygale.call_debug_handler(
            'not doing AKD for %s; done too recently' %
            name)
        pygale.call_update_handler('Chaining to existing key '+
          'request for %s' % name)
        self.__keychain[name] = self.__keychain.get(name, []) +\
          [callback]
        return
    else:
      self.__last_akd[name] = time.time()
  
    self.__keychain[name] = self.__keychain.get(name, []) +\
      [callback]
    pygale.call_update_handler('Requesting key %s' % name)
    client = pygale.GaleClient()
    client.connect(lambda h, s=self, d=domain, u=user, n=name, k=keyobj,
      c=client: s.find_pubkey_akd2(h, d, u, n, c, k))

  def find_pubkey_akd2(self, hostname, domain, user, name, client,
    keyobj):
    if hostname is None:
      pygale.call_error_handler('Unable to connect to gale ' +
        'server for AKD')
      keyobj.setpublic(None)
      self.cleanup_akd(keyobj)
      return

    flipped_user = string.split(user, '.')
    flipped_user.reverse()
    flipped_user = string.join(flipped_user, '.')
    locs = ['%s%s@%s' % (KEY_RESPONSE_CAT, user, domain),
      OLD_KEY_RESPONSE_CAT % (domain, flipped_user)]
    cb = lambda b, g, s=self, u=user, d=domain, n=name, c=client, \
      k=keyobj: s.find_pubkey_akd3(b, g, u, d, n, c, k)
    client.sub_to(locs, cb)
  
  def find_pubkey_akd3(self, bad_locs, good_locs, user, domain, name,
    client, keyobj):

    if bad_locs:
      pygale.call_error_handler('Error subscribing to AKD ' +
        'location %s' % string.join(bad_locs, ', '))
      keyobj.setpublic(None)
      self.cleanup_akd(keyobj)
      return
    p = pygale.Puff()

    # for backwards compatibility with old key serving clients
    # dangermouse
    p.set_text('question.key', name)
    p.set_text('question/key', sign.flip_local_key_part(name))

    flipped_user = string.split(user, '.')
    flipped_user.reverse()
    flipped_user = string.join(flipped_user, '.')

    auth_locs = ['%s%s@%s' % (KEY_REQUEST_CAT, user, domain)]
    auth_locs.append(OLD_KEY_REQUEST_CAT % (domain, flipped_user))
    p.set_loc(string.join(auth_locs, ' '))

    timeout_callback = lambda k=keyobj, s=self, l=client:\
      s.handle_AKD_timeout(k, l)
    # add_timeout returns a handle to use to cancel the timeout
    timeout_handle = engine.engine.add_timeout(AKD_TIMEOUT,
      timeout_callback)
    client.set_puff_callback(lambda p, s=self, k=keyobj,
      l=client, t=timeout_handle, d=domain:
      s.handle_key_puff(p, k, l, t, d))
    client.transmit_puff(p)
  
  def cleanup_akd(self, keyobj):
    name = keyobj.name()
    if keyobj.public():
      for keyname in [name] + keyobj.get_links_to_me():
        self.__keys[keyname] = keyobj
    if DEBUG:
      pygale.call_debug_handler('Cleaning up after %s' % name)
      pygale.call_debug_handler('Links to me: %s' %
          keyobj.get_links_to_me())

    for name in [keyobj.name()] + keyobj.get_links_to_me():
      if self.__keychain.has_key(name):
        # make copy of callbacks
        cbs = self.__keychain[name][:]
        del self.__keychain[name]
        for cb in cbs:
          cb(keyobj)
      if self.__last_akd.has_key(name):
        del self.__last_akd[name]

  def handle_AKD_timeout(self, key, client):
    if DEBUG:
      pygale.call_debug_handler('AKD request timeout, key %s' % key.name())
    pygale.call_update_handler('key request for %s timed out' %
      key.name())
    client.del_puff_callback()
    key.setdata(None)
    self.cleanup_akd(key)

  def handle_key_puff(self, puff, keyobj, client, timeout_handle,
    domain):
    if DEBUG:
      pygale.call_debug_handler('Key response puff returned for %s' %
        keyobj.name())
    if DEBUG:
      pygale.call_debug_handler('Key response puff loc: %s' %
        `puff.get_loc()`)
    if puff.get_loc():
      # New-style AKD category
      if '_gale.key.' + keyobj.name() == puff.get_loc():
        if DEBUG:
          pygale.call_debug_handler('... and it is for the right key')
      else:
        if DEBUG:
          pygale.call_debug_handler(
            '... and it is for the wrong key; ignoring')
        return
    
    keyobj.setpublic(None)
    if puff.get_text('answer/key/error'):
      if DEBUG:
        pygale.call_debug_handler('... but it contains an error: %s' %
          puff.get_text_first('answer/key/error'))
      signer = puff.get_signer(None)
      if signer is None or signer != domain:
        if DEBUG:
          pygale.call_debug_handler('Received unverified AKD response')
        pygale.call_update_handler(
          'Received unverified AKD response from ' + `signer`)
        pygale.call_update_handler(
          'Unverified response: ' + puff.get_text_first(
            'answer/key/error'))
        return
      client.del_puff_callback()
      engine.engine.del_timeout(timeout_handle)
      pygale.call_update_handler(
        puff.get_text_first('answer/key/error', 'AKD error'))
      self.cleanup_akd(keyobj)
      return
    if puff.get_binary('answer/key'):
      if DEBUG:
        pygale.call_debug_handler('... and it contains answer/key')
      key = puff.get_binary_first('answer/key')
      keyobj.setdata(key)
      sign.import_pubkey(keyobj, lambda k, to=timeout_handle,
        c=client, s=self: s.finish_key_puff(k, c, to), 0)
    elif puff.get_binary('answer.key'):
      if DEBUG:
        pygale.call_debug_handler('... and it contains answer.key')
      key = puff.get_binary_first('answer.key')
      keyobj.setdata(key)
      sign.import_pubkey(keyobj, lambda k, to=timeout_handle,
        c=client, s=self: s.finish_key_puff(k, c, to), 0)
    else:
      if DEBUG:
        pygale.call_debug_handler(
          '... but it does not contain a key; waiting')
  
  def finish_key_puff(self, keyobj, client, timeout_handle):
    if DEBUG:
      pygale.call_debug_handler('Finished key puff for %s' % keyobj.name())
#   if not keyobj.public() and not keyobj.members():
    if not keyobj.verified():
      # Got a bad public key; don't bother cleaning up just yet
      if DEBUG:
        pygale.call_debug_handler(
          'Got a bad public key; waiting for another')
      return
    client.del_puff_callback()
    engine.engine.del_timeout(timeout_handle)
    self.cleanup_akd(keyobj)

# ----------------------------------------------------------------------

# ----------------------------------------------------------------------
# Private keys

def import_v3_privkey(key):
  fraglist = gale_pack.group_to_FragList(key, DAN_IS_STOOPID=1)
  privkey = openssl.evp.PKEY()
  privkey.assign_RSA(openssl.rsa.RSA())
  rsa = privkey.rsa
  rsa.n = openssl.bn.bin2bn(fraglist.get_binary_first('rsa.modulus'))
  rsa.e = openssl.bn.bin2bn(fraglist.get_binary_first('rsa.exponent'))
  rsa.d = openssl.bn.bin2bn(fraglist
      .get_binary_first('rsa.private.exponent'))
  prime_data = fraglist.get_binary_first('rsa.private.prime')
  rsa.p = openssl.bn.bin2bn(prime_data[:GALE_RSA_PRIME_LEN])
  rsa.q = openssl.bn.bin2bn(prime_data[GALE_RSA_PRIME_LEN:])
  prime_data = fraglist.get_binary_first('rsa.private.prime.exponent')
  rsa.dmp1 = openssl.bn.bin2bn(prime_data[:GALE_RSA_PRIME_LEN])
  rsa.dmq1 = openssl.bn.bin2bn(prime_data[GALE_RSA_PRIME_LEN:])
  rsa.iqmp = openssl.bn.bin2bn(fraglist
      .get_binary_first('rsa.private.coefficient'))
  return privkey


def import_v1or2_privkey(key):
  privkey = openssl.evp.PKEY()
  privkey.assign_RSA(openssl.rsa.RSA())
  (bits, key) = gale_pack.pop_int(key)
  if bits > GALE_RSA_MODULUS_BITS:
    pygale.call_error_handler('wrong number of bits in private key')
    return None
  (modulus, key) = gale_pack.pop_rle(key, GALE_RSA_MODULUS_LEN)
  privkey.rsa.n = openssl.bn.bin2bn(modulus)
  (pubexp, key) = gale_pack.pop_rle(key, GALE_RSA_MODULUS_LEN)
  privkey.rsa.e = openssl.bn.bin2bn(pubexp)
  (exp, key) = gale_pack.pop_rle(key, GALE_RSA_MODULUS_LEN)
  privkey.rsa.d = openssl.bn.bin2bn(exp)
  (prime, key) = gale_pack.pop_rle(key, GALE_RSA_PRIME_LEN*2)
  privkey.rsa.p = openssl.bn.bin2bn(prime[:GALE_RSA_PRIME_LEN])
  privkey.rsa.q = openssl.bn.bin2bn(prime[GALE_RSA_PRIME_LEN])
  (primeexp, key) = gale_pack.pop_rle(key, GALE_RSA_PRIME_LEN*2)
  privkey.rsa.dmp1 = openssl.bn.bin2bn(primeexp[:GALE_RSA_PRIME_LEN])
  privkey.rsa.dmq1 = openssl.bn.bin2bn(prime[GALE_RSA_PRIME_LEN:])
  (coef, key) = gale_pack.pop_rle(key, GALE_RSA_PRIME_LEN)
  privkey.rsa.iqmp = openssl.bn.bin2bn(coef)
  return privkey

def import_privkey(key):
  # _ga_import_priv
  (magic, key) = gale_pack.pop_data(key, len(PRIVATE_MAGIC))
  if PRIVATE_MAGIC == magic:
    version = 1
    (keyname, key) = gale_pack.pop_nulltermstr(key)
  elif PRIVATE_MAGIC2 == magic:
    version = 2
    (keyname, key) = gale_pack.pop_lenstr(key, chars=1)
  elif PRIVATE_MAGIC3 == magic:
    (subversion, key) = gale_pack.pop_data(key, len(SUBVERSION))
    if SUBVERSION == subversion:
      version = 3
    else:
      pygale.call_error_handler('Unsupported version 3 key format')
      return None
    (keyname, key) = gale_pack.pop_lenstr(key, chars=1)
  else:
    pygale.call_error_handler('invalid private key format')
    return None

  if version == 3:
    privkey = import_v3_privkey(key)
  else:
    privkey = import_v1or2_privkey(key)

  if privkey is None:
    return None
  
  if not KeyCache.has_key(keyname):
    keyobj = sign.Key(keyname)
    keyobj.setprivate(privkey)
    add_to_memory_cache(keyobj)
  else:
    keyobj = KeyCache.get(keyname)
    keyobj.setprivate(privkey)

  return keyobj

# Recipients is a list of either string key names (e.g.,
# "bull@test.yammer.net") or Key objects
def have_a_privkey(recipients):
  """Return 1 iff I have at least one of the private keys in this
  list of ids"""
  for recp in recipients:
    if isinstance(recp, sign.Key):
      keyobj = recp
      keyname = keyobj.name()
    else:
      keyobj = get_key(recp)
      keyname = recp
    if keyobj and keyobj.private():
      return 1
    else:
      keyobj = find_privkey_fromdisk(keyname)
      if keyobj and keyobj.private():
        return 1
  return 0
# ----------------------------------------------------------------------

# Copy a public key into the in-memory cache if one can be found in
# the key path.
# Return the name of the key if found, None otherwise
def find_pubkey_fromdisk(keyobj, callback):
  name = keyobj.name()
  revname = sign.flip_local_key_part(name)
  if DEBUG:
    pygale.call_debug_handler('finding pubkey from disk cache: %s' % name)
  # Look first for modern-style .gpub keys, then for legacy extensionless
  # ones.
  for ext in '.gpub', '':
    for prefix, suffix, trust in GPUBKEYPATH:
      kpath= os.path.join(prefix, suffix, name + ext)
      if isinstance(kpath, UnicodeType):
        kpath= kpath.encode('utf8')
      if DEBUG >= 2:
        pygale.call_debug_handler('authcache: checking %s' % kpath)
      if os.path.exists(kpath):
        if DEBUG:
          pygale.call_debug_handler('found key at %s' % kpath)
        f = open(kpath, 'rb')
        keydata = f.read()
        f.close()
        keyobj.setdata(keydata)
        sign.import_pubkey(keyobj,
          lambda k, cb=callback: cache_key_cb(k, cb), trust)
        return
  # Otherwise, we didn't find it; return None
  keyobj.setpublic(None)
  callback(keyobj)
  return

def cache_key_cb(keyobj, callback):
  # Save it to in-memory cache
  if keyobj.data():
    if DEBUG:
      pygale.call_debug_handler('caching key to memory: %s' % keyobj)
    KeyCache.add_to_memory_cache(keyobj)
  callback(keyobj)

def find_privkey_fromdisk(name):
  """
  Find a private key on disk.  Return the key object, or None if not found.

  >>> find_privkey_fromdisk('court@test.yammer.net')
  Key <court@test.yammer.net> private

  """
  # look for gpri first, then look for the old school keys
  for ext in '.gpri', '':
    for prefix, suffix in PRIVKEYPATH:
      path = os.path.join(prefix, suffix, name + ext)
      if os.path.exists(path):
        return import_privkey(open(path, 'rb').read())

def save_pubkey_todisk(keyobj):
  """Save public key bits to disk; also save copy in in-memory
  cache"""
  if keyobj.data() is None:
    if DEBUG:
      pygale.call_debug_handler('Got empty public key to save to disk!')
    return
  # First store it in the in-memory cache
  KeyCache.add_to_memory_cache(keyobj)
  if DEBUG:
    pygale.call_debug_handler('save_pubkey_todisk(%s)' % keyobj.name())
  # Save it to a file
  tempfile.tempdir = CACHE_PATH
  tmpfile = tempfile.mktemp()
  # Add '.gpub' on to the name of the key
  gpubname = keyobj.name() + '.gpub'
  keypath = os.path.join(CACHE_PATH, gpubname)
  # Don't bother overwriting the old (non-.gpub) key
  if os.path.exists(keypath):
    pygale.call_update_handler('overwriting old '+
      'public key %s with a new one' % keyobj.name())
  try:
    f = open(tmpfile, 'wb')
    f.write(keyobj.data())
    f.close()
    # Fix for win32: rename won't overwrite an existing file
    if sys.platform == 'win32':
      if os.path.exists(keypath):
        os.unlink(keypath)
    os.rename(tmpfile, keypath)
  except IOError, e:
    pygale.call_update_handler(
      'Error saving key to cache: ' + str(e))

# Find all of the public key bits for the Key objects in this list.
# The callback will be called with a list of Key objects.
def find_pubkey_list(keyobjs, callback, do_akd=1):
  if DEBUG:
    pygale.call_debug_handler('Finding all pubkeys in list: %s' % keyobjs)
  c = Collector(map(lambda x: x.name(), keyobjs))
  for key in keyobjs:
    if DEBUG > 1:
      pygale.call_debug_handler('Finding pubkey %s' % key.name())
    find_pubkey(key, lambda key, c=c, cb=callback:
      _collector_callback(key, c, cb), do_akd=do_akd)

def _collector_callback(key, collector, callback):
  if DEBUG > 1:
    pygale.call_debug_handler('collector_callback_all, key.name: %s' %
      key.name())
  collector.setoutput(key.name(), key)
  if collector.done():
    if DEBUG > 1:
      pygale.call_debug_handler('collector_callback_all, done!')
    # Call back with the response
    callback(collector.getvalues())

# Find any one of the public key bits for the keys on this list.
def find_pubkey_any(keyobjs, callback, do_akd=1):
  "Find any of the keys on this list"
  if DEBUG:
    pygale.call_debug_handler('Finding any pubkey in list: %s' % keyobjs)
  c = AnyCollector(map(lambda x: x.name(), keyobjs))
  for key in keyobjs:
    # TODO: this may break for redirected keys
    find_pubkey(key, lambda key, c=c, cb=callback:
      _collector_callback_any(key, c, cb), do_akd=do_akd)

def _collector_callback_any(key, collector, callback):
  if DEBUG > 1:
    pygale.call_debug_handler('collector_callback_any, key.name: %s' %
      key.name())
# if key.public() is None and not key.members():
  if not key.verified():
    if DEBUG > 1:
      pygale.call_debug_handler(
        'collector_callback_any: key %s is not verified' %\
        key.name())
    key.setpublic(None)
  collector.setoutput(key.name(), key)
  if collector.done():
    retval = collector.getvalue()
    if DEBUG > 1:
      pygale.call_debug_handler(
        'collector_callback_any, done! calling cb with %s %s' % (
        retval, callback))
    # Call back with the first response
    callback(retval)

# Given a key object, attempt to acquire its public key bits.  If
# do_akd is true, then we will attempt to use Automatic Key
# Distribution to fetch the key.
# The callback expects one argument, the Key object (I think)
def find_pubkey(keyobj, callback, do_akd=1):
#   if DEBUG: print 'Find_pubkey: %s (%s)' % (`keyobj`, keyobj.name())
  if DEBUG:
    pygale.call_debug_handler('Find_pubkey (%s), cb: %s' % (
      keyobj.name(), callback))
  keyobj.setpublic(None)
  # First check our memory cache
  if KeyCache.has_key(keyobj.name()) and\
    (KeyCache.get(keyobj.name()).public() or
    KeyCache.get(keyobj.name()).redirect()):
    if DEBUG: pygale.call_debug_handler('Returning key from in-memory cache')
    cached_key = KeyCache.get(keyobj.name())
    callback(cached_key)
    return

  # Go to the disk cache
  find_pubkey_fromdisk(keyobj, lambda k, cb=callback,
    d=do_akd: _find_pubkey2(k, cb, do_akd=d))

# Second part of find_pubkey.  We are called with the result of trying
# to find the key on disk.  If keyobj.public() is None, then we
# couldn't find it on disk; we have to go to the network.
def _find_pubkey2(keyobj, callback, do_akd=1):
  if keyobj.public() is not None:
    # Put it in the in-memory cache
    KeyCache.add_to_memory_cache(keyobj)
    callback(keyobj)
    return

  # Oops, we gotta do AKD
  if do_akd:
    find_pubkey_akd(keyobj, lambda k, cb=callback:
      _find_pubkey3(k, cb))
  else:
    # Can't find it without AKD, oh well
    callback(keyobj)

def _find_pubkey3(key, callback):
  if key.verified():
    # Put it in the in-memory cache
    KeyCache.add_to_memory_cache(key)
    callback(key)
    return
  if DEBUG:
    pygale.call_debug_handler('In _find_pubkey3, calling callback')
  callback(key)

# ----------------------------------------------------------------------
def find_pubkey_akd(*args):
  return apply(KeyCache.find_pubkey_akd, args)
def get_key(name):
  return KeyCache.get_key(name)
def add_to_memory_cache(*args):
  return apply(KeyCache.add_to_memory_cache, args)

def init():
  global KeyCache
  if DEBUG: print 'Initializing keycache'
  KeyCache = KeyCacheClass()

  if not gale_env.has_key('GALE_SYS_DIR'):
    print 'Warning: GALE_SYS_DIR not set; using ""'
  GALE_SYS_DIR = gale_env.get('GALE_SYS_DIR', '')
  global GPUBKEYPATH, KEYPATH, CACHE_PATH, PRIVKEYPATH
  GPUBKEYPATH = [
    (GALE_DIR, os.path.join('auth','trusted'), TRUSTED),
    (GALE_DIR, os.path.join('auth','local'), NORMAL),
    (GALE_DIR, os.path.join('auth','cache'), NORMAL),
    (GALE_SYS_DIR, os.path.join('auth', 'trusted'), TRUSTED),
    (GALE_SYS_DIR, os.path.join('auth', 'local'), NORMAL),
    (GALE_SYS_DIR, os.path.join('auth', 'cache'), NORMAL)]
  KEYPATH = [
    (GALE_DIR, os.path.join('auth','trusted'), TRUSTED),
    (GALE_DIR, os.path.join('auth','local'), NORMAL),
    (GALE_DIR, os.path.join('auth','cache'), NORMAL),
    (GALE_SYS_DIR, os.path.join('auth', 'trusted'), TRUSTED),
    (GALE_SYS_DIR, os.path.join('auth', 'local'), NORMAL),
    (GALE_SYS_DIR, os.path.join('auth', 'cache'), NORMAL)]

  CACHE_PATH = os.path.join(GALE_SYS_DIR, 'auth', 'cache')

  PRIVKEYPATH = [
    (GALE_DIR, os.path.join('auth','private')),
    (GALE_SYS_DIR, os.path.join('auth', 'private'))]


def shutdown():
  global KeyCache
  del KeyCache
