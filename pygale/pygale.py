#!/usr/bin/env python

"""
pygale.py, the King of PyGale Country.


"""

import getopt, sys, os, select, errno, re
import socket, pickle, string, time, traceback, random
import openssl.evp, openssl.rand
import engine, authcache, gale_pack, sign, gale_env, userinfo
from types import *
from gale_const import *
from version import PYGALE_VERSION

def _testInit(td):
  TEST_DOMAIN= 'test.yammer.net'
  init(domain=TEST_DOMAIN)
  authcache.PRIVKEYPATH.append((td, 'private'))
  authcache.GPUBKEYPATH.append((td, 'public', authcache.NORMAL))
  authcache.GPUBKEYPATH.append((td, 'trusted', authcache.TRUSTED))
  os.environ['PYGALE_TEST_DIR']= td


# Enable debugging output
DEBUG_SOCKET = 0x01
DEBUG_KEYS = 0x02
DEBUG_CRYPTO = 0x04
DEBUG_PUFF = 0x08
DEBUG_PROTOCOL = 0x10
DEBUG = 0

PyGaleErr = 'PyGale Error'
PyGaleWarn = 'PyGale Warning'

DEFAULT_GALE_PORT = 11512

# Fragment types
FRAG_TYPE_TEXT = 0
FRAG_TYPE_BINARY = 1
FRAG_TYPE_TIME = 2
FRAG_TYPE_INT = 3
FRAG_TYPE_LIST = 4
# Gale constants
# TODO: check to see which are actually needed in this file
SIG_MAGIC = 'h\023\001\000'
PRIVATE_MAGIC = 'h\023\000\001'
KEY_MAGIC = 'h\023\000\000'
KEY_MAGIC2 = 'h\023\000\002'
PRIVATE_MAGIC2 = 'h\023\000\003'
CIPHER_MAGIC = 'h\023\002\000'
CIPHER_MAGIC2 = 'h\023\002\001'
# Error handling function
ERROR_HANDLER = None
# Update handling function
UPDATE_HANDLER = None
# Debug message handling function
DEBUG_HANDLER = lambda msg: sys.stdout.write(msg + '\n')
# Maximum time (in seconds) before next retry attempt
MAX_RETRY_DELAY = 300
# Delimiter for location parts in the upper level (user-visible) protocol
LOCATION_DELIMITER_UPPER = '.'
# Delimiter for location parts in the lower level (wire) protocol
LOCATION_DELIMITER_LOWER = '/'


def gale_u32_size():
  return 4

def gale_wch_size():
  return 2

class Blocker:
  wait = 1
  val = None
  def done(self):
    self.wait = 0
  def done_setval(self, *args):
    self.wait = 0
    if len(args) == 1:
      self.val = args[0]
    else:
      self.val = args

class Puff:
  def __init__(self, dict=None):
    self.__fragments = gale_pack.GaleFragList()
    if dict is not None:
      self.__fragments.update(dict)
    self.__loc = None
    self.__signer = None
    self.__recipients = []
  
  def set_loc(self, loc):
    self.__loc = loc
  
  def get_loc(self, default=''):
    if self.__loc is None:
      return default
    else:
      return self.__loc

  def get_loc_list(self):
    if self.__loc is None:
      return []
    else:
      return string.split(self.__loc, None)
  
  def get_signer(self, default=''):
    if self.__signer is None:
      return default
    else:
      return self.__signer

  def get_recipients(self):
    return self.__recipients

  def set_recipients(self, ids):
    self.__recipients = ids

  def get(self, fragname, default=None):
    # TODO dangermouse
    # I think this is now obsolete
    print 'Warning: Puff.get() is now obsolete'
    traceback.print_stack()
    ret = self.__fragments[fragname]
    if not ret:
      return default
    else:
      return ret
  
  def set_text(self, name, val):
    self.__fragments.set(name, FRAG_TYPE_TEXT, val)
  def get_text(self, name):
    "Return list of text fragments matching this key name"
    return self.__fragments.get_text(name)
  def get_text_first(self, name, default=None):
    """Return the first text fragment matching this name, default if
    none"""
    ret = self.__fragments.get_text(name)
    if not ret:
      return default
    else:
      return ret[0]
  
  def set_time(self, name, val):
    self.__fragments.set(name, FRAG_TYPE_TIME, val)
  def get_time(self, name):
    "Return list of time fragments matching this key name"
    return self.__fragments.get_time(name)
  def get_time_first(self, name, default=None):
    """Return the first time fragment matching this name, default if
    none"""
    ret = self.__fragments.get_time(name)
    if not ret:
      return default
    else:
      return ret[0]

  def set_int(self, name, val):
    self.__fragments.set(name, FRAG_TYPE_INT, val)
  def get_int(self, name):
    "Return list of int fragments matching this key name"
    return self.__fragments.get_int(name)
  def get_int_first(self, name, default=None):
    """Return the first int fragment matching this name, default if
    none"""
    ret = self.__fragments.get_int(name)
    if not ret:
      return default
    else:
      return ret[0]
  
  def set_binary(self, name, val):
    self.__fragments.set(name, FRAG_TYPE_BINARY, val)
  def get_binary(self, name):
    "Return list of binary fragments matching this key name"
    return self.__fragments.get_binary(name)
  def get_binary_first(self, name, default=None):
    """Return the first binary fragment matching this name, default if
    none"""
    ret = self.__fragments.get_binary(name)
    if not ret:
      return default
    else:
      return ret[0]
  
  def fragments(self):
    return self.__fragments
  
  def __repr__(self):
    return ('[%s] ' % self.__loc) + repr(self.__fragments)
  
  def swizzled(self):
    # Construct puff bits
    loc = self.get_loc()
    if not loc:
      if DEBUG & DEBUG_PUFF:
        call_debug_handler('Swizzled: No category specified!')
      loc = ''
    else:
      loc = escape_location_list(string.split(loc, None))
      if DEBUG & DEBUG_PUFF:
        call_debug_handler('Swizzling category: %s' % `loc`)
    puffbits = gale_pack.push_lenstr(loc, chars=0) +\
      gale_pack.push_int(0)
    if DEBUG & DEBUG_PUFF:
      call_debug_handler('Sending puff with category: %s' % `puffbits`)
    puffbits = puffbits + gale_pack.FragList_to_group(self.fragments())
    if DEBUG & DEBUG_PUFF:
      call_debug_handler('... and with fragments: %s' % `puffbits`)
    if DEBUG & DEBUG_PUFF:
      call_debug_handler('Sending puff, datalen is %s' % len(puffbits))
    return puffbits
  
  # Consruct a signed message fragment
  # signer is the name of the signing key, e.g. "egnor@ofb.net"
  def sign_message(self, signer):
    p = Puff()
    p.__loc = self.__loc
    p.__signer = self.__signer = signer
    p.__recipients = self.__recipients

    # TODO: use the equivalent of gale_user() here
    if DEBUG & DEBUG_PUFF:
      call_debug_handler('Signing message with signer %s' % signer)
    input_data = ''
    input_data = input_data + gale_pack.push_int(0)
    input_data = input_data +\
      gale_pack.FragList_to_group(self.__fragments)

    privkey = authcache.get_key(signer)
    if not (privkey and privkey.private()):
      # If the private key isn't cached, try to find it
      privkey = authcache.find_privkey_fromdisk(signer)
      if not (privkey and privkey.private()):
        call_error_handler('No private key %s to sign with' %
          signer)
        return None

    context = openssl.evp.MD_CTX()
    context.SignInit(openssl.evp.md5())
    context.SignUpdate(input_data)
    sig_data = context.SignFinal(privkey.private())
    if sig_data is None:
      call_error_handler('Failure signing message with key ' + signer)
      return None

    # pack a new fragment
    sig = ''
    sig = SIG_MAGIC + gale_pack.push_int(len(sig_data)) + sig_data +\
      make_stub_pub(signer)
    out = gale_pack.push_int(len(sig)) + sig + input_data

    p.__fragments = gale_pack.GaleFragList()
    p.__fragments.set('security/signature', FRAG_TYPE_BINARY, out)

    return p
  
  # utility function
  def map_recipient_list(self, keyobj):
    if isinstance(keyobj, sign.Key):
      return keyobj
    else:
      return sign.Key(keyobj)
  
  # if callback is None, block and return encrypted Puff instance
  # otherwise, call callback with encrypted Puff instance
  # If encryption cannot be performed (perhaps because an empty
  # list of recipients is passed), return/callback None.
  # If '' is in the recipients list, meaning "no encryption",
  # return/callback None.
  def encrypt_message(self, recipient_list, callback=None):
    if type(recipient_list) is not ListType:
      recipient_list = [recipient_list]
    if callback is None:
      blocker = Blocker()
      cb = lambda p, blocker=blocker: blocker.done_setval(p)
    else:
      cb = callback

    if DEBUG & DEBUG_CRYPTO:
      call_debug_handler('Encrypting message to %s' % recipient_list)
    if not recipient_list or recipient_list == [None] or\
      '' in recipient_list:
      cb(None)
      return
    keyobjlist = map(self.map_recipient_list, recipient_list)
    if DEBUG & DEBUG_CRYPTO:
      call_debug_handler('Encryption keys: %s' % keyobjlist)
    try:
      authcache.find_pubkey_list(keyobjlist,
        lambda l, cb=cb, s=self: s.encrypt_message2(l, cb))
    except PyGaleErr, e:
      call_error_handler(e)
      cb(None)
      return

    if callback is None:
      while blocker.wait:
        engine.engine.process()
      return blocker.val
  
  def encrypt_message2(self, recipient_keys, callback):
    keynames = map(lambda x: x.name(), recipient_keys)
    if DEBUG & DEBUG_CRYPTO:
      call_debug_handler('encrypt_message2: keys %s' % keynames)
    for key in recipient_keys:
      if DEBUG & DEBUG_CRYPTO:
        call_debug_handler('em2: processing key %s' % key)
      if key.public() is None:
        if DEBUG & DEBUG_CRYPTO:
          call_debug_handler('em2: no key', key)
        call_error_handler('no public key (%s) to encrypt with' %\
          key.name())
        callback(None)
        if DEBUG & DEBUG_CRYPTO:
          call_debug_handler('em2: returning')
        return

    # Now do the sealing
    if DEBUG & DEBUG_CRYPTO:
      call_debug_handler('encrypt_message2 context')
    context = openssl.evp.CIPHER_CTX()
    keys = map(lambda x: x.public(), recipient_keys)
    (iv, ekeys) = context.SealInit(openssl.evp.des_ede3_cbc(), keys)

    if DEBUG & DEBUG_CRYPTO:
      call_debug_handler('encrypt_message2 top')
    plain_data = gale_pack.push_int(0) + gale_pack.FragList_to_group(
      self.__fragments)
    n = len(CIPHER_MAGIC2) + len(iv) + gale_u32_size() + len(plain_data)
    num = len(ekeys)
    for i in range(num):
      n = n + (gale_u32_size() + (len(recipient_keys[i].name()) *
        gale_wch_size()))
      n = n + len(ekeys[i]) + gale_u32_size()

    if DEBUG & DEBUG_CRYPTO:
      call_debug_handler('iv is %i bytes' % len(iv))
      call_debug_handler('encoding %i keys' % num)
    cipher = CIPHER_MAGIC2 + iv[:8] + gale_pack.push_int(num)
    for i in range(num):
      cipher = cipher + gale_pack.push_lenstr(
        sign.flip_local_key_part(recipient_keys[i].name()))
      cipher = cipher + gale_pack.push_int(len(ekeys[i]))
      cipher = cipher + ekeys[i]

    if DEBUG & DEBUG_CRYPTO:
      call_debug_handler('encrypt_message2 middle')
    enc_data = context.SealUpdate(plain_data)
    if enc_data is None:
      call_error_handler('SealUpdate failed')
      callback(None)
      return

    cipher = cipher + enc_data
    enc_data = context.SealFinal()
    if enc_data is None:
      call_error_handler('SealFinal failed')
      callback(None)
      return
    cipher = cipher + enc_data

    if DEBUG & DEBUG_CRYPTO:
      call_debug_handler('encrypt_message2 constructing new puff')
    p = Puff()
    p.__loc = self.__loc
    p.__signer = self.__signer
    p.__recipients = self.__recipients = map(lambda x: x.name(),
      recipient_keys)
    p.__fragments = gale_pack.GaleFragList()
    p.__fragments.set('security/encryption', FRAG_TYPE_BINARY, cipher)
    if DEBUG & DEBUG_CRYPTO:
      call_debug_handler('calling callback from encrypt_message2')
    callback(p)

  def verify(self, callback):
    if not self.__fragments.has_key('security/signature'):
      if DEBUG & DEBUG_CRYPTO:
        call_debug_handler(
          'Verify: puff to %s is unsigned' % self.__loc)
      # How to indicate unsigned puff?
      self.__signer = '*unsigned*'
      callback(self)
      return self

    p = Puff()
    p.__loc = self.__loc
    p.__signer = None
    p.__recipients = self.__recipients

    # Pull out only the first security/signature fragment
    if DEBUG & DEBUG_CRYPTO:
      call_debug_handler('Verify: puff to %s is signed' % self.__loc)
    frag = self.__fragments.get_binary_first('security/signature')
    (sig_len, frag) = gale_pack.pop_int(frag)
    (sig, frag) = gale_pack.pop_data(frag, sig_len)
    p.__fragments.update(gale_pack.group_to_FragList(frag))
    sign.decode_sig(sig, frag, lambda key, s=self, p=p, c=callback:
      s.decode_done(key, p, c))
    return p

  def decode_done(self, key, puff, callback):
    if key.public() is None:
      signer = '*unverified*'
    else:
      signer = key.name()
    if DEBUG & DEBUG_CRYPTO: 'Verify done: %s' % (signer)
    puff.__signer = signer
    callback(puff)
  
  def decrypt(self):
    if not self.__fragments.has_key('security/encryption'):
      self.__recipients = []
      return self

    p = Puff()
    p.__loc = self.__loc
    p.__signer = self.__signer
    p.__recipients = self.__recipients

    # Hack: pull out only the first security/encryption fragment
    frag = self.__fragments.get_binary_first('security/encryption')
    encr_id, plain_msg, frag = self.__decrypt_msg(frag)
    p.__recipients = encr_id
    p.__fragments.update(gale_pack.group_to_FragList(plain_msg))
    return p

  def __decrypt_msg(self, cipher):
    if DEBUG & DEBUG_CRYPTO:
      call_debug_handler('Decrypting message...')
    # init variables
    plain_msg = None

    # auth_decrypt
    (magic, cipher) = gale_pack.pop_data(cipher, len(CIPHER_MAGIC))
    if DEBUG & DEBUG_CRYPTO:
      call_debug_handler('Magic is: %s' % `magic`)
    if magic == CIPHER_MAGIC:
      version = 1
    elif magic == CIPHER_MAGIC2:
      version = 2
    else:
      raise PyGaleWarn, 'Invalid encryption magic'

    # constant length 8 byte "iv" data
    (iv, cipher) = gale_pack.pop_data(cipher, 8)
    keycountorig = cipher[:4]
    (keycount, cipher) = gale_pack.pop_int(cipher)
    if keycount != 1:
      if DEBUG & DEBUG_CRYPTO:
        call_debug_handler('Found keycount: %s (orig %s)' %
          (keycount, `keycountorig`))

    found_key = 0
    ekeynames = []
    for i in range(keycount):
      if version == 1:
        (keyname, cipher) = gale_pack.pop_nulltermstr(cipher)
      else:
        (keyname, cipher) = gale_pack.pop_lenstr(cipher, chars=1)
      # Backwards compat: wire protocol has local parts in reverse
      # order
      keyname = sign.flip_local_key_part(keyname)
      (keylen, cipher) = gale_pack.pop_int(cipher)
      (keydata, cipher) = gale_pack.pop_data(cipher, keylen)
      if DEBUG & DEBUG_CRYPTO:
        call_debug_handler('Found key name: %s' % keyname)
      ekeynames.append(keyname)
      if keylen > GALE_ENCRYPTED_KEY_LEN or\
        len(keydata) < keylen:
        raise PyGaleWarn, 'Invalid encrypted key length'
      # If we already found a working private key, no need to find
      # another one
      if found_key: continue

      private_key = authcache.get_key(keyname)
      if not (private_key and private_key.private()):
        # We don't have the private key cached;
        # try to import it from disk
        private_key = authcache.find_privkey_fromdisk(keyname)

      if (private_key and private_key.private()):
        # Now, if we have a private key, we can decrypt
        ekey = keydata
        ekeylen = keylen
        
        # Test if this key works
        env = openssl.evp.CIPHER_CTX()
        ret = env.OpenInit(openssl.evp.des_ede3_cbc(), ekey,
          iv, private_key.private())
        if ret != 0:
          # Success
          found_key = 1

    if not found_key:
      # If we haven't found any private key that works
      # No private key found to decrypt this message
      raise PyGaleWarn, "No private key(s) to decrypt puff " +\
        "on category %s" % self.get_loc()

    unencrypted_data = env.OpenUpdate(cipher)
    if unencrypted_data is None:
      raise PyGaleWarn, 'OpenUpdate failed'
    plain_msg = unencrypted_data
    unencrypted_data = env.OpenFinal()
    if unencrypted_data is None:
      raise PyGaleWarn, 'OpenFinal failed'
    plain_msg = plain_msg + unencrypted_data

    if DEBUG & DEBUG_CRYPTO:
      call_debug_handler(
      'Decryption succeeded, encrypted to: %s' % ekeynames)
    return (ekeynames, plain_msg, '')

# ----------------------------------------------------------------------
# Random numbers

def _initrandunix():
  data = str(time.time())
  pid = data + str(os.getpid())
  pgroup = data + str(os.getpgrp())
  results = data + str(os.stat('/'))
  rand_file = open("/dev/urandom", 'r')
  data = data + rand_file.read(16)
  data = data + str(time.time())
  openssl.rand.seed(data)

def _initrandwin():
  openssl.rand.screen()

def initrand():
  if sys.platform == 'win32':
    _initrandwin()
  else:
    _initrandunix()

#def getrandom():
# return openssl.rand.bytes(16)
# ----------------------------------------------------------------------

def make_stub_pub(signer):
  # Backwards compat: flip local part of key name for wire protocol
  return KEY_MAGIC2 + gale_pack.push_lenstr(
    sign.flip_local_key_part(signer))

class GaleClient:
  def __init__(self, hostname=None, retry=1):
    if hostname is None:
      # Default connections
      proxy = gale_env.get('GALE_PROXY', None)
      if proxy is not None:
        self._hosts = re.split('[, ]+', proxy)
      else:
        domain = gale_env.get('GALE_DOMAIN')
        if domain is None:
          print 'GaleClient initialization error: unable ' +\
            'to determine GALE_DOMAIN'
          self._hosts = []
        else:
          self._hosts = [domain, 'gale.' + domain,
            domain + '.gale.org']
    else:
      self._hosts = [hostname]
    self._retry = retry   # whether to automatically reconnect
    self._sock = None
    self._buffer = ''
    self._puff_callback = None
    self._verify_callback = None
    self._on_connect = None
    self._on_disconnect = None
    self._puffs = []
    self._engine = engine.engine
    self.__sockets_in_progress = []
    self.__connected = 0
    self._retry_delay = 1 # how many seconds before this retry

  def __del__(self):
    if DEBUG & DEBUG_SOCKET:
      call_debug_handler('GaleClient.__del__: Client dying')
    if self._puff_callback:
      self._engine.del_callback(self._sock)

  def set_onconnect(self, cb):
    self._on_connect = cb
  
  def set_ondisconnect(self, cb):
    self._on_disconnect = cb
  
  def socket(self):
    return self._sock
  
  # The callback will be called with a hostname, or with None if connect
  # failed
  # if the callback is None, block until connected, and return hostname
  # or None
  def connect(self, callback = None):
    if DEBUG & DEBUG_SOCKET:
      call_debug_handler('starting connect')
    if callback is None:
      blocker = Blocker()
      cb = lambda h, b=blocker: b.done_setval(h)
    else:
      cb = callback

    self.__connected = 0
    self.__sockets_in_progress = []
    for hostport in self._hosts:
      if ':' in hostport:
        index = string.index(hostport, ':')
        portstr = hostport[index+1:]
        try:
          port = int(portstr)
        except ValueError:
          call_error_handler(
            'Error parsing server string: %s' % hostport)
          port = DEFAULT_GALE_PORT
        host = hostport[:index]
      else:
        host = hostport
        port = DEFAULT_GALE_PORT
      sock = socket.socket(socket.AF_INET,
        socket.SOCK_STREAM)
      sock.setblocking(0)
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
      self.__sockets_in_progress.append(sock)
      self._engine.add_write_callback(sock, lambda self=self,
        s=sock, h=hostport, cb=cb: self.connect2(s, h, cb))
      if DEBUG & DEBUG_SOCKET:
        call_debug_handler('Connecting to %s' % hostport)
      try:
        sock.connect((host, port))
      except socket.error, e:
        if e[0] == errno.EINPROGRESS or e[0] == 10035:
          if DEBUG & DEBUG_SOCKET:
            call_debug_handler('Connect in progress to %s'
              % host)
          continue
        else:
          if DEBUG & DEBUG_SOCKET:
            call_debug_handler('Connect failed to %s' % host)
          self._engine.del_write_callback(sock)
          self.__sockets_in_progress.remove(sock)
          continue
      # Connected immediately
      self.connect2(sock, hostport, cb)

    # Check once after all hosts have been processed
    if not self.__sockets_in_progress:
      cb(None)
      return

    if callback is None:
      while blocker.wait:
        engine.engine.process()
      return blocker.val
  
  def connect2(self, sock, host, callback):
    if DEBUG & DEBUG_SOCKET:
      call_debug_handler('in connect2, host: %s' % host)
    self._engine.del_write_callback(sock)
    if self.__connected:
      # Someone else already connected
      if DEBUG & DEBUG_SOCKET:
        call_debug_handler('already connected to a server')
      if sock in self.__sockets_in_progress:
        self.__sockets_in_progress.remove(sock)
      return

    # I suspect this block isn't necessary
    r, w, e = select.select([], [sock], [], 0)
    if sock not in w:
      # Something weird's going on
      call_error_handler('Weirdness connecting to %s' % host)
      if sock in self.__sockets_in_progress:
        self.__sockets_in_progress.remove(sock)
      if not self.__sockets_in_progress:
        call_error_handler(
          'Error: unable to connect to any server')
        callback(None)
      return

    # Check for error
    if DEBUG & DEBUG_SOCKET:
      call_debug_handler('checking socket options')
    if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) != 0:
      # unsuccessful
      if DEBUG & DEBUG_SOCKET:
        call_debug_handler(
          'socket options indicate error connecting' +\
          ' to ' + host)
      if sock in self.__sockets_in_progress:
        self.__sockets_in_progress.remove(sock)
      if not self.__sockets_in_progress:
        call_update_handler(
          'Error: unable to connect to any server')
        callback(None)
      return

    # Otherwise, we're connected
    if DEBUG & DEBUG_SOCKET:
      call_debug_handler('it seems we are connected')
    try:
      # Send our version string
      sock.send(gale_pack.pack32bit(1))
    except socket.error, e:
      call_error_handler('Error sending version string to %s: %s'
        % (host, str(e)))
      self.__sockets_in_progress.remove(sock)
      if not self.__sockets_in_progress:
        callback(None)
      return

    self._engine.add_callback(sock, lambda self=self, s=sock, h=host,
      cb=callback: self.connect3(s, h, '', cb))

  # Hmm, shouldn't this possibly fail in some way?
  def connect3(self, sock, host, buf, callback):
    if DEBUG & DEBUG_SOCKET:
      call_debug_handler('in connect3, host %s' % host)
    self._engine.del_callback(sock)
    if self.__connected:
      if DEBUG & DEBUG_SOCKET:
        call_debug_handler('already connected, host: %s' % host)
      self.__sockets_in_progress.remove(sock)
      return
    try:
      r = sock.recv(1024)
    except socket.error:
      # It's possible to get a "connection reset" error here
      # Can't connect to server
      if sock in self.__sockets_in_progress:
        self.__sockets_in_progress.remove(sock)
      return

    r = buf + r
    if len(r) >= 4:
      # We got the handshake
      server_version = gale_pack.unpack32bit(r[:4])
      if DEBUG & DEBUG_SOCKET:
        call_debug_handler('Server version is %s' % server_version)
      self._buffer = r[4:]
      self.__connected = 1
      self._sock = sock
      callback(host)
      if self._on_connect is not None:
        self._on_connect(host)
    else:
      self._engine.add_callback(sock, lambda self=self, s=sock,
        h=host, b=r, cb=callback: self.connect3(s, h, b, cb))
  
  # Attempt to reconnect to server
  def retry(self):
    self._retry_delay = 1
    self.continue_retry()
  
  def continue_retry(self):
    call_update_handler('Retrying server connection')
    if DEBUG & DEBUG_SOCKET:
      call_debug_handler('Calling connect from continue_retry')
    self.connect(self.retry_done)

  def retry_done(self, host):
    if DEBUG & DEBUG_SOCKET:
      call_debug_handler('In retry_done, host: %s' % host)
    if host is None:
      # Retry failed
      if self._retry_delay == 1:
        wait = 1
      else:
        wait = random.randint(1, self._retry_delay)
      self._retry_delay = self._retry_delay + wait
      if self._retry_delay > MAX_RETRY_DELAY:
        self._retry_delay = self._retry_delay / 2
      call_error_handler('Retry failed; waiting %i seconds' %
        self._retry_delay)
      self._engine.add_timeout(self._retry_delay * 1000,
        self.continue_retry)
      return
    call_update_handler('Reconnected to server at %s' % host)
    if self._puff_callback is not None:
      self._engine.add_callback(self._sock, self.handle_read)

  # Subscribe to a list of locations.  If list is empty, subscribe to
  # nothing ("-").
  # if callback is None, block until subscribed and return
  # Return value is a 2-tuple.  First element of tuple is a list of "bad
  # locations" that cannot be found; second is list of good locations.
  def sub_to(self, loc_list, callback=None, locadd=None):
    if DEBUG & DEBUG_SOCKET:
      call_debug_handler('in sub_to, callback is %s' % callback)
    assert type(loc_list) is ListType
    if callback is None:
      blocker = Blocker()
      cb = lambda badlocs, goodlocs, blocker=blocker:\
        blocker.done_setval(badlocs, goodlocs)
    else:
      cb = callback
    
    # Look up keys for locations in list
    lookup_all_locations(loc_list, lambda l, s=self, cb=cb:
      s.sub_to2(l, cb, locadd=locadd))
  
    if callback is None:
      while blocker.wait:
        engine.engine.process()
      return blocker.val
  
  def sub_to2(self, loc_key_list, callback, locadd=None):
    if DEBUG & DEBUG_SOCKET:
      call_debug_handler('sub2, loc_key_list: %s' % loc_key_list)
    bad_locs = []
    locs = []
    for (loc, keylist) in loc_key_list:
      if keylist is None:
        # loc is INVALID
        call_error_handler(
          'location %s is invalid; not subscribing' % loc)
        bad_locs.append(loc)
        continue
      # otherwise, it's a valid location
      locs.append(loc)
      if loc[0] != '-':
        if '' not in keylist and not\
          authcache.have_a_privkey(keylist):
        # must look up all private keys in recipients list
          call_error_handler(('location %s is unauthorized; ' %
            loc) + 'subscribing anyway')

    if locadd:
      locs.extend(locadd)
    if not locs:
      # Subscribe to nothing
      category = '-'
    else:
      category = escape_location_list(locs)
    if DEBUG & DEBUG_SOCKET:
      call_debug_handler('sub_to2: category %s' % category)

    self._category = category
    req = gale_pack.pack32bit(2)
    ucat = gale_pack.push_string(category)
    req = req + gale_pack.pack32bit(len(ucat))
    req = req + ucat
    if self._sock is None:
      raise PyGaleErr, 'Error subscribing: dead server connection'
    else:
      self._sock.send(req)
    if DEBUG & DEBUG_SOCKET:
      call_debug_handler('Subscribed to: %s' % category)
    callback(bad_locs, locs)

  def swizzle_puff(self, p, will=0):
    if will:
      opcode = gale_pack.push_int(1)
    else:
      opcode = gale_pack.push_int(0)
    puffbits = p.swizzled()
    req = opcode + gale_pack.push_int(len(puffbits)) + puffbits
    return req

  def transmit_puff(self, p, will=0):
    bits = self.swizzle_puff(p, will)
    # construct server request
    if DEBUG & DEBUG_PUFF:
      call_debug_handler('Sending puff: %s' % `bits`)
    if self._sock is None:
      raise PyGaleErr, 'Error sending puff: dead socket!'
    try:
      self._sock.send(bits)
    except socket.error, e:
      if e[0] == errno.EPIPE:
        raise PyGaleErr, 'Error sending puff: connection closed'
      else:
        raise PyGaleErr, 'Error sending puff: %s' % e[1]

  def set_puff_callback(self, callback):
    if not self._sock:
      raise PyGaleErr, 'Unable to set callback when not connected'
    self._puff_callback = callback
    self._engine.add_callback(self._sock, self.handle_read)

  def set_verify_callback(self, callback):
    self._verify_callback = callback

  def del_puff_callback(self):
    self._del_puff_callback()
    if self._puff_callback:
      self._puff_callback = None

  # remove puff cb but remember what it used to be
  def _del_puff_callback(self):
    if self._puff_callback:
      self._engine.del_callback(self._sock)

  def disconnect(self):
    self._del_puff_callback()
    self._sock.close()
    if self._on_disconnect is not None:
      self._on_disconnect()

  def handle_read(self):
    try:
      r = self._sock.recv(1024)
    except socket.error, e:
      call_error_handler('Server died: %s' % str(e))
      self.disconnect()
      if self._retry:
        # Wait two seconds, then retry
        self._engine.add_timeout(2000, self.retry)
      return None
    if r == '':
      call_error_handler('Server closed connection (read)')
      self.disconnect()
      if self._retry:
        # Wait two seconds, then retry
        self._engine.add_timeout(2000, self.retry)
      return None
    self._buffer = self._buffer + r
    while len(self._buffer) > 8:
      opcode = gale_pack.unpack32bit(self._buffer[0:4])
      datalen = gale_pack.unpack32bit(self._buffer[4:8])
      if len(self._buffer) - 8 < datalen:
        break

      self._buffer = self._buffer[8:]
      puffdata = self._buffer[:datalen]
      self._buffer = self._buffer[datalen:]
      if DEBUG & DEBUG_PUFF:
        call_debug_handler('Read puff from wire, len %s' % datalen)
      if opcode == 0:
        try:
          self._puffs.append(self.process_puff(puffdata))
        except PyGaleWarn, e:
          if ERROR_HANDLER:
            ERROR_HANDLER(e)
        except:
          if ERROR_HANDLER:
            ERROR_HANDLER(
              'Error processing puff (check console)')
          traceback.print_exc()
      elif opcode == 1:
        # We should never get wills
        print "Wills not handled"
      elif opcode == 2:
        print "Gimme not handled"


  # Non-blocking call to get next puffs queued
  def next_puffs(self):
    puffs = []
    self.set_puff_callback(lambda p, puffs=puffs: puffs.append(p))
    self._engine.process(0)
    return puffs

  # Read from socket forever, calling handler(Puff: p) whenever we
  # receive a complete puff
  def next(self):
    while 1:
      self._engine.process()

  def process_puff(self, p):
    if DEBUG & DEBUG_PUFF:
      call_debug_handler('Processing puff: %s' % `p`)
    (loc, p) = gale_pack.pop_lenstr(p)
    loc = unescape_location_string(loc)
    if DEBUG & DEBUG_PUFF:
      call_debug_handler('Processing puff, category: %s' % `loc`)

    # Fragment list
    p = Puff(gale_pack.group_to_FragList(p))
    p.set_loc(loc)
    p = p.decrypt()
    if self._verify_callback:
      if DEBUG & DEBUG_PUFF:
        call_debug_handler('Process: Verifying puff to %s' % loc)
      p = p.verify(lambda p, s=self: s._verify_callback(p))
    elif self._puff_callback:
      if DEBUG & DEBUG_PUFF:
        call_debug_handler(
          'Processing: calling puff cb wrapper %s' % loc)
      p = p.verify(self._puff_callback_wrapper)
    else:
      print 'Yikes! no verify or puff callback registered!'
    # If you don't tell us you want to be notified of verification
    # we will not call your puff callback until verification is done.
    # (tlau) There seems like there could be a race condition here if
    # self._verify_callback is changed while the puff is being
    # verified.  Perhaps the verify callback (above) ought to take
    # one function if verify_callback is now set, and a different one
    # if it isn't?  That way the callbacks are called as is
    # appropriate for the setting at the time the puff arrives.
    # In particular, if self._verify_callback is removed during the
    # verify operation, it could result in puff_callback being called
    # twice on the same puff.
    #p = p.verify(lambda p, s=self: s.verify_done(p))
    # I think I fixed this above, though it ought to be tested.
    if self._verify_callback:
      if self._puff_callback:
        self._puff_callback(p)
      else:
        print 'Yikes! no puff callback registered!'

  def _puff_callback_wrapper(self, p):
    if self._puff_callback is not None:
      self._puff_callback(p)
    else:
      traceback.print_stack
      print 'ERROR: puff callback is None, puff loc:', p.get_loc()

# ----------------------------------------------------------------------
# Misc utility functions

# Return an id/instance string
def getinstance():
  import socket
  dom = gale_env.get('GALE_DOMAIN', 'GALE_DOMAIN_UNSET')
  host = socket.gethostname()
  user = userinfo.login_name
  if sys.platform == 'win32':
    display = 'Windows'
  else:
    display = gale_env.get('DISPLAY', None)
    if display is None:
      try:
        display = os.ttyname(sys.stdin.fileno())
      except:
        display = 'UNKNOWN_DISPLAY'
  pid = str(os.getpid())
  return '%(dom)s/%(host)s/%(user)s/%(display)s/%(pid)s' % locals()

def gale_user():
  # Find the current user
  if gale_env.has_key('GALE_ID'):
    return gale_env.get('GALE_ID')
  else:
    gdomain = gale_env.get('GALE_DOMAIN', 'GALE_DOMAIN_UNSET')
    guser = userinfo.login_name
    return '%s@%s' % (guser, gdomain)

def gale_domain():
  return gale_env.get('GALE_DOMAIN', 'GALE_DOMAIN_UNSET')

# used for backwards compatibility in Fugu receipt requests
def id_category(name, midstr='', postfix=''):
  i = string.find(name, '@')
  username = name[:i]
  domain = name[i+1:]
  return '@%s/%s/%s/%s' % (domain, midstr, username, postfix)

# ----------------------------------------------------------------------
# Look up a single ID/key

# Calls callback with a key object
#def lookup_id(name, callback = None):
# """Name should be the string representing the name to be looked up"""
# if not '@' in name:
#   print 'ERROR: lookup_id must be called with fully-qualified id'
#   traceback.print_stack()
#   name = name + '@' + gale_domain()
# 
# if callback is None:
#   blocker = Blocker()
#   cb = lambda k, blocker=blocker: blocker.done_setval(k)
# else:
#   cb = callback
# keyobj = sign.Key(name)
# try:
#   authcache.find_pubkey(keyobj, lambda k, c=cb: c(k))
# except PyGaleErr, e:
#   call_error_handler(e)
#   cb(None)
#   return
#   
# if callback is None:
#   while blocker.wait:
#     engine.engine.process(authcache.AKD_TIMEOUT)
#   return blocker.val

# Look up a list of names (e.g., "bull@test.yammer.net") and return a list of
# Key objects.  If all=0, return as soon as you find any one of the
# ids otherwise, return only with all ids.
# If do_akd is 0, do not do AKD to find these keys.
#
# 6/30/04: this will also process key.redirect fields in those keys.
#
# Calls callback with (key name, list of Key objects).  If callback is
# None, block until the answer is obtained and then return the list of
# Key objects.
def lookup_ids(names, callback=None, all=3, do_akd=1):
  canonical_names = []
  for name in names:
    # Canonicalize the domain if it's not fully qualified
    if '@' not in name:
      gdomain = gale_env.get('GALE_DOMAIN', 'GALE_DOMAIN_UNSET')
      name = name + '@' + gdomain
      canonical_names.append(name)
    else:
      canonical_names.append(name)
  if callback is None:
    blocker = Blocker()
    cb = lambda name, keylist, blocker=blocker:\
      blocker.done_setval(keylist)
  else:
    cb = callback
  keyobjs = map(sign.Key, canonical_names)
  if DEBUG & DEBUG_PROTOCOL:
    call_debug_handler('lookup_ids: %s %s' % (canonical_names, keyobjs))
  if all:
    authcache.find_pubkey_list(keyobjs, lambda keylist, c=cb:
      lookup_ids_done(keylist, c, do_akd), do_akd=do_akd)
  else:
    authcache.find_pubkey_any(keyobjs, lambda keyobj, c=cb:
      lookup_ids_done([keyobj], c, do_akd), do_akd=do_akd)
  
  if callback is None:
    while blocker.wait:
      engine.engine.process(authcache.AKD_TIMEOUT)
    return blocker.val

# Callback will be called once for each key in the keylist, with two
# arguments (name of key, list of members)
def lookup_ids_done(keylist, callback, do_akd):
  if DEBUG & DEBUG_PROTOCOL:
    call_debug_handler('Lookup_ids_done, looking up redirects')
    call_debug_handler('keylist is: %s' % keylist)
  for key in keylist:
    if key.public() is None:
      callback(key.name(), None)
    else:
      _lookup_location_redirect(key, key.name(), callback, do_akd,
        None)

# ----------------------------------------------------------------------
# Export a public key

def export_pubkey(keyname, callback = None):
  if callback is None:
    blocker = Blocker()
    cb = lambda k, blocker=blocker: blocker.done_setval(k)
  else:
    cb = callback

  # Let's just hope we don't do AKD at this point, OK?
  keyobj = authcache.get_key(keyname)
  if keyobj is None:
    keyobj = sign.Key(keyname)
    authcache.find_pubkey_fromdisk(keyobj, lambda k, c=cb:
      __export_pubkey2(k, c))
  else:
    cb(keyobj.data())
  
  if callback is None:
    while blocker.wait:
      engine.engine.process()
    return blocker.val

def __export_pubkey2(keyobj, callback):
  callback(keyobj.data())

# ----------------------------------------------------------------------
# Alias expansion and default domain appending

def expand_aliases(loc):
  galedir = gale_env.get('GALE_DIR', os.path.join(userinfo.home_dir,
    '.gale'))
  useraliasdir = os.path.join(galedir, 'aliases')
  galesysdir = gale_env.get('GALE_SYS_DIR', '')
  galealiasdir = os.path.join(galesysdir, 'aliases')

  aliases = {}
  for aliasdir in [galealiasdir, useraliasdir]:
    if os.path.exists(aliasdir):
      # read in aliases
      for file in os.listdir(aliasdir):
        path = os.path.join(aliasdir, file)
        if not os.path.islink(path):
          continue
        aliases[file] = os.readlink(path)
  if aliases.has_key(loc):
    return aliases[loc]
  else:
    # For each alias, check for prefix + domain match.
    i = string.find(loc, '@')
    if i == -1:
      locpre = loc
      locdom = ""
    else:
      locpre = loc[:i]
      locdom = loc[i+1:]
    for alias in aliases.keys():
      i = alias.find('@')
      if i == -1:
        aliaspre = alias
        aliasdom = ""
      else:
        aliaspre = alias[:i]
        aliasdom = alias[i+1:]
      if locdom == aliasdom and locpre.startswith(aliaspre):
        if alias.startswith('@'):
          targetpre = ""
          targetdom = aliases[alias]
        else:
          i = aliases[alias].find('@')
          if i == -1:
            targetpre = aliases[alias]
            targetdom = gale_domain()
          else:
            targetpre = aliases[alias][:i]
            targetdom = aliases[alias][i+1:]
        return targetpre + locpre[len(aliaspre):] + '@' + \
            targetdom
  if '@' not in loc:
    loc = loc + '@' + gale_domain()
  return loc

# ----------------------------------------------------------------------
# Location transformations

def escape_location(loc):
  """
  Convert user-level location string to wire protocol.

  >>> escape_location('pub.tv.earth:final/conflict@ofb.net')
  '@ofb.net/user/pub/tv/earth..final.|conflict/'
  >>> escape_location('somejerk@funky:troublesome/domain.com')
  '@funky@.troublesome@|domain.com/user/somejerk/'

  """
  if loc[0] == '-':
    loc = loc[1:]
    neg = '-'
  else:
    neg = ''
  domain, cats = parse_location_upper(loc)
  domain = re.sub(':', '@.', domain)
  domain = re.sub('/', '@|', domain)
  cats = map(lambda c: re.sub(':', '..', c), cats)
  cats = map(lambda c: re.sub('/', '.|', c), cats)
  cat = string.join(cats, LOCATION_DELIMITER_LOWER)
  return '%s@%s/user/%s/' % (neg, domain, cat)

def escape_location_list(loc_list):
  """Convert user-level location string possibly containing multiple
  locations into single wire-level procotol string; if first character
  of location is '@', pass it through unchanged (backwards compatibility
  hack)"""
  out = []
  for loc in loc_list:
    if loc and loc[0] == '@':
      out.append(loc)
    else:
      out.append(escape_location(loc))
  return string.join(out, ':')

def parse_location_upper(loc):
  if '@' not in loc:
    call_debug_handler(
      'ERROR: location "%s" must contain @; using default domain' %
      loc)
    loc = loc + '@' + gale_domain()
  i = string.rfind(loc, '@')
  domain = loc[i+1:]
  cat = loc[:i]
  cats = string.split(cat, LOCATION_DELIMITER_UPPER)
  return domain, cats

def unescape_location(loc):
  """
  Convert wire protocol to user-level location string; may return
  None if the wire protocol category is supposed to be ignored (i.e. it
  does not contain the string "/user/" after the domain)

  >>> unescape_location('@ofb.net/user/pub/tv/earth..final.|conflict/')
  'pub.tv.earth:final/conflict@ofb.net'
  >>> unescape_location('@funky@.troublesome@|domain.com/user/somejerk/')
  'somejerk@funky:troublesome/domain.com'
  >>> unescape_location('@ofb.net/server/ignore')

  """
  retval = parse_location_lower(loc)
  if retval is not None:
    domain, cats = retval
    cat = string.join(cats, LOCATION_DELIMITER_UPPER)
    return '%s@%s' % (cat, domain)
  else:
    if DEBUG & DEBUG_PROTOCOL:
      call_debug_handler('unescape loc: ignoring old cat: %s' % loc)
    return None

def unescape_location_string(loc):
  """Convert wire protocol string possibly containing multiple locations
  into single user-level location string; the number of user-level
  locations may be smaller than the number of wire-level locations"""
  locs = string.split(loc, ':')
  return string.join(filter(None, map(unescape_location, locs)), ' ')

def parse_location_lower(loc):
  """Return either a tuple of (domain, category list), if the category
  can be parsed into such fields, or None if it does not contain the
  string "/user/" after the domain part of the category"""
  i = string.find(loc, '/')
  domain = loc[1:i]
  cat = loc[i+1:]
  if cat and cat[-1] == '/':
    cat = cat[:-1]
  domain = re.sub('@\.', ':', domain)
  domain = re.sub('@\|', '/', domain)
  cats = string.split(cat, LOCATION_DELIMITER_LOWER)
  if cats[0] == 'user':
    cats = cats[1:]
  else:
    # drop this category, for backwards compatibility
    # why is this necessary?
    return
  cats = map(lambda c: re.sub('\.\.', ':', c), cats)
  cats = map(lambda c: re.sub('\.\|', '/', c), cats)
  return domain, cats


# ----------------------------------------------------------------------
# Handle non-fatal errors
def set_error_handler(func):
  global ERROR_HANDLER
  ERROR_HANDLER = func

# Notify on progress reports
def set_update_handler(func):
  global UPDATE_HANDLER
  UPDATE_HANDLER = func

def set_debug_handler(func):
  global DEBUG_HANDLER
  DEBUG_HANDLER = func

def call_error_handler(msg):
  if ERROR_HANDLER is not None:
    ERROR_HANDLER(msg)
def call_update_handler(msg):
  if UPDATE_HANDLER is not None:
    UPDATE_HANDLER(msg)
def call_debug_handler(msg):
  if DEBUG_HANDLER is not None:
    DEBUG_HANDLER(msg)

# ----------------------------------------------------------------------
# Notifications
def notify_in(presence, conn, userid=None, fullname=None, version=None,
  instance=None):
  p = Puff()
  if userid is None:
    userid = gale_user()
  p.set_loc('_gale.notice.' + userid)
  p.set_text('notice/presence', presence)
  p.set_time('id/time', int(time.time()))
  if version is not None:
    p.set_text('id/class', version)
  else:
    p.set_text('id/class', PYGALE_VERSION)
  if instance is not None:
    p.set_text('id/instance', instance)
  else:
    p.set_text('id/instance', getinstance())
  if fullname:
    p.set_text('message/sender', fullname)
  p = p.sign_message(userid)
  if p is not None:
    conn.transmit_puff(p)
  else:
    call_error_handler('Error signing notify in message')

def notify_out(presence, conn, userid=None, fullname=None, version=None,
  instance=None):
  p = Puff()
  if userid is None:
    userid = gale_user()
  p.set_loc('_gale.notice.' + userid)
  p.set_text('notice/presence', presence)
  if version is not None:
    p.set_text('id/class', version)
  else:
    p.set_text('id/class', PYGALE_VERSION)
  if instance is not None:
    p.set_text('id/instance', instance)
  else:
    p.set_text('id/instance', getinstance())
  if fullname:
    p.set_text('message/sender', fullname)
  p = p.sign_message(userid)
  if p is not None:
    conn.transmit_puff(p, will=1)
  else:
    call_error_handler('Error signing notify out message')

# ----------------------------------------------------------------------
# Look up keys/recipients for a set of locations
# ----------------------------------------------------------------------

# ----------------------------------------------------------------------
# Location -> key lookup
# Calls the callback with the new location (after redirection) and a list
# of keyobjs (to be used to encrypt for this location).
# If callback is None, block until location has been found, then return a
# tuple consisting of the new location and the list of keyobjs.
#
# 6/29/04: I believe that the list of keyobjs may be [''], which means
# not to encrypt for this location.
#
# This calls lookup_ids under the covers to find the key objects, and also
# _lookup_location_redirect.
def lookup_location(loc, callback=None, do_akd=1, keys_seen=None):
  """
  Lookup and return list of encryption keys corresponding to
  this location

  >>> import textwrap

  Individual keys:

  >>> for h in 'bull christine harry reinhold selma'.split():
  ...   lookup_location('%s@test.yammer.net' % h, do_akd=0)
  (u'bull@test.yammer.net', [Key <bull@test.yammer.net> public [Z]])
  (u'christine@test.yammer.net', [Key <christine@test.yammer.net> public [Z]])
  (u'harry@test.yammer.net', [Key <harry@test.yammer.net> public [Z]])
  (u'reinhold@test.yammer.net', [Key <reinhold@test.yammer.net> public [Z]])
  (u'selma@test.yammer.net', [Key <selma@test.yammer.net> public [Z]])

  Group key:

  >>> print textwrap.fill(`lookup_location('bailiffs@test.yammer.net',
  ...   do_akd=0)`)
  (u'bailiffs@test.yammer.net', [Key <bailiffs@test.yammer.net> public
  members[u'selma@test.yammer.net', u'bull@test.yammer.net']
  [Unspecified owner], Key <selma@test.yammer.net> public [Z], Key
  <bull@test.yammer.net> public [Z]])

  """

  if callback is None:
    blocker = Blocker()
    cb = lambda loc, keylist, blocker=blocker:\
      blocker.done_setval(loc, keylist)
  else:
    cb = callback
  if loc[:5] == '_gale':
    cb(loc, [''])
    return
  elif loc[0] == '@':
    # hack for old-style location
    # TODO: remove this when no one needs old-style categories
    # anymore
    cb(loc, [''])
    return
  elif loc[0] == '-':
    # Negative location
    # Add another layer that puts the - back in front of the
    # redirected location string
    cb = lambda l, k, cb=cb: neg_location(l, k, cb)
    loc = loc[1:]
  domain, cats = parse_location_upper(loc)
  candidate_keynames = ['%s@%s' % (string.join(cats, '.'), domain)]
  cats = cats[:-1]
  while cats:
    candidate_keynames.append(
      '%s.*@%s' % (string.join(cats, '.'), domain))
    cats = cats[:-1]
  candidate_keynames.append('*@%s' % domain)
  if DEBUG & DEBUG_PROTOCOL:
    call_debug_handler('Got candidate keynames: %s' %
      candidate_keynames)
  # 6/30/04 Refactor: move redirect processing inside of lookup_ids
# new_cb = lambda key, loc=loc, cb=cb, d=do_akd, s=keys_seen:\
#   _lookup_location_redirect(key, loc, cb, d, s)
  retval = lookup_ids(candidate_keynames, callback=cb, all=0,
    do_akd=do_akd)
  if callback is None:
    while blocker.wait:
      engine.engine.process()
    return blocker.val

def neg_location(loc, keylist, callback):
  if DEBUG & DEBUG_PROTOCOL:
    call_debug_handler('Negating location: %s' % loc)
  callback('-' + loc, keylist)

# Helper function: lookup a location, following key redirects.
# Callback takes two arguments: the name of the location, and a list
# of keyobjs to be used to encrypt to this location.  The list of key
# objs may contain the empty string (''), which means no encryption
# should be used.
def _lookup_location_redirect(keyobj, loc, callback, do_akd=1,
  keys_seen=None):
  "Helper function to look up locations in presence of redirects"
  if DEBUG & DEBUG_PROTOCOL:
    call_debug_handler('lookup location: redirect helper, keyobj %s' %
      keyobj)
  if keyobj is None:
    if DEBUG & DEBUG_PROTOCOL:
      call_debug_handler('lookup_loc_red: calling cb with None')
    _lookup_location_members(loc, keyobj, callback)
    return
  if keys_seen is None:
    keys_seen = []
  if keyobj.name() in keys_seen:
    # Key redirect loop!
    call_error_handler('redirect loop on location %s' %\
      loc)
    _lookup_location_members(loc, None, callback)
    return

  redirect = keyobj.redirect()
  if redirect is None:
    # Use this key
    assert keyobj.public() or keyobj.members()
    if DEBUG & DEBUG_PROTOCOL:
      call_debug_handler(
        'lookup_loc_red: regular key found, using it %s' %
        keyobj.name())
    _lookup_location_members(loc, keyobj, callback)
    return
  else:
    if DEBUG & DEBUG_PROTOCOL:
      call_debug_handler('Found symlink key to %s' % redirect)
    # Merge key name, redirect, and old location to get new loc
    new_loc = _merge_locs(loc, redirect, keyobj.name())
    if DEBUG & DEBUG_PROTOCOL:
      call_debug_handler('Merged location is: %s' % new_loc)
    lookup_location(new_loc, callback, do_akd, keys_seen +
      [keyobj.name()])

def _lookup_location_members(new_loc, keyobj, callback):
  if keyobj is None:
    callback(new_loc, [keyobj])
    return
  mc = MemberCollector(new_loc, callback)
  mc.process(keyobj)

# Call the callback with a list of tuples.  The first element of the tuple
# is the (new) location to subscribe to (as a string), the second is a list
# of keyobjs to be used to encrypt to this location.  If the list of keys is
# None, the location in INVALID.  If it contains the empty string, no
# encryption should be done.
# If callback is None, block until all locations are available.  Return a
# list of tuples as in the callback return.
def lookup_all_locations(loc_list, callback=None):
  "Try disk cache first, then go to AKD if that fails"
  # Check for empty list and return immediately
  if not loc_list:
    if callback is None:
      return []
    else:
      callback([])

  # ensure there are no duplicates in loc_list
  new_loc_list = []
  for i in loc_list:
    if i not in new_loc_list:
      new_loc_list.append(i)
  loc_list = new_loc_list

  # Need at least one key for each location in loc_list
  if DEBUG & DEBUG_PROTOCOL:
    call_debug_handler('Looking up list of locations: %s' % loc_list)
  # The Collector waits until it gets something for every item in
  # loc_list
  if callback is None:
    blocker = Blocker()
    cb = lambda k, blocker=blocker: blocker.done_setval(k)
  else:
    cb = callback
  collector = authcache.Collector(loc_list)
  new_cb = lambda keys, cb=cb:\
    lookup_all_locations_akd(keys, cb)
  for loc in loc_list:
    if DEBUG & DEBUG_PROTOCOL:
      call_debug_handler('Finding key for location %s' % loc)
    loc_cb = lambda new_loc, keylist, l=loc, c=collector, cb=new_cb:\
      _loc_coll_callback(new_loc, keylist, l, c, cb)
    lookup_location(loc, loc_cb, do_akd=0)
  if callback is None:
    while blocker.wait:
      engine.engine.process()
    return blocker.val

def _loc_coll_callback(new_loc, keylist, orig_loc, collector, cb):
  "keylist should be used to encrypt to redirected location new_loc"
  if DEBUG & DEBUG_PROTOCOL:
    call_debug_handler('loc coll cb, new loc: %s' % new_loc)
    call_debug_handler('keylist: %s' % keylist)
    call_debug_handler('orig: %s' % orig_loc)
  collector.setoutput(orig_loc, (new_loc, keylist))
  if collector.done():
    if DEBUG & DEBUG_PROTOCOL:
      call_debug_handler('loc coll cb: collector DONE')
    # Call back with the response
    cb(collector.getvalues())

def lookup_all_locations_akd(loc_key_list, callback):
  list_of_list_of_keys = map(lambda x: x[1], loc_key_list)
  new_locs = map(lambda x: x[0], loc_key_list)
  if None not in list_of_list_of_keys:
    # Found a local key for each location
    callback(loc_key_list)
    return
  if DEBUG & DEBUG_PROTOCOL:
    call_debug_handler(
      'Lookup_location_akd: not all keys found, trying akd')
    call_debug_handler('Lookup_location_akd: new locs: %s' % new_locs)
  collector = authcache.Collector(new_locs)
  for loc in new_locs:
    if DEBUG & DEBUG_PROTOCOL:
      call_debug_handler('Finding key using AKD for loc %s' % loc)
    loc_cb = lambda new_loc, keylist, l=loc, c=collector, cb=callback:\
      _loc_coll_callback(new_loc, keylist, l, c, cb)
    lookup_location(loc, loc_cb, do_akd=1)

def _merge_locs(orig, redirect, keyname):
  """Implement the merging of location strings on a redirect"""
  orig_domain, orig_cats = parse_location_upper(orig)
  redirect_domain, redirect_cats = parse_location_upper(redirect)
  key_domain, key_cats = parse_location_upper(keyname)
  if key_cats[-1] == '*':
    key_cats = key_cats[:-1]
  assert len(key_cats) <= len(orig_cats)
  new_cats = redirect_cats + orig_cats[len(key_cats):]
  return string.join(new_cats, '.') + '@' + redirect_domain


class MemberCollector:
  def __init__(self, locname, callback):
    self.__callback = callback
    self.__locname = locname
    self.__members = []
    self.__pending = 0
  
  def process(self, keyobj):
    """Initial entry point.  Process a single key object and call the
    callback with the list of members for this key, or None if there
    is an error.  The list may include the empty string."""

    # Increment pending to 1 to begin
    self.__pending = self.__pending + 1
    if DEBUG & DEBUG_KEYS:
      call_debug_handler('MC process: %s' % keyobj)
    assert keyobj is not None

    # Process this one key
    self.__pending = self.__pending + 1
    if DEBUG & DEBUG_KEYS:
      call_debug_handler('MC process objs incr pending to %s' %
        self.__pending)
    self.got_keys(keyobj.name(), [keyobj])

    # At this point, if there's nothing else pending or we didn't
    # short-circuit, pending should be 1
    if self.__pending == 0:
      return
    # If we reach here, then there's nothing pending and the reason
    # pending is 1 is because we set it earlier in this function.
    # Therefore we must be done; call the callback.
    self.__pending = self.__pending - 1
    if DEBUG & DEBUG_KEYS:
      call_debug_handler('MC main process decr pending to %s' %
        self.__pending)
    if self.__pending == 0:
      if DEBUG & DEBUG_KEYS:
        call_debug_handler(
          'MC main process done, calling cb with %s' %
          `(self.__locname, self.__members)`)
      self.__pending = 0
      self.call_callback()

  def process_members(self, list_of_keynames):
    if DEBUG & DEBUG_KEYS:
      call_debug_handler('MC processing %s' % list_of_keynames)
    if self.__pending == 0:
      return
    for keyname in list_of_keynames:
      if self.__pending == 0:
        if DEBUG & DEBUG_KEYS:
          call_debug_handler(
            'MC process_mem: pending 0, returning')
        return
      self.__pending = self.__pending + 1
      if DEBUG & DEBUG_KEYS:
        call_debug_handler(
          'MC processing incr pending to %s' % self.__pending)
      if keyname == '':
        # Shortcircuit the rest of the processing and callback
        # immediately
        self.got_everyone()
      else:
        lookup_ids([keyname], lambda newloc, keylist,
          s=self: s.got_keys(newloc, keylist))

  def got_everyone(self):
    if self.__pending == 0:
      if DEBUG & DEBUG_KEYS:
        call_debug_handler(
          'MC got everyone but pending is 0; returning')
      return
    self.__members = ['']
    self.__pending = 0
    if DEBUG & DEBUG_KEYS:
      call_debug_handler('MC calling CB 1 with %s' % self.__members)
    self.call_callback()
  def got_error(self):
    if self.__pending == 0:
      if DEBUG & DEBUG_KEYS:
        call_debug_handler(
          'MC got error but pending is 0; returning')
      return
    self.__members = []
    self.__pending = 0
    if DEBUG & DEBUG_KEYS:
      call_debug_handler('MC calling CB 2 with None')
    self.call_callback(0)

  # keyobjs may be None
  def got_keys(self, keyname, keyobjs):
    if self.__pending == 0:
      # We are extraneous
      if DEBUG & DEBUG_KEYS:
        call_debug_handler('MC got key but pending is 0; returning')
      return

    if DEBUG & DEBUG_KEYS:
      call_debug_handler('MC pending: %s' % self.__pending)
    if keyobjs is not None:
      for keyobj in keyobjs:
        if DEBUG & DEBUG_KEYS:
          call_debug_handler('MC got key %s' % keyobj)
        if keyobj == '':
          self.got_everyone()
        else:
          if keyobj.public():
            if keyobj not in self.__members:
              self.__members.append(keyobj)
          if keyobj.members():
            if '' in keyobj.members():
              self.got_everyone()
            else:
              self.process_members(keyobj.members())

        if self.__pending == 0:
          return

    self.__pending = self.__pending - 1
    if DEBUG & DEBUG_KEYS:
      call_debug_handler('MC decrementing pending to %s' %
        self.__pending)
    if self.__pending == 0:
      if DEBUG & DEBUG_KEYS:
        call_debug_handler('MC calling CB 3 with %s' % 
          self.__members)
      self.__pending = 0
      self.call_callback()

  def call_callback(self, succeed=1):
    if succeed:
      self.__callback(self.__locname, self.__members)
    else:
      self.__callback(self.__locname, None)
    # Cleanup
    self.__keyobjs = None
    self.__members = None
    self.__locname = None

# ----------------------------------------------------------------------
# Initialization
# galeconf is the path to a Gale configuration file; if None, it defaults
# to ~/.gale/conf (see gale_env)
def init(galeconf=None, domain=None):

  gale_env.init(galeconf=galeconf, domain=domain)
# if authcache.DEBUG < DEBUG:
#   authcache.DEBUG = DEBUG
# if sign.DEBUG < DEBUG:
#   sign.DEBUG = DEBUG

  authcache.init()
  initrand()

def shutdown():
  authcache.shutdown()

# ----------------------------------------------------------------------
# Test Pygale functionality
def main():
  opts, args = getopt.getopt(sys.argv[1:], 'rsd:')
  receive = 1
  global DEBUG
  for (opt, val) in opts:
    if opt == '-r':
      receive = 1
    elif opt == '-s':
      receive = 0
    elif opt == '-d':
      DEBUG = int(val)
      print 'Setting DEBUG to', DEBUG
  init()
  if receive:
    testrecv()
  else:
    testsend()

if __name__ == '__main__':
  main()

