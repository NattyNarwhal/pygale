"""
Expose the fields of a C struct.

(Example removed due to looking too deep inside a struct.)

"""

import opensslc
try:
  import _rsac as rsac
except ImportError:
  import rsac
import wrap
import bn

class RSA(wrap.Wrapper):
  def __init__(self, ptr = None):
    attr_dict = \
    {
      'flags': (rsac.RSA_flags, rsac.RSA_set_flags, None),
      'iqmp': (rsac.RSA_get0_iqmp, None, bn.BIGNUM),
      'dmq1': (rsac.RSA_get0_dmq1, None, bn.BIGNUM),
      'dmp1': (rsac.RSA_get0_dmp1, None, bn.BIGNUM),
      'q': (rsac.RSA_get0_q, None, bn.BIGNUM),
      'p': (rsac.RSA_get0_p, None, bn.BIGNUM),
      'd': (rsac.RSA_get0_d, None, bn.BIGNUM),
      'e': (rsac.RSA_get0_e, None, bn.BIGNUM),
      'n': (rsac.RSA_get0_n, None, bn.BIGNUM),
    }
    wrap.Wrapper.__init__(self, ptr, rsac.RSA_new, rsac.RSA_free, attr_dict)

  # XXX: Do we need to make these have PyObject wrappers or something?
  def set_key(self, n, e, d):
    return rsac.RSA_set0_key(self.ptr, n.ptr, e.ptr, d.ptr)

  def set_factors(self, p, q):
    return rsac.RSA_set0_factors(self.ptr, p.ptr, q.ptr)

  def set_crt_params(self, dmp1, dmq1, iqmp):
    return rsac.RSA_set0_crt_params(self.ptr, dmp1.ptr, dmq1.ptr, iqmp.ptr)


