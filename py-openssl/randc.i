%module randc

%pragma make_default

%{
#include "openssl/err.h"
#include "openssl/rand.h"
#include "opensslc.h"

#if !defined(WINDOWS) && !defined(WIN32)
void RAND_screen(void)
{
}
#endif /* !WIN32 */

extern PyObject* OpenSSLErr;

PyObject*
python_RAND_bytes(int num)
{
	PyObject* bytes_python_string;
	unsigned char* bytes_buffer;

	bytes_python_string = PyString_FromStringAndSize(NULL, num);
	if (bytes_python_string == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Unable to allocate memory for random byte buffer.");
		return NULL;
	}

	bytes_buffer = PyString_AsString(bytes_python_string);
	/* RAND_bytes is declared void in OpenSSL 0.9.4 but int in >= 0.9.5 */
	RAND_bytes(bytes_buffer, num);
	return bytes_python_string;
}

%}

%typemap(in) unsigned char*
{
        $1 = PyString_AsString($input);
}

void RAND_seed(unsigned char *buf,int num);
void RAND_screen(void);
void RAND_bytes(unsigned char *buf,int num);
PyObject* python_RAND_bytes(int num);
