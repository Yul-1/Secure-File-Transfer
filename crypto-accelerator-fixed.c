#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>

#if defined(__GLIBC__) && ( ( __GLIBC__ > 2 ) || ( __GLIBC__ == 2 && __GLIBC_MINOR__ >= 25 ) )
    #define secure_memzero(ptr, size) explicit_bzero(ptr, size)
#elif defined(_MSC_VER)
    #include <windows.h>
    #define secure_memzero(ptr, size) SecureZeroMemory(ptr, size)
#else
    static void secure_memzero(void *v, size_t n) {
        volatile unsigned char *p = (volatile unsigned char *)v;
        while (n--) *p++ = 0;
    }
#endif

#define CHECK_PTR(ptr) if (ptr == NULL) { PyErr_SetString(PyExc_MemoryError, "OpenSSL allocation failed"); goto cleanup; }
#define CHECK_SSL_SUCCESS(ret) if (ret <= 0) { PyErr_SetString(PyExc_ValueError, "OpenSSL operation failed"); goto cleanup; }

#define MIN_PY_BUFFER_SIZE 0
#define MAX_PY_BUFFER_SIZE (10 * 1024 * 1024)

static int validate_buffer_size(Py_ssize_t size, Py_ssize_t min, Py_ssize_t max, const char* name) {
    if (size > max || size < min) {
        PyErr_Format(PyExc_ValueError, "Invalid %s size: %zd. Must be between %zd and %zd bytes.",
                     name, size, min, max);
        return 0;
    }
    return 1;
}




static PyObject* aes_gcm_encrypt_safe(PyObject* self, PyObject* args) {
    PyObject* result_tuple = NULL;
    PyObject* ciphertext_obj = NULL;
    PyObject* tag_obj = NULL;
    
    const unsigned char *plaintext = NULL;
    const unsigned char *key = NULL;
    const unsigned char *iv = NULL;
    Py_ssize_t plaintext_len, key_len, iv_len;

    unsigned char *ciphertext_buf = NULL;
    unsigned char *tag_buf = NULL;
    
    EVP_CIPHER_CTX *ctx = NULL;
    int len, ciphertext_len;

    if (!PyArg_ParseTuple(args, "y#y#y#", &plaintext, &plaintext_len, &key, &key_len, &iv, &iv_len)) {
        return NULL;
    }

    if (key_len != 32 || iv_len != 12) {
        PyErr_SetString(PyExc_ValueError, "Invalid key or IV size");
        return NULL;
    }
    if (!validate_buffer_size(plaintext_len, MIN_PY_BUFFER_SIZE, MAX_PY_BUFFER_SIZE, "plaintext")) {
        return NULL;
    }
    
    if (plaintext_len > INT_MAX) {
        PyErr_SetString(PyExc_ValueError, "Plaintext too large for OpenSSL (max 2GB)");
        return NULL;
    }

    ciphertext_buf = (unsigned char*)PyMem_Malloc(plaintext_len + EVP_MAX_BLOCK_LENGTH);
    tag_buf = (unsigned char*)PyMem_Malloc(16);
    if (ciphertext_buf == NULL || tag_buf == NULL) {
        PyErr_SetString(PyExc_MemoryError, "Failed to allocate memory");
        goto cleanup;
    }
    
    ctx = EVP_CIPHER_CTX_new();
    CHECK_PTR(ctx);

    CHECK_SSL_SUCCESS(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));
    CHECK_SSL_SUCCESS(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));

    CHECK_SSL_SUCCESS(EVP_EncryptUpdate(ctx, ciphertext_buf, &len, plaintext, (int)plaintext_len));
    ciphertext_len = len;

    CHECK_SSL_SUCCESS(EVP_EncryptFinal_ex(ctx, ciphertext_buf + len, &len));
    ciphertext_len += len;

    CHECK_SSL_SUCCESS(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag_buf));

    ciphertext_obj = PyBytes_FromStringAndSize((char*)ciphertext_buf, ciphertext_len);
    if (!ciphertext_obj) {
        PyErr_SetString(PyExc_MemoryError, "Failed to create ciphertext bytes object");
        goto cleanup;
    }
    
    tag_obj = PyBytes_FromStringAndSize((char*)tag_buf, 16);
    if (!tag_obj) {
        PyErr_SetString(PyExc_MemoryError, "Failed to create tag bytes object");
        Py_DECREF(ciphertext_obj);
        ciphertext_obj = NULL;
        goto cleanup;
    }
    
    result_tuple = PyTuple_Pack(2, ciphertext_obj, tag_obj);
    if (!result_tuple) {
        PyErr_SetString(PyExc_MemoryError, "Failed to create result tuple");
        goto cleanup;
    }
    
    Py_DECREF(ciphertext_obj);
    Py_DECREF(tag_obj);

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (ciphertext_buf) {
        secure_memzero(ciphertext_buf, plaintext_len + EVP_MAX_BLOCK_LENGTH);
        PyMem_Free(ciphertext_buf);
    }
    if (tag_buf) {
        secure_memzero(tag_buf, 16);
        PyMem_Free(tag_buf);
    }
    
    if (result_tuple == NULL) {
        Py_XDECREF(ciphertext_obj);
        Py_XDECREF(tag_obj);
    }
    

    return result_tuple;
}


static PyObject* aes_gcm_decrypt_safe(PyObject* self, PyObject* args) {
    PyObject* plaintext_obj = NULL;
    
    const unsigned char *ciphertext = NULL;
    const unsigned char *key = NULL;
    const unsigned char *iv = NULL;
    const unsigned char *tag = NULL;
    Py_ssize_t ciphertext_len, key_len, iv_len, tag_len;

    unsigned char *plaintext_buf = NULL;
    
    EVP_CIPHER_CTX *ctx = NULL;
    int len, plaintext_len;
    
    if (!PyArg_ParseTuple(args, "y#y#y#y#", &ciphertext, &ciphertext_len, &key, &key_len, &iv, &iv_len, &tag, &tag_len)) {
        return NULL;
    }

    if (key_len != 32 || iv_len != 12 || tag_len != 16) {
        PyErr_SetString(PyExc_ValueError, "Invalid key, IV or tag size");
        return NULL;
    }
    if (!validate_buffer_size(ciphertext_len, MIN_PY_BUFFER_SIZE, MAX_PY_BUFFER_SIZE, "ciphertext")) {
        return NULL;
    }
    
    if (ciphertext_len > INT_MAX) {
        PyErr_SetString(PyExc_ValueError, "Ciphertext too large for OpenSSL (max 2GB)");
        return NULL;
    }

    plaintext_buf = (unsigned char*)PyMem_Malloc(ciphertext_len + EVP_MAX_BLOCK_LENGTH);
    if (plaintext_buf == NULL) {
        PyErr_SetString(PyExc_MemoryError, "Failed to allocate memory");
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    CHECK_PTR(ctx);

    CHECK_SSL_SUCCESS(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));
    CHECK_SSL_SUCCESS(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv));

    CHECK_SSL_SUCCESS(EVP_DecryptUpdate(ctx, plaintext_buf, &len, ciphertext, (int)ciphertext_len));
    plaintext_len = len;

    CHECK_SSL_SUCCESS(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (void*)tag));

    if (EVP_DecryptFinal_ex(ctx, plaintext_buf + len, &len) <= 0) {
        PyErr_SetString(PyExc_ValueError, "Decryption failed (Authentication Tag Mismatch or corrupted data)");
        goto cleanup;
    }
    plaintext_len += len;

    plaintext_obj = PyBytes_FromStringAndSize((char*)plaintext_buf, plaintext_len);
    if (!plaintext_obj) {
        PyErr_SetString(PyExc_MemoryError, "Failed to create plaintext bytes object");
        goto cleanup;
    }
    
cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (plaintext_buf) {
        secure_memzero(plaintext_buf, ciphertext_len + EVP_MAX_BLOCK_LENGTH);
        PyMem_Free(plaintext_buf);
    }
    

    return plaintext_obj;
}


static PyObject* generate_secure_random_safe(PyObject* self, PyObject* args) {
    Py_ssize_t num_bytes;
    PyObject* random_bytes_obj = NULL;
    unsigned char *random_buf = NULL;

    if (!PyArg_ParseTuple(args, "n", &num_bytes)) {
        return NULL;
    }

    if (!validate_buffer_size(num_bytes, 1, MAX_PY_BUFFER_SIZE, "buffer")) {
        return NULL;
    }
    
    if (num_bytes > INT_MAX) {
        PyErr_SetString(PyExc_ValueError, "Requested size too large for OpenSSL (max 2GB)");
        return NULL;
    }

    random_buf = (unsigned char*)PyMem_Malloc(num_bytes);
    if (random_buf == NULL) {
        PyErr_SetString(PyExc_MemoryError, "Failed to allocate memory");
        goto cleanup;
    }

    if (RAND_bytes(random_buf, (int)num_bytes) != 1) {
        PyErr_SetString(PyExc_SystemError, "OpenSSL RAND_bytes failed (PRNG not seeded?)");
        goto cleanup;
    }

    random_bytes_obj = PyBytes_FromStringAndSize((char*)random_buf, num_bytes);
    if (!random_bytes_obj) {
        PyErr_SetString(PyExc_MemoryError, "Failed to create random bytes object");
        goto cleanup;
    }

cleanup:
    if (random_buf) {
        secure_memzero(random_buf, num_bytes);
        PyMem_Free(random_buf);
    }
    return random_bytes_obj;
}


static PyObject* sha256_hash_safe(PyObject* self, PyObject* args) {
    const unsigned char *data;
    Py_ssize_t data_len;
    unsigned char hash_buf[SHA256_DIGEST_LENGTH];

    if (!PyArg_ParseTuple(args, "y#", &data, &data_len)) {
        return NULL;
    }

    if (!validate_buffer_size(data_len, MIN_PY_BUFFER_SIZE, MAX_PY_BUFFER_SIZE, "data for hashing")) {
        return NULL;
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        PyErr_SetString(PyExc_MemoryError, "EVP_MD_CTX_new failed");
        return NULL;
    }

    if (1 != EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) ||
        1 != EVP_DigestUpdate(md_ctx, data, data_len) ||
        1 != EVP_DigestFinal_ex(md_ctx, hash_buf, NULL)) {
        
        EVP_MD_CTX_free(md_ctx);
        PyErr_SetString(PyExc_SystemError, "OpenSSL SHA-256 operation failed");
        return NULL;
    }

    EVP_MD_CTX_free(md_ctx);

    return PyBytes_FromStringAndSize((char*)hash_buf, SHA256_DIGEST_LENGTH);
}


static PyObject* compare_digest_safe(PyObject* self, PyObject* args) {
    const unsigned char *a, *b;
    Py_ssize_t a_len, b_len;

    if (!PyArg_ParseTuple(args, "y#y#", &a, &a_len, &b, &b_len)) {
        return NULL;
    }
    
    if (a_len < 0 || b_len < 0) {
        PyErr_SetString(PyExc_ValueError, "Invalid lengths");
        return NULL;
    }

    int match = 0;
    
    if (a_len == b_len) {
        if (CRYPTO_memcmp(a, b, a_len) == 0) {
            match = 1;
        }
    }
    
    if (match == 1) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}


static PyObject* benchmark_crypto_safe(PyObject* self, PyObject* args) {
    Py_RETURN_NONE;
}


static PyMethodDef CryptoMethods[] = {
    {"aes_gcm_encrypt", aes_gcm_encrypt_safe, METH_VARARGS,
     "Secure AES-GCM encryption with bounds checking"},
    {"aes_gcm_decrypt", aes_gcm_decrypt_safe, METH_VARARGS,
     "Secure AES-GCM decryption with auth tag checking"},
    {"generate_secure_random", generate_secure_random_safe, METH_VARARGS,
     "Generate cryptographically secure random bytes"},
    {"sha256_hash", sha256_hash_safe, METH_VARARGS,
     "Secure SHA-256 hashing with bounds checking"},
    {"compare_digest", compare_digest_safe, METH_VARARGS,
     "Constant-time comparison for digests (Timing Attacks)"},
    {"benchmark", benchmark_crypto_safe, METH_VARARGS,
     "Safe benchmark of crypto operations"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef cryptomodule = {
    PyModuleDef_HEAD_INIT,
    "crypto_accelerator",
    "Secure hardware-accelerated cryptographic operations",
    -1,
    CryptoMethods
};

PyMODINIT_FUNC PyInit_crypto_accelerator(void) {
    
    #if OPENSSL_VERSION_NUMBER < 0x10100000L
        OpenSSL_add_all_algorithms();
    #endif
    
    
    return PyModule_Create(&cryptomodule);
}