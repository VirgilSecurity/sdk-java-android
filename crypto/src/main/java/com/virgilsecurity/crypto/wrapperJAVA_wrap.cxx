/**
 * Copyright (C) 2016 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <cstddef>


#define SWIGJAVA
#define SWIG_DIRECTORS


#ifdef __cplusplus
/* SwigValueWrapper is described in swig.swg */
template<typename T> class SwigValueWrapper {
  struct SwigMovePointer {
    T *ptr;
    SwigMovePointer(T *p) : ptr(p) { }
    ~SwigMovePointer() { delete ptr; }
    SwigMovePointer& operator=(SwigMovePointer& rhs) { T* oldptr = ptr; ptr = 0; delete oldptr; ptr = rhs.ptr; rhs.ptr = 0; return *this; }
  } pointer;
  SwigValueWrapper& operator=(const SwigValueWrapper<T>& rhs);
  SwigValueWrapper(const SwigValueWrapper<T>& rhs);
public:
  SwigValueWrapper() : pointer(0) { }
  SwigValueWrapper& operator=(const T& t) { SwigMovePointer tmp(new T(t)); pointer = tmp; return *this; }
  operator T&() const { return *pointer.ptr; }
  T *operator&() { return pointer.ptr; }
};

template <typename T> T SwigValueInit() {
  return T();
}
#endif

/* -----------------------------------------------------------------------------
 *  This section contains generic SWIG labels for method/variable
 *  declarations/attributes, and other compiler dependent labels.
 * ----------------------------------------------------------------------------- */

/* template workaround for compilers that cannot correctly implement the C++ standard */
#ifndef SWIGTEMPLATEDISAMBIGUATOR
# if defined(__SUNPRO_CC) && (__SUNPRO_CC <= 0x560)
#  define SWIGTEMPLATEDISAMBIGUATOR template
# elif defined(__HP_aCC)
/* Needed even with `aCC -AA' when `aCC -V' reports HP ANSI C++ B3910B A.03.55 */
/* If we find a maximum version that requires this, the test would be __HP_aCC <= 35500 for A.03.55 */
#  define SWIGTEMPLATEDISAMBIGUATOR template
# else
#  define SWIGTEMPLATEDISAMBIGUATOR
# endif
#endif

/* inline attribute */
#ifndef SWIGINLINE
# if defined(__cplusplus) || (defined(__GNUC__) && !defined(__STRICT_ANSI__))
#   define SWIGINLINE inline
# else
#   define SWIGINLINE
# endif
#endif

/* attribute recognised by some compilers to avoid 'unused' warnings */
#ifndef SWIGUNUSED
# if defined(__GNUC__)
#   if !(defined(__cplusplus)) || (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4))
#     define SWIGUNUSED __attribute__ ((__unused__))
#   else
#     define SWIGUNUSED
#   endif
# elif defined(__ICC)
#   define SWIGUNUSED __attribute__ ((__unused__))
# else
#   define SWIGUNUSED
# endif
#endif

#ifndef SWIG_MSC_UNSUPPRESS_4505
# if defined(_MSC_VER)
#   pragma warning(disable : 4505) /* unreferenced local function has been removed */
# endif
#endif

#ifndef SWIGUNUSEDPARM
# ifdef __cplusplus
#   define SWIGUNUSEDPARM(p)
# else
#   define SWIGUNUSEDPARM(p) p SWIGUNUSED
# endif
#endif

/* internal SWIG method */
#ifndef SWIGINTERN
# define SWIGINTERN static SWIGUNUSED
#endif

/* internal inline SWIG method */
#ifndef SWIGINTERNINLINE
# define SWIGINTERNINLINE SWIGINTERN SWIGINLINE
#endif

/* exporting methods */
#if (__GNUC__ >= 4) || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
#  ifndef GCC_HASCLASSVISIBILITY
#    define GCC_HASCLASSVISIBILITY
#  endif
#endif

#ifndef SWIGEXPORT
# if defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
#   if defined(STATIC_LINKED)
#     define SWIGEXPORT
#   else
#     define SWIGEXPORT __declspec(dllexport)
#   endif
# else
#   if defined(__GNUC__) && defined(GCC_HASCLASSVISIBILITY)
#     define SWIGEXPORT __attribute__ ((visibility("default")))
#   else
#     define SWIGEXPORT
#   endif
# endif
#endif

/* calling conventions for Windows */
#ifndef SWIGSTDCALL
# if defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
#   define SWIGSTDCALL __stdcall
# else
#   define SWIGSTDCALL
# endif
#endif

/* Deal with Microsoft's attempt at deprecating C standard runtime functions */
#if !defined(SWIG_NO_CRT_SECURE_NO_DEPRECATE) && defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
# define _CRT_SECURE_NO_DEPRECATE
#endif

/* Deal with Microsoft's attempt at deprecating methods in the standard C++ library */
#if !defined(SWIG_NO_SCL_SECURE_NO_DEPRECATE) && defined(_MSC_VER) && !defined(_SCL_SECURE_NO_DEPRECATE)
# define _SCL_SECURE_NO_DEPRECATE
#endif



/* Fix for jlong on some versions of gcc on Windows */
#if defined(__GNUC__) && !defined(__INTEL_COMPILER)
  typedef long long __int64;
#endif

/* Fix for jlong on 64-bit x86 Solaris */
#if defined(__x86_64)
# ifdef _LP64
#   undef _LP64
# endif
#endif

#include <jni.h>
#include <stdlib.h>
#include <string.h>


/* Support for throwing Java exceptions */
typedef enum {
  SWIG_JavaOutOfMemoryError = 1, 
  SWIG_JavaIOException, 
  SWIG_JavaRuntimeException, 
  SWIG_JavaIndexOutOfBoundsException,
  SWIG_JavaArithmeticException,
  SWIG_JavaIllegalArgumentException,
  SWIG_JavaNullPointerException,
  SWIG_JavaDirectorPureVirtual,
  SWIG_JavaUnknownError
} SWIG_JavaExceptionCodes;

typedef struct {
  SWIG_JavaExceptionCodes code;
  const char *java_exception;
} SWIG_JavaExceptions_t;


static void SWIGUNUSED SWIG_JavaThrowException(JNIEnv *jenv, SWIG_JavaExceptionCodes code, const char *msg) {
  jclass excep;
  static const SWIG_JavaExceptions_t java_exceptions[] = {
    { SWIG_JavaOutOfMemoryError, "java/lang/OutOfMemoryError" },
    { SWIG_JavaIOException, "java/io/IOException" },
    { SWIG_JavaRuntimeException, "java/lang/RuntimeException" },
    { SWIG_JavaIndexOutOfBoundsException, "java/lang/IndexOutOfBoundsException" },
    { SWIG_JavaArithmeticException, "java/lang/ArithmeticException" },
    { SWIG_JavaIllegalArgumentException, "java/lang/IllegalArgumentException" },
    { SWIG_JavaNullPointerException, "java/lang/NullPointerException" },
    { SWIG_JavaDirectorPureVirtual, "java/lang/RuntimeException" },
    { SWIG_JavaUnknownError,  "java/lang/UnknownError" },
    { (SWIG_JavaExceptionCodes)0,  "java/lang/UnknownError" }
  };
  const SWIG_JavaExceptions_t *except_ptr = java_exceptions;

  while (except_ptr->code != code && except_ptr->code)
    except_ptr++;

  jenv->ExceptionClear();
  excep = jenv->FindClass(except_ptr->java_exception);
  if (excep)
    jenv->ThrowNew(excep, msg);
}


/* Contract support */

#define SWIG_contract_assert(nullreturn, expr, msg) if (!(expr)) {SWIG_JavaThrowException(jenv, SWIG_JavaIllegalArgumentException, msg); return nullreturn; } else

/*  Errors in SWIG */
#define  SWIG_UnknownError    	   -1
#define  SWIG_IOError        	   -2
#define  SWIG_RuntimeError   	   -3
#define  SWIG_IndexError     	   -4
#define  SWIG_TypeError      	   -5
#define  SWIG_DivisionByZero 	   -6
#define  SWIG_OverflowError  	   -7
#define  SWIG_SyntaxError    	   -8
#define  SWIG_ValueError     	   -9
#define  SWIG_SystemError    	   -10
#define  SWIG_AttributeError 	   -11
#define  SWIG_MemoryError    	   -12
#define  SWIG_NullReferenceError   -13



/* -----------------------------------------------------------------------------
 * director.swg
 *
 * This file contains support for director classes that proxy
 * method calls from C++ to Java extensions.
 * ----------------------------------------------------------------------------- */

#ifdef __cplusplus

#if defined(DEBUG_DIRECTOR_OWNED)
#include <iostream>
#endif

namespace Swig {
  /* Java object wrapper */
  class JObjectWrapper {
  public:
    JObjectWrapper() : jthis_(NULL), weak_global_(true) {
    }

    ~JObjectWrapper() {
      jthis_ = NULL;
      weak_global_ = true;
    }

    bool set(JNIEnv *jenv, jobject jobj, bool mem_own, bool weak_global) {
      if (!jthis_) {
        weak_global_ = weak_global || !mem_own; // hold as weak global if explicitly requested or not owned
        if (jobj)
          jthis_ = weak_global_ ? jenv->NewWeakGlobalRef(jobj) : jenv->NewGlobalRef(jobj);
#if defined(DEBUG_DIRECTOR_OWNED)
        std::cout << "JObjectWrapper::set(" << jobj << ", " << (weak_global ? "weak_global" : "global_ref") << ") -> " << jthis_ << std::endl;
#endif
        return true;
      } else {
#if defined(DEBUG_DIRECTOR_OWNED)
        std::cout << "JObjectWrapper::set(" << jobj << ", " << (weak_global ? "weak_global" : "global_ref") << ") -> already set" << std::endl;
#endif
        return false;
      }
    }

    jobject get(JNIEnv *jenv) const {
#if defined(DEBUG_DIRECTOR_OWNED)
      std::cout << "JObjectWrapper::get(";
      if (jthis_)
        std::cout << jthis_;
      else
        std::cout << "null";
      std::cout << ") -> return new local ref" << std::endl;
#endif
      return (jthis_ ? jenv->NewLocalRef(jthis_) : jthis_);
    }

    void release(JNIEnv *jenv) {
#if defined(DEBUG_DIRECTOR_OWNED)
      std::cout << "JObjectWrapper::release(" << jthis_ << "): " << (weak_global_ ? "weak global ref" : "global ref") << std::endl;
#endif
      if (jthis_) {
        if (weak_global_) {
          if (jenv->IsSameObject(jthis_, NULL) == JNI_FALSE)
            jenv->DeleteWeakGlobalRef((jweak)jthis_);
        } else
          jenv->DeleteGlobalRef(jthis_);
      }

      jthis_ = NULL;
      weak_global_ = true;
    }

    /* Only call peek if you know what you are doing wrt to weak/global references */
    jobject peek() {
      return jthis_;
    }

    /* Java proxy releases ownership of C++ object, C++ object is now
       responsible for destruction (creates NewGlobalRef to pin Java
       proxy) */
    void java_change_ownership(JNIEnv *jenv, jobject jself, bool take_or_release) {
      if (take_or_release) {  /* Java takes ownership of C++ object's lifetime. */
        if (!weak_global_) {
          jenv->DeleteGlobalRef(jthis_);
          jthis_ = jenv->NewWeakGlobalRef(jself);
          weak_global_ = true;
        }
      } else { /* Java releases ownership of C++ object's lifetime */
        if (weak_global_) {
          jenv->DeleteWeakGlobalRef((jweak)jthis_);
          jthis_ = jenv->NewGlobalRef(jself);
          weak_global_ = false;
        }
      }
    }

  private:
    /* pointer to Java object */
    jobject jthis_;
    /* Local or global reference flag */
    bool weak_global_;
  };

  /* director base class */
  class Director {
    /* pointer to Java virtual machine */
    JavaVM *swig_jvm_;

  protected:
#if defined (_MSC_VER) && (_MSC_VER<1300)
    class JNIEnvWrapper;
    friend class JNIEnvWrapper;
#endif
    /* Utility class for managing the JNI environment */
    class JNIEnvWrapper {
      const Director *director_;
      JNIEnv *jenv_;
      int env_status;
    public:
      JNIEnvWrapper(const Director *director) : director_(director), jenv_(0), env_status(0) {
#if defined(__ANDROID__)
        JNIEnv **jenv = &jenv_;
#else
        void **jenv = (void **)&jenv_;
#endif
        env_status = director_->swig_jvm_->GetEnv((void **)&jenv_, JNI_VERSION_1_2);
#if defined(SWIG_JAVA_ATTACH_CURRENT_THREAD_AS_DAEMON)
        // Attach a daemon thread to the JVM. Useful when the JVM should not wait for 
        // the thread to exit upon shutdown. Only for jdk-1.4 and later.
        director_->swig_jvm_->AttachCurrentThreadAsDaemon(jenv, NULL);
#else
        director_->swig_jvm_->AttachCurrentThread(jenv, NULL);
#endif
      }
      ~JNIEnvWrapper() {
#if !defined(SWIG_JAVA_NO_DETACH_CURRENT_THREAD)
        // Some JVMs, eg jdk-1.4.2 and lower on Solaris have a bug and crash with the DetachCurrentThread call.
        // However, without this call, the JVM hangs on exit when the thread was not created by the JVM and creates a memory leak.
        if (env_status == JNI_EDETACHED)
          director_->swig_jvm_->DetachCurrentThread();
#endif
      }
      JNIEnv *getJNIEnv() const {
        return jenv_;
      }
    };

    /* Java object wrapper */
    JObjectWrapper swig_self_;

    /* Disconnect director from Java object */
    void swig_disconnect_director_self(const char *disconn_method) {
      JNIEnvWrapper jnienv(this) ;
      JNIEnv *jenv = jnienv.getJNIEnv() ;
      jobject jobj = swig_self_.get(jenv);
#if defined(DEBUG_DIRECTOR_OWNED)
      std::cout << "Swig::Director::disconnect_director_self(" << jobj << ")" << std::endl;
#endif
      if (jobj && jenv->IsSameObject(jobj, NULL) == JNI_FALSE) {
        jmethodID disconn_meth = jenv->GetMethodID(jenv->GetObjectClass(jobj), disconn_method, "()V");
        if (disconn_meth) {
#if defined(DEBUG_DIRECTOR_OWNED)
          std::cout << "Swig::Director::disconnect_director_self upcall to " << disconn_method << std::endl;
#endif
          jenv->CallVoidMethod(jobj, disconn_meth);
        }
      }
      jenv->DeleteLocalRef(jobj);
    }

  public:
    Director(JNIEnv *jenv) : swig_jvm_((JavaVM *) NULL), swig_self_() {
      /* Acquire the Java VM pointer */
      jenv->GetJavaVM(&swig_jvm_);
    }

    virtual ~Director() {
      JNIEnvWrapper jnienv(this) ;
      JNIEnv *jenv = jnienv.getJNIEnv() ;
      swig_self_.release(jenv);
    }

    bool swig_set_self(JNIEnv *jenv, jobject jself, bool mem_own, bool weak_global) {
      return swig_self_.set(jenv, jself, mem_own, weak_global);
    }

    jobject swig_get_self(JNIEnv *jenv) const {
      return swig_self_.get(jenv);
    }

    // Change C++ object's ownership, relative to Java
    void swig_java_change_ownership(JNIEnv *jenv, jobject jself, bool take_or_release) {
      swig_self_.java_change_ownership(jenv, jself, take_or_release);
    }
  };
}

#endif /* __cplusplus */


namespace Swig {
  namespace {
    jclass jclass_virgil_crypto_javaJNI = NULL;
    jmethodID director_methids[4];
  }
}

SWIGINTERN void SWIG_JavaException(JNIEnv *jenv, int code, const char *msg) {
  SWIG_JavaExceptionCodes exception_code = SWIG_JavaUnknownError;
  switch(code) {
  case SWIG_MemoryError:
    exception_code = SWIG_JavaOutOfMemoryError;
    break;
  case SWIG_IOError:
    exception_code = SWIG_JavaIOException;
    break;
  case SWIG_SystemError:
  case SWIG_RuntimeError:
    exception_code = SWIG_JavaRuntimeException;
    break;
  case SWIG_OverflowError:
  case SWIG_IndexError:
    exception_code = SWIG_JavaIndexOutOfBoundsException;
    break;
  case SWIG_DivisionByZero:
    exception_code = SWIG_JavaArithmeticException;
    break;
  case SWIG_SyntaxError:
  case SWIG_ValueError:
  case SWIG_TypeError:
    exception_code = SWIG_JavaIllegalArgumentException;
    break;
  case SWIG_UnknownError:
  default:
    exception_code = SWIG_JavaUnknownError;
    break;
  }
  SWIG_JavaThrowException(jenv, exception_code, msg);
}


#include <stdexcept>


#include <stdexcept>


#include <string>


#include <vector>


#include <virgil/crypto/VirgilCryptoException.h>


#include <virgil/crypto/VirgilByteArray.h>


#include <virgil/crypto/VirgilVersion.h>


#include <virgil/crypto/VirgilDataSource.h>


#include <virgil/crypto/VirgilDataSink.h>


#include <virgil/crypto/foundation/asn1/VirgilAsn1Compatible.h>


#include <virgil/crypto/foundation/VirgilHash.h>


#include <virgil/crypto/foundation/VirgilBase64.h>


#include <virgil/crypto/foundation/VirgilPBKDF.h>


#include <virgil/crypto/foundation/VirgilRandom.h>


#include <virgil/crypto/VirgilCustomParams.h>


#include <virgil/crypto/VirgilKeyPair.h>


#include <virgil/crypto/VirgilCipherBase.h>


#include <virgil/crypto/VirgilCipher.h>


#include <virgil/crypto/VirgilChunkCipher.h>


#include <virgil/crypto/VirgilSigner.h>


#include <virgil/crypto/VirgilStreamSigner.h>


#include <virgil/crypto/VirgilStreamCipher.h>


#include <virgil/crypto/VirgilTinyCipher.h>


#include <virgil/crypto/VirgilByteArrayUtils.h>


using virgil::crypto::VirgilKeyPair;



/* ---------------------------------------------------
 * C++ director class methods
 * --------------------------------------------------- */

#include "wrapperJAVA_wrap.h"

SwigDirector_VirgilDataSource::SwigDirector_VirgilDataSource(JNIEnv *jenv) : virgil::crypto::VirgilDataSource(), Swig::Director(jenv) {
}

bool SwigDirector_VirgilDataSource::hasData() {
  bool c_result = SwigValueInit< bool >() ;
  jboolean jresult = 0 ;
  JNIEnvWrapper swigjnienv(this) ;
  JNIEnv * jenv = swigjnienv.getJNIEnv() ;
  jobject swigjobj = (jobject) NULL ;
  
  if (!swig_override[0]) {
    SWIG_JavaThrowException(JNIEnvWrapper(this).getJNIEnv(), SWIG_JavaDirectorPureVirtual, "Attempted to invoke pure virtual method virgil::crypto::VirgilDataSource::hasData.");
    return c_result;
  }
  swigjobj = swig_get_self(jenv);
  if (swigjobj && jenv->IsSameObject(swigjobj, NULL) == JNI_FALSE) {
    jresult = (jboolean) jenv->CallStaticBooleanMethod(Swig::jclass_virgil_crypto_javaJNI, Swig::director_methids[0], swigjobj);
    if (jenv->ExceptionCheck() == JNI_TRUE) return c_result;
    c_result = jresult ? true : false; 
  } else {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null upcall object");
  }
  if (swigjobj) jenv->DeleteLocalRef(swigjobj);
  return c_result;
}

virgil::crypto::VirgilByteArray SwigDirector_VirgilDataSource::read() {
  virgil::crypto::VirgilByteArray c_result ;
  jbyteArray jresult = 0 ;
  JNIEnvWrapper swigjnienv(this) ;
  JNIEnv * jenv = swigjnienv.getJNIEnv() ;
  jobject swigjobj = (jobject) NULL ;
  
  if (!swig_override[1]) {
    SWIG_JavaThrowException(JNIEnvWrapper(this).getJNIEnv(), SWIG_JavaDirectorPureVirtual, "Attempted to invoke pure virtual method virgil::crypto::VirgilDataSource::read.");
    return c_result;
  }
  swigjobj = swig_get_self(jenv);
  if (swigjobj && jenv->IsSameObject(swigjobj, NULL) == JNI_FALSE) {
    jresult = (jbyteArray) jenv->CallStaticObjectMethod(Swig::jclass_virgil_crypto_javaJNI, Swig::director_methids[1], swigjobj);
    if (jenv->ExceptionCheck() == JNI_TRUE) return c_result;
    if(!jresult) {
      if (!jenv->ExceptionCheck()) {
        SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
      }
      return c_result;
    }
    Swig::LocalRefGuard jresult_guard(jenv, jresult);
    jbyte *c_result_pdata = (jbyte *)jenv->GetByteArrayElements(jresult, 0);
    size_t c_result_size = (size_t)jenv->GetArrayLength(jresult);
    if (!c_result_pdata) return c_result;
    c_result.assign(c_result_pdata, c_result_pdata + c_result_size);
    jenv->ReleaseByteArrayElements(jresult, c_result_pdata, 0);
    
  } else {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null upcall object");
  }
  if (swigjobj) jenv->DeleteLocalRef(swigjobj);
  return c_result;
}

SwigDirector_VirgilDataSource::~SwigDirector_VirgilDataSource() throw () {
  swig_disconnect_director_self("swigDirectorDisconnect");
}


void SwigDirector_VirgilDataSource::swig_connect_director(JNIEnv *jenv, jobject jself, jclass jcls, bool swig_mem_own, bool weak_global) {
  static struct {
    const char *mname;
    const char *mdesc;
    jmethodID base_methid;
  } methods[] = {
    {
      "hasData", "()Z", NULL 
    },
    {
      "read", "()[B", NULL 
    }
  };
  
  static jclass baseclass = 0 ;
  
  if (swig_set_self(jenv, jself, swig_mem_own, weak_global)) {
    if (!baseclass) {
      baseclass = jenv->FindClass("com/virgilsecurity/crypto/VirgilDataSource");
      if (!baseclass) return;
      baseclass = (jclass) jenv->NewGlobalRef(baseclass);
    }
    bool derived = (jenv->IsSameObject(baseclass, jcls) ? false : true);
    for (int i = 0; i < 2; ++i) {
      if (!methods[i].base_methid) {
        methods[i].base_methid = jenv->GetMethodID(baseclass, methods[i].mname, methods[i].mdesc);
        if (!methods[i].base_methid) return;
      }
      swig_override[i] = false;
      if (derived) {
        jmethodID methid = jenv->GetMethodID(jcls, methods[i].mname, methods[i].mdesc);
        swig_override[i] = (methid != methods[i].base_methid);
        jenv->ExceptionClear();
      }
    }
  }
}


SwigDirector_VirgilDataSink::SwigDirector_VirgilDataSink(JNIEnv *jenv) : virgil::crypto::VirgilDataSink(), Swig::Director(jenv) {
}

bool SwigDirector_VirgilDataSink::isGood() {
  bool c_result = SwigValueInit< bool >() ;
  jboolean jresult = 0 ;
  JNIEnvWrapper swigjnienv(this) ;
  JNIEnv * jenv = swigjnienv.getJNIEnv() ;
  jobject swigjobj = (jobject) NULL ;
  
  if (!swig_override[0]) {
    SWIG_JavaThrowException(JNIEnvWrapper(this).getJNIEnv(), SWIG_JavaDirectorPureVirtual, "Attempted to invoke pure virtual method virgil::crypto::VirgilDataSink::isGood.");
    return c_result;
  }
  swigjobj = swig_get_self(jenv);
  if (swigjobj && jenv->IsSameObject(swigjobj, NULL) == JNI_FALSE) {
    jresult = (jboolean) jenv->CallStaticBooleanMethod(Swig::jclass_virgil_crypto_javaJNI, Swig::director_methids[2], swigjobj);
    if (jenv->ExceptionCheck() == JNI_TRUE) return c_result;
    c_result = jresult ? true : false; 
  } else {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null upcall object");
  }
  if (swigjobj) jenv->DeleteLocalRef(swigjobj);
  return c_result;
}

void SwigDirector_VirgilDataSink::write(virgil::crypto::VirgilByteArray const &data) {
  JNIEnvWrapper swigjnienv(this) ;
  JNIEnv * jenv = swigjnienv.getJNIEnv() ;
  jobject swigjobj = (jobject) NULL ;
  jbyteArray jdata = 0 ;
  
  if (!swig_override[1]) {
    SWIG_JavaThrowException(JNIEnvWrapper(this).getJNIEnv(), SWIG_JavaDirectorPureVirtual, "Attempted to invoke pure virtual method virgil::crypto::VirgilDataSink::write.");
    return;
  }
  swigjobj = swig_get_self(jenv);
  if (swigjobj && jenv->IsSameObject(swigjobj, NULL) == JNI_FALSE) {
    jdata = jenv->NewByteArray((&data)->size());
    jenv->SetByteArrayRegion(jdata, 0, (&data)->size(), (const jbyte *)&data[0]);
    Swig::LocalRefGuard data_refguard(jenv, jdata);
    
    jenv->CallStaticVoidMethod(Swig::jclass_virgil_crypto_javaJNI, Swig::director_methids[3], swigjobj, jdata);
    if (jenv->ExceptionCheck() == JNI_TRUE) return ;
  } else {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null upcall object");
  }
  if (swigjobj) jenv->DeleteLocalRef(swigjobj);
}

SwigDirector_VirgilDataSink::~SwigDirector_VirgilDataSink() throw () {
  swig_disconnect_director_self("swigDirectorDisconnect");
}


void SwigDirector_VirgilDataSink::swig_connect_director(JNIEnv *jenv, jobject jself, jclass jcls, bool swig_mem_own, bool weak_global) {
  static struct {
    const char *mname;
    const char *mdesc;
    jmethodID base_methid;
  } methods[] = {
    {
      "isGood", "()Z", NULL 
    },
    {
      "write", "([B)V", NULL 
    }
  };
  
  static jclass baseclass = 0 ;
  
  if (swig_set_self(jenv, jself, swig_mem_own, weak_global)) {
    if (!baseclass) {
      baseclass = jenv->FindClass("com/virgilsecurity/crypto/VirgilDataSink");
      if (!baseclass) return;
      baseclass = (jclass) jenv->NewGlobalRef(baseclass);
    }
    bool derived = (jenv->IsSameObject(baseclass, jcls) ? false : true);
    for (int i = 0; i < 2; ++i) {
      if (!methods[i].base_methid) {
        methods[i].base_methid = jenv->GetMethodID(baseclass, methods[i].mname, methods[i].mdesc);
        if (!methods[i].base_methid) return;
      }
      swig_override[i] = false;
      if (derived) {
        jmethodID methid = jenv->GetMethodID(jcls, methods[i].mname, methods[i].mdesc);
        swig_override[i] = (methid != methods[i].base_methid);
        jenv->ExceptionClear();
      }
    }
  }
}



#ifdef __cplusplus
extern "C" {
#endif

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilVersion_1asNumber(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilVersion::asNumber();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jstring JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilVersion_1asString(JNIEnv *jenv, jclass jcls) {
  jstring jresult = 0 ;
  std::string result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilVersion::asString();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = jenv->NewStringUTF((&result)->c_str()); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilVersion_1majorVersion(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilVersion::majorVersion();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilVersion_1minorVersion(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilVersion::minorVersion();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilVersion_1patchVersion(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilVersion::patchVersion();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jstring JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilVersion_1fullName(JNIEnv *jenv, jclass jcls) {
  jstring jresult = 0 ;
  std::string result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilVersion::fullName();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = jenv->NewStringUTF((&result)->c_str()); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilVersion(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilVersion *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilVersion *)new virgil::crypto::VirgilVersion();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilVersion **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilVersion(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilVersion *arg1 = (virgil::crypto::VirgilVersion *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilVersion **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilDataSource_1hasData(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilDataSource *arg1 = (virgil::crypto::VirgilDataSource *) 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilDataSource **)&jarg1; 
  {
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilDataSource_1read(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilDataSource *arg1 = (virgil::crypto::VirgilDataSource *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilDataSource **)&jarg1; 
  {
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilDataSource(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilDataSource *arg1 = (virgil::crypto::VirgilDataSource *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilDataSource **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilDataSource(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilDataSource *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilDataSource *)new SwigDirector_VirgilDataSource(jenv);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilDataSource **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilDataSource_1director_1connect(JNIEnv *jenv, jclass jcls, jobject jself, jlong objarg, jboolean jswig_mem_own, jboolean jweak_global) {
  virgil::crypto::VirgilDataSource *obj = *((virgil::crypto::VirgilDataSource **)&objarg);
  (void)jcls;
  SwigDirector_VirgilDataSource *director = dynamic_cast<SwigDirector_VirgilDataSource *>(obj);
  if (director) {
    director->swig_connect_director(jenv, jself, jenv->GetObjectClass(jself), (jswig_mem_own == JNI_TRUE), (jweak_global == JNI_TRUE));
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilDataSource_1change_1ownership(JNIEnv *jenv, jclass jcls, jobject jself, jlong objarg, jboolean jtake_or_release) {
  virgil::crypto::VirgilDataSource *obj = *((virgil::crypto::VirgilDataSource **)&objarg);
  SwigDirector_VirgilDataSource *director = dynamic_cast<SwigDirector_VirgilDataSource *>(obj);
  (void)jcls;
  if (director) {
    director->swig_java_change_ownership(jenv, jself, jtake_or_release ? true : false);
  }
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilDataSink_1isGood(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilDataSink *arg1 = (virgil::crypto::VirgilDataSink *) 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilDataSink **)&jarg1; 
  {
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilDataSink_1write(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::VirgilDataSink *arg1 = (virgil::crypto::VirgilDataSink *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilDataSink **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilDataSink(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilDataSink *arg1 = (virgil::crypto::VirgilDataSink *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilDataSink **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilDataSink(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilDataSink *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilDataSink *)new SwigDirector_VirgilDataSink(jenv);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilDataSink **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilDataSink_1director_1connect(JNIEnv *jenv, jclass jcls, jobject jself, jlong objarg, jboolean jswig_mem_own, jboolean jweak_global) {
  virgil::crypto::VirgilDataSink *obj = *((virgil::crypto::VirgilDataSink **)&objarg);
  (void)jcls;
  SwigDirector_VirgilDataSink *director = dynamic_cast<SwigDirector_VirgilDataSink *>(obj);
  if (director) {
    director->swig_connect_director(jenv, jself, jenv->GetObjectClass(jself), (jswig_mem_own == JNI_TRUE), (jweak_global == JNI_TRUE));
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilDataSink_1change_1ownership(JNIEnv *jenv, jclass jcls, jobject jself, jlong objarg, jboolean jtake_or_release) {
  virgil::crypto::VirgilDataSink *obj = *((virgil::crypto::VirgilDataSink **)&objarg);
  SwigDirector_VirgilDataSink *director = dynamic_cast<SwigDirector_VirgilDataSink *>(obj);
  (void)jcls;
  if (director) {
    director->swig_java_change_ownership(jenv, jself, jtake_or_release ? true : false);
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Compatible_1toAsn1(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Compatible *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Compatible *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::asn1::VirgilAsn1Compatible const *)arg1)->toAsn1();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Compatible_1fromAsn1(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::asn1::VirgilAsn1Compatible *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Compatible *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->fromAsn1((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilAsn1Compatible(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::asn1::VirgilAsn1Compatible *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Compatible *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1md5(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilHash result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::foundation::VirgilHash::md5();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::foundation::VirgilHash **)&jresult = new virgil::crypto::foundation::VirgilHash((const virgil::crypto::foundation::VirgilHash &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1sha256(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilHash result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::foundation::VirgilHash::sha256();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::foundation::VirgilHash **)&jresult = new virgil::crypto::foundation::VirgilHash((const virgil::crypto::foundation::VirgilHash &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1sha384(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilHash result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::foundation::VirgilHash::sha384();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::foundation::VirgilHash **)&jresult = new virgil::crypto::foundation::VirgilHash((const virgil::crypto::foundation::VirgilHash &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1sha512(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilHash result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::foundation::VirgilHash::sha512();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::foundation::VirgilHash **)&jresult = new virgil::crypto::foundation::VirgilHash((const virgil::crypto::foundation::VirgilHash &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1withName(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::foundation::VirgilHash result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::foundation::VirgilHash::withName((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::foundation::VirgilHash **)&jresult = new virgil::crypto::foundation::VirgilHash((const virgil::crypto::foundation::VirgilHash &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilHash_1_1SWIG_10(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::foundation::VirgilHash *)new virgil::crypto::foundation::VirgilHash();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::foundation::VirgilHash **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilHash(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jstring JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1name(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jstring jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  std::string result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilHash const *)arg1)->name();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = jenv->NewStringUTF((&result)->c_str()); 
  return jresult;
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1type(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jint jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  int result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  {
    try {
      result = (int)((virgil::crypto::foundation::VirgilHash const *)arg1)->type();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1hash(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = ((virgil::crypto::foundation::VirgilHash const *)arg1)->hash((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1start(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  {
    try {
      (arg1)->start();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1update(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->update((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1finish(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  {
    try {
      result = (arg1)->finish();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1hmac(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = ((virgil::crypto::foundation::VirgilHash const *)arg1)->hmac((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1hmacStart(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->hmacStart((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1hmacReset(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  {
    try {
      (arg1)->hmacReset();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1hmacUpdate(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->hmacUpdate((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1hmacFinish(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  {
    try {
      result = (arg1)->hmacFinish();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilHash_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *arg1 = 0 ;
  virgil::crypto::foundation::VirgilHash *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::foundation::VirgilHash const & reference is null");
    return 0;
  } 
  {
    try {
      result = (virgil::crypto::foundation::VirgilHash *)new virgil::crypto::foundation::VirgilHash((virgil::crypto::foundation::VirgilHash const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::foundation::VirgilHash **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jstring JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilBase64_1encode(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jstring jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  std::string result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::foundation::VirgilBase64::encode((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = jenv->NewStringUTF((&result)->c_str()); 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilBase64_1decode(JNIEnv *jenv, jclass jcls, jstring jarg1) {
  jbyteArray jresult = 0 ;
  std::string *arg1 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null string");
    return 0;
  }
  const char *arg1_pstr = (const char *)jenv->GetStringUTFChars(jarg1, 0); 
  if (!arg1_pstr) return 0;
  std::string arg1_str(arg1_pstr);
  arg1 = &arg1_str;
  jenv->ReleaseStringUTFChars(jarg1, arg1_pstr); 
  {
    try {
      result = virgil::crypto::foundation::VirgilBase64::decode((std::string const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilBase64(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilBase64 *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::foundation::VirgilBase64 *)new virgil::crypto::foundation::VirgilBase64();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::foundation::VirgilBase64 **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilBase64(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::VirgilBase64 *arg1 = (virgil::crypto::foundation::VirgilBase64 *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::VirgilBase64 **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1kIterationCount_1Default_1get(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  unsigned int result;
  
  (void)jenv;
  (void)jcls;
  result = (unsigned int)virgil::crypto::foundation::VirgilPBKDF::kIterationCount_Default;
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1None_1get(JNIEnv *jenv, jclass jcls) {
  jint jresult = 0 ;
  virgil::crypto::foundation::VirgilPBKDF::Algorithm result;
  
  (void)jenv;
  (void)jcls;
  result = (virgil::crypto::foundation::VirgilPBKDF::Algorithm)virgil::crypto::foundation::VirgilPBKDF::Algorithm_None;
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1SHA1_1get(JNIEnv *jenv, jclass jcls) {
  jint jresult = 0 ;
  virgil::crypto::foundation::VirgilPBKDF::Hash result;
  
  (void)jenv;
  (void)jcls;
  result = (virgil::crypto::foundation::VirgilPBKDF::Hash)virgil::crypto::foundation::VirgilPBKDF::Hash_SHA1;
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPBKDF_1_1SWIG_10(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilPBKDF *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::foundation::VirgilPBKDF *)new virgil::crypto::foundation::VirgilPBKDF();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::foundation::VirgilPBKDF **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPBKDF_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jlong jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  unsigned int arg2 ;
  virgil::crypto::foundation::VirgilPBKDF *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  arg2 = (unsigned int)jarg2; 
  {
    try {
      result = (virgil::crypto::foundation::VirgilPBKDF *)new virgil::crypto::foundation::VirgilPBKDF((virgil::crypto::VirgilByteArray const &)*arg1,arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::foundation::VirgilPBKDF **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPBKDF_1_1SWIG_12(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::foundation::VirgilPBKDF *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = (virgil::crypto::foundation::VirgilPBKDF *)new virgil::crypto::foundation::VirgilPBKDF((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::foundation::VirgilPBKDF **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilPBKDF(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1getSalt(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilPBKDF const *)arg1)->getSalt();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1getIterationCount(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  unsigned int result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  {
    try {
      result = (unsigned int)((virgil::crypto::foundation::VirgilPBKDF const *)arg1)->getIterationCount();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1setAlgorithm(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jint jarg2) {
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  virgil::crypto::foundation::VirgilPBKDF::Algorithm arg2 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  arg2 = (virgil::crypto::foundation::VirgilPBKDF::Algorithm)jarg2; 
  {
    try {
      (arg1)->setAlgorithm(arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1getAlgorithm(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jint jresult = 0 ;
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  virgil::crypto::foundation::VirgilPBKDF::Algorithm result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  {
    try {
      result = (virgil::crypto::foundation::VirgilPBKDF::Algorithm)((virgil::crypto::foundation::VirgilPBKDF const *)arg1)->getAlgorithm();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1setHash(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jint jarg2) {
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  virgil::crypto::foundation::VirgilPBKDF::Hash arg2 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  arg2 = (virgil::crypto::foundation::VirgilPBKDF::Hash)jarg2; 
  {
    try {
      (arg1)->setHash(arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1getHash(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jint jresult = 0 ;
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  virgil::crypto::foundation::VirgilPBKDF::Hash result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  {
    try {
      result = (virgil::crypto::foundation::VirgilPBKDF::Hash)((virgil::crypto::foundation::VirgilPBKDF const *)arg1)->getHash();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1enableRecommendationsCheck(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  {
    try {
      (arg1)->enableRecommendationsCheck();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1disableRecommendationsCheck(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  {
    try {
      (arg1)->disableRecommendationsCheck();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1derive_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jlong jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  size_t arg3 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  arg3 = (size_t)jarg3; 
  {
    try {
      result = (arg1)->derive((virgil::crypto::VirgilByteArray const &)*arg2,arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1derive_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (arg1)->derive((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilRandom(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::foundation::VirgilRandom *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = (virgil::crypto::foundation::VirgilRandom *)new virgil::crypto::foundation::VirgilRandom((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::foundation::VirgilRandom **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilRandom_1randomize_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilRandom *arg1 = (virgil::crypto::foundation::VirgilRandom *) 0 ;
  size_t arg2 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilRandom **)&jarg1; 
  arg2 = (size_t)jarg2; 
  {
    try {
      result = (arg1)->randomize(arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilRandom_1randomize_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilRandom *arg1 = (virgil::crypto::foundation::VirgilRandom *) 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilRandom **)&jarg1; 
  {
    try {
      result = (arg1)->randomize();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilRandom_1randomize_1_1SWIG_12(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jlong jarg3) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilRandom *arg1 = (virgil::crypto::foundation::VirgilRandom *) 0 ;
  size_t arg2 ;
  size_t arg3 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilRandom **)&jarg1; 
  arg2 = (size_t)jarg2; 
  arg3 = (size_t)jarg3; 
  {
    try {
      result = (arg1)->randomize(arg2,arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilRandom(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::VirgilRandom *arg1 = (virgil::crypto::foundation::VirgilRandom *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::VirgilRandom **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1isEmpty(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  {
    try {
      result = (bool)((virgil::crypto::VirgilCustomParams const *)arg1)->isEmpty();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1setInteger(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jint jarg3) {
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  int arg3 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  arg3 = (int)jarg3; 
  {
    try {
      (arg1)->setInteger((virgil::crypto::VirgilByteArray const &)*arg2,arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1getInteger(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jint jresult = 0 ;
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  int result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (int)((virgil::crypto::VirgilCustomParams const *)arg1)->getInteger((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1removeInteger(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->removeInteger((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1setString(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return ;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      (arg1)->setString((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1getString(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = ((virgil::crypto::VirgilCustomParams const *)arg1)->getString((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1removeString(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->removeString((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1setData(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return ;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      (arg1)->setData((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1getData(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = ((virgil::crypto::VirgilCustomParams const *)arg1)->getData((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1removeData(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->removeData((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1clear(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  {
    try {
      (arg1)->clear();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilCustomParams(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCustomParams_1_1SWIG_10(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilCustomParams *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilCustomParams *)new virgil::crypto::VirgilCustomParams();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilCustomParams **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCustomParams_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilCustomParams *arg1 = 0 ;
  virgil::crypto::VirgilCustomParams *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilCustomParams const & reference is null");
    return 0;
  } 
  {
    try {
      result = (virgil::crypto::VirgilCustomParams *)new virgil::crypto::VirgilCustomParams((virgil::crypto::VirgilCustomParams const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilCustomParams **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1Default_1get(JNIEnv *jenv, jclass jcls) {
  jint jresult = 0 ;
  virgil::crypto::VirgilKeyPair::Type result;
  
  (void)jenv;
  (void)jcls;
  result = (virgil::crypto::VirgilKeyPair::Type)virgil::crypto::VirgilKeyPair::Type_Default;
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1EC_1Curve25519_1get(JNIEnv *jenv, jclass jcls) {
  jint jresult = 0 ;
  virgil::crypto::VirgilKeyPair::Type result;
  
  (void)jenv;
  (void)jcls;
  result = (virgil::crypto::VirgilKeyPair::Type)virgil::crypto::VirgilKeyPair::Type_EC_Curve25519;
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1generate_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jint jarg1, jbyteArray jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair::Type arg1 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  arg1 = (virgil::crypto::VirgilKeyPair::Type)jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::generate(arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1generate_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jint jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair::Type arg1 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  arg1 = (virgil::crypto::VirgilKeyPair::Type)jarg1; 
  {
    try {
      result = virgil::crypto::VirgilKeyPair::generate(arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1generate_1_1SWIG_12(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilKeyPair::generate();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1generateFrom_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilKeyPair **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilKeyPair const & reference is null");
    return 0;
  } 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::generateFrom((virgil::crypto::VirgilKeyPair const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1generateFrom_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilKeyPair **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilKeyPair const & reference is null");
    return 0;
  } 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::generateFrom((virgil::crypto::VirgilKeyPair const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1generateFrom_1_1SWIG_12(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilKeyPair **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilKeyPair const & reference is null");
    return 0;
  } 
  {
    try {
      result = virgil::crypto::VirgilKeyPair::generateFrom((virgil::crypto::VirgilKeyPair const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecNist192_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecNist192((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecNist192_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecNist192();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecNist224_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecNist224((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecNist224_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecNist224();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecNist256_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecNist256((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecNist256_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecNist256();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecNist384_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecNist384((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecNist384_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecNist384();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecNist521_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecNist521((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecNist521_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecNist521();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecBrainpool256_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecBrainpool256((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecBrainpool256_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecBrainpool256();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecBrainpool384_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecBrainpool384((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecBrainpool384_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecBrainpool384();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecBrainpool512_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecBrainpool512((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecBrainpool512_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecBrainpool512();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecKoblitz192_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecKoblitz192((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecKoblitz192_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecKoblitz192();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecKoblitz224_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecKoblitz224((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecKoblitz224_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecKoblitz224();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecKoblitz256_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecKoblitz256((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1ecKoblitz256_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilKeyPair::ecKoblitz256();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1rsa256_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::rsa256((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1rsa256_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilKeyPair::rsa256();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1rsa512_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::rsa512((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1rsa512_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilKeyPair::rsa512();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1rsa1024_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::rsa1024((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1rsa1024_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilKeyPair::rsa1024();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1rsa2048_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::rsa2048((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1rsa2048_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilKeyPair::rsa2048();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1rsa4096_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::rsa4096((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1rsa4096_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilKeyPair::rsa4096();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1isKeyPairMatch_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2, jbyteArray jarg3) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = (bool)virgil::crypto::VirgilKeyPair::isKeyPairMatch((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1isKeyPairMatch_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (bool)virgil::crypto::VirgilKeyPair::isKeyPairMatch((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1checkPrivateKeyPassword(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (bool)virgil::crypto::VirgilKeyPair::checkPrivateKeyPassword((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1isPrivateKeyEncrypted(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = (bool)virgil::crypto::VirgilKeyPair::isPrivateKeyEncrypted((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1resetPrivateKeyPassword(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::resetPrivateKeyPassword((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1extractPublicKey(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::extractPublicKey((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilKeyPair_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = (virgil::crypto::VirgilKeyPair *)new virgil::crypto::VirgilKeyPair((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilKeyPair_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilKeyPair *)new virgil::crypto::VirgilKeyPair();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilKeyPair_1_1SWIG_12(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilKeyPair *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (virgil::crypto::VirgilKeyPair *)new virgil::crypto::VirgilKeyPair((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1publicKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilKeyPair *arg1 = (virgil::crypto::VirgilKeyPair *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilKeyPair **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::VirgilKeyPair const *)arg1)->publicKey();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1privateKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilKeyPair *arg1 = (virgil::crypto::VirgilKeyPair *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilKeyPair **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::VirgilKeyPair const *)arg1)->privateKey();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilKeyPair_1_1SWIG_13(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilKeyPair **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilKeyPair const & reference is null");
    return 0;
  } 
  {
    try {
      result = (virgil::crypto::VirgilKeyPair *)new virgil::crypto::VirgilKeyPair((virgil::crypto::VirgilKeyPair const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilKeyPair(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilKeyPair *arg1 = (virgil::crypto::VirgilKeyPair *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilKeyPair **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCipherBase(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilCipherBase *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilCipherBase *)new virgil::crypto::VirgilCipherBase();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilCipherBase **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilCipherBase(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1addKeyRecipient(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return ;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      (arg1)->addKeyRecipient((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1removeKeyRecipient(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->removeKeyRecipient((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1keyRecipientExists(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (bool)((virgil::crypto::VirgilCipherBase const *)arg1)->keyRecipientExists((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1addPasswordRecipient(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->addPasswordRecipient((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1removePasswordRecipient(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->removePasswordRecipient((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1removeAllRecipients(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  {
    try {
      (arg1)->removeAllRecipients();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1getContentInfo(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::VirgilCipherBase const *)arg1)->getContentInfo();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1setContentInfo(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->setContentInfo((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1defineContentInfoSize(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilCipherBase::defineContentInfoSize((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1customParams_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  virgil::crypto::VirgilCustomParams *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  {
    try {
      result = (virgil::crypto::VirgilCustomParams *) &(arg1)->customParams();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilCustomParams **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1computeShared_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilCipherBase::computeShared((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1computeShared_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilCipherBase::computeShared((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilCipher(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilCipher *arg1 = (virgil::crypto::VirgilCipher *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilCipher **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipher_1encrypt_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jboolean jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilCipher *arg1 = (virgil::crypto::VirgilCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  bool arg3 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  arg3 = jarg3 ? true : false; 
  {
    try {
      result = (arg1)->encrypt((virgil::crypto::VirgilByteArray const &)*arg2,arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipher_1encrypt_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilCipher *arg1 = (virgil::crypto::VirgilCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (arg1)->encrypt((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipher_1decryptWithKey_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3, jbyteArray jarg4, jbyteArray jarg5) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilCipher *arg1 = (virgil::crypto::VirgilCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::VirgilByteArray *arg5 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  if(!jarg5) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg5_pdata = (jbyte *)jenv->GetByteArrayElements(jarg5, 0);
  size_t arg5_size = (size_t)jenv->GetArrayLength(jarg5);
  if (!arg5_pdata) return 0;
  virgil::crypto::VirgilByteArray arg5_data(arg5_pdata, arg5_pdata + arg5_size);
  arg5 = &arg5_data;
  jenv->ReleaseByteArrayElements(jarg5, arg5_pdata, 0);
  
  {
    try {
      result = (arg1)->decryptWithKey((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4,(virgil::crypto::VirgilByteArray const &)*arg5);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipher_1decryptWithKey_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3, jbyteArray jarg4) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilCipher *arg1 = (virgil::crypto::VirgilCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      result = (arg1)->decryptWithKey((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipher_1decryptWithPassword(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilCipher *arg1 = (virgil::crypto::VirgilCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = (arg1)->decryptWithPassword((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCipher(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilCipher *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilCipher *)new virgil::crypto::VirgilCipher();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilCipher **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilChunkCipher_1kPreferredChunkSize_1get(JNIEnv *jenv, jclass jcls) {
  jint jresult = 0 ;
  int result;
  
  (void)jenv;
  (void)jcls;
  result = (int)virgil::crypto::VirgilChunkCipher::kPreferredChunkSize;
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilChunkCipher_1startEncryption_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilChunkCipher *arg1 = (virgil::crypto::VirgilChunkCipher *) 0 ;
  size_t arg2 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilChunkCipher **)&jarg1; 
  arg2 = (size_t)jarg2; 
  {
    try {
      result = (arg1)->startEncryption(arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilChunkCipher_1startEncryption_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilChunkCipher *arg1 = (virgil::crypto::VirgilChunkCipher *) 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilChunkCipher **)&jarg1; 
  {
    try {
      result = (arg1)->startEncryption();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilChunkCipher_1startDecryptionWithKey_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3, jbyteArray jarg4) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilChunkCipher *arg1 = (virgil::crypto::VirgilChunkCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilChunkCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      result = (arg1)->startDecryptionWithKey((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilChunkCipher_1startDecryptionWithKey_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilChunkCipher *arg1 = (virgil::crypto::VirgilChunkCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilChunkCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = (arg1)->startDecryptionWithKey((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilChunkCipher_1startDecryptionWithPassword(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilChunkCipher *arg1 = (virgil::crypto::VirgilChunkCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilChunkCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (arg1)->startDecryptionWithPassword((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilChunkCipher_1process(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilChunkCipher *arg1 = (virgil::crypto::VirgilChunkCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilChunkCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (arg1)->process((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilChunkCipher_1finish(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  virgil::crypto::VirgilChunkCipher *arg1 = (virgil::crypto::VirgilChunkCipher *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilChunkCipher **)&jarg1; 
  {
    try {
      (arg1)->finish();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilChunkCipher(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilChunkCipher *arg1 = (virgil::crypto::VirgilChunkCipher *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilChunkCipher **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilChunkCipher(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilChunkCipher *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilChunkCipher *)new virgil::crypto::VirgilChunkCipher();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilChunkCipher **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilSigner_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *arg1 = 0 ;
  virgil::crypto::VirgilSigner *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::foundation::VirgilHash const & reference is null");
    return 0;
  } 
  {
    try {
      result = (virgil::crypto::VirgilSigner *)new virgil::crypto::VirgilSigner((virgil::crypto::foundation::VirgilHash const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilSigner **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilSigner_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilSigner *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilSigner *)new virgil::crypto::VirgilSigner();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilSigner **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSigner_1sign_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3, jbyteArray jarg4) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilSigner *arg1 = (virgil::crypto::VirgilSigner *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilSigner **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      result = (arg1)->sign((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSigner_1sign_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilSigner *arg1 = (virgil::crypto::VirgilSigner *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilSigner **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = (arg1)->sign((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSigner_1verify(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3, jbyteArray jarg4) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilSigner *arg1 = (virgil::crypto::VirgilSigner *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilSigner **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      result = (bool)(arg1)->verify((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilSigner(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilSigner *arg1 = (virgil::crypto::VirgilSigner *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilSigner **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilStreamSigner_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *arg1 = 0 ;
  virgil::crypto::VirgilStreamSigner *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::foundation::VirgilHash const & reference is null");
    return 0;
  } 
  {
    try {
      result = (virgil::crypto::VirgilStreamSigner *)new virgil::crypto::VirgilStreamSigner((virgil::crypto::foundation::VirgilHash const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilStreamSigner **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilStreamSigner_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilStreamSigner *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilStreamSigner *)new virgil::crypto::VirgilStreamSigner();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilStreamSigner **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilStreamSigner_1sign_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jbyteArray jarg3, jbyteArray jarg4) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilStreamSigner *arg1 = (virgil::crypto::VirgilStreamSigner *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  arg1 = *(virgil::crypto::VirgilStreamSigner **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return 0;
  } 
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      result = (arg1)->sign(*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilStreamSigner_1sign_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilStreamSigner *arg1 = (virgil::crypto::VirgilStreamSigner *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  arg1 = *(virgil::crypto::VirgilStreamSigner **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return 0;
  } 
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = (arg1)->sign(*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilStreamSigner_1verify(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jbyteArray jarg3, jbyteArray jarg4) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilStreamSigner *arg1 = (virgil::crypto::VirgilStreamSigner *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  arg1 = *(virgil::crypto::VirgilStreamSigner **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return 0;
  } 
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      result = (bool)(arg1)->verify(*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilStreamSigner(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilStreamSigner *arg1 = (virgil::crypto::VirgilStreamSigner *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilStreamSigner **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilStreamCipher(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilStreamCipher *arg1 = (virgil::crypto::VirgilStreamCipher *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilStreamCipher **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilStreamCipher_1encrypt_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_, jboolean jarg4) {
  virgil::crypto::VirgilStreamCipher *arg1 = (virgil::crypto::VirgilStreamCipher *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilDataSink *arg3 = 0 ;
  bool arg4 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::VirgilStreamCipher **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return ;
  } 
  arg3 = *(virgil::crypto::VirgilDataSink **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSink & reference is null");
    return ;
  } 
  arg4 = jarg4 ? true : false; 
  {
    try {
      (arg1)->encrypt(*arg2,*arg3,arg4);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilStreamCipher_1encrypt_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_) {
  virgil::crypto::VirgilStreamCipher *arg1 = (virgil::crypto::VirgilStreamCipher *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilDataSink *arg3 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::VirgilStreamCipher **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return ;
  } 
  arg3 = *(virgil::crypto::VirgilDataSink **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSink & reference is null");
    return ;
  } 
  {
    try {
      (arg1)->encrypt(*arg2,*arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilStreamCipher_1decryptWithKey_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_, jbyteArray jarg4, jbyteArray jarg5, jbyteArray jarg6) {
  virgil::crypto::VirgilStreamCipher *arg1 = (virgil::crypto::VirgilStreamCipher *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilDataSink *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::VirgilByteArray *arg5 = 0 ;
  virgil::crypto::VirgilByteArray *arg6 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::VirgilStreamCipher **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return ;
  } 
  arg3 = *(virgil::crypto::VirgilDataSink **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSink & reference is null");
    return ;
  } 
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return ;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  if(!jarg5) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg5_pdata = (jbyte *)jenv->GetByteArrayElements(jarg5, 0);
  size_t arg5_size = (size_t)jenv->GetArrayLength(jarg5);
  if (!arg5_pdata) return ;
  virgil::crypto::VirgilByteArray arg5_data(arg5_pdata, arg5_pdata + arg5_size);
  arg5 = &arg5_data;
  jenv->ReleaseByteArrayElements(jarg5, arg5_pdata, 0);
  
  if(!jarg6) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg6_pdata = (jbyte *)jenv->GetByteArrayElements(jarg6, 0);
  size_t arg6_size = (size_t)jenv->GetArrayLength(jarg6);
  if (!arg6_pdata) return ;
  virgil::crypto::VirgilByteArray arg6_data(arg6_pdata, arg6_pdata + arg6_size);
  arg6 = &arg6_data;
  jenv->ReleaseByteArrayElements(jarg6, arg6_pdata, 0);
  
  {
    try {
      (arg1)->decryptWithKey(*arg2,*arg3,(virgil::crypto::VirgilByteArray const &)*arg4,(virgil::crypto::VirgilByteArray const &)*arg5,(virgil::crypto::VirgilByteArray const &)*arg6);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilStreamCipher_1decryptWithKey_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_, jbyteArray jarg4, jbyteArray jarg5) {
  virgil::crypto::VirgilStreamCipher *arg1 = (virgil::crypto::VirgilStreamCipher *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilDataSink *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::VirgilByteArray *arg5 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::VirgilStreamCipher **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return ;
  } 
  arg3 = *(virgil::crypto::VirgilDataSink **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSink & reference is null");
    return ;
  } 
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return ;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  if(!jarg5) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg5_pdata = (jbyte *)jenv->GetByteArrayElements(jarg5, 0);
  size_t arg5_size = (size_t)jenv->GetArrayLength(jarg5);
  if (!arg5_pdata) return ;
  virgil::crypto::VirgilByteArray arg5_data(arg5_pdata, arg5_pdata + arg5_size);
  arg5 = &arg5_data;
  jenv->ReleaseByteArrayElements(jarg5, arg5_pdata, 0);
  
  {
    try {
      (arg1)->decryptWithKey(*arg2,*arg3,(virgil::crypto::VirgilByteArray const &)*arg4,(virgil::crypto::VirgilByteArray const &)*arg5);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilStreamCipher_1decryptWithPassword(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_, jbyteArray jarg4) {
  virgil::crypto::VirgilStreamCipher *arg1 = (virgil::crypto::VirgilStreamCipher *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilDataSink *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::VirgilStreamCipher **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return ;
  } 
  arg3 = *(virgil::crypto::VirgilDataSink **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSink & reference is null");
    return ;
  } 
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return ;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      (arg1)->decryptWithPassword(*arg2,*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilStreamCipher(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilStreamCipher *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilStreamCipher *)new virgil::crypto::VirgilStreamCipher();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilStreamCipher **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1Min_1get(JNIEnv *jenv, jclass jcls) {
  jint jresult = 0 ;
  virgil::crypto::VirgilTinyCipher::PackageSize result;
  
  (void)jenv;
  (void)jcls;
  result = (virgil::crypto::VirgilTinyCipher::PackageSize)virgil::crypto::VirgilTinyCipher::PackageSize_Min;
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1Short_1SMS_1get(JNIEnv *jenv, jclass jcls) {
  jint jresult = 0 ;
  virgil::crypto::VirgilTinyCipher::PackageSize result;
  
  (void)jenv;
  (void)jcls;
  result = (virgil::crypto::VirgilTinyCipher::PackageSize)virgil::crypto::VirgilTinyCipher::PackageSize_Short_SMS;
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1Long_1SMS_1get(JNIEnv *jenv, jclass jcls) {
  jint jresult = 0 ;
  virgil::crypto::VirgilTinyCipher::PackageSize result;
  
  (void)jenv;
  (void)jcls;
  result = (virgil::crypto::VirgilTinyCipher::PackageSize)virgil::crypto::VirgilTinyCipher::PackageSize_Long_SMS;
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilTinyCipher_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  jlong jresult = 0 ;
  size_t arg1 ;
  virgil::crypto::VirgilTinyCipher *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = (size_t)jarg1; 
  {
    try {
      result = (virgil::crypto::VirgilTinyCipher *)new virgil::crypto::VirgilTinyCipher(arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilTinyCipher **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilTinyCipher_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilTinyCipher *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilTinyCipher *)new virgil::crypto::VirgilTinyCipher();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  *(virgil::crypto::VirgilTinyCipher **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1reset(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  {
    try {
      (arg1)->reset();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilTinyCipher(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1encrypt(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return ;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      (arg1)->encrypt((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1encryptAndSign_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3, jbyteArray jarg4, jbyteArray jarg5) {
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::VirgilByteArray *arg5 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return ;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return ;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  if(!jarg5) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg5_pdata = (jbyte *)jenv->GetByteArrayElements(jarg5, 0);
  size_t arg5_size = (size_t)jenv->GetArrayLength(jarg5);
  if (!arg5_pdata) return ;
  virgil::crypto::VirgilByteArray arg5_data(arg5_pdata, arg5_pdata + arg5_size);
  arg5 = &arg5_data;
  jenv->ReleaseByteArrayElements(jarg5, arg5_pdata, 0);
  
  {
    try {
      (arg1)->encryptAndSign((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4,(virgil::crypto::VirgilByteArray const &)*arg5);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1encryptAndSign_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3, jbyteArray jarg4) {
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return ;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return ;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      (arg1)->encryptAndSign((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1getPackageCount(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::VirgilTinyCipher const *)arg1)->getPackageCount();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1getPackage(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  size_t arg2 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  arg2 = (size_t)jarg2; 
  {
    try {
      result = ((virgil::crypto::VirgilTinyCipher const *)arg1)->getPackage(arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1addPackage(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->addPackage((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1isPackagesAccumulated(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  {
    try {
      result = (bool)((virgil::crypto::VirgilTinyCipher const *)arg1)->isPackagesAccumulated();
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1decrypt_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = (arg1)->decrypt((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1decrypt_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (arg1)->decrypt((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1verifyAndDecrypt_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3, jbyteArray jarg4) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      result = (arg1)->verifyAndDecrypt((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1verifyAndDecrypt_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = (arg1)->verifyAndDecrypt((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilByteArrayUtils_1jsonToBytes(JNIEnv *jenv, jclass jcls, jstring jarg1) {
  jbyteArray jresult = 0 ;
  std::string *arg1 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null string");
    return 0;
  }
  const char *arg1_pstr = (const char *)jenv->GetStringUTFChars(jarg1, 0); 
  if (!arg1_pstr) return 0;
  std::string arg1_str(arg1_pstr);
  arg1 = &arg1_str;
  jenv->ReleaseStringUTFChars(jarg1, arg1_pstr); 
  {
    try {
      result = virgil::crypto::VirgilByteArrayUtils::jsonToBytes((std::string const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilByteArrayUtils_1stringToBytes(JNIEnv *jenv, jclass jcls, jstring jarg1) {
  jbyteArray jresult = 0 ;
  std::string *arg1 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null string");
    return 0;
  }
  const char *arg1_pstr = (const char *)jenv->GetStringUTFChars(jarg1, 0); 
  if (!arg1_pstr) return 0;
  std::string arg1_str(arg1_pstr);
  arg1 = &arg1_str;
  jenv->ReleaseStringUTFChars(jarg1, arg1_pstr); 
  {
    try {
      result = virgil::crypto::VirgilByteArrayUtils::stringToBytes((std::string const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jstring JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilByteArrayUtils_1bytesToString(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jstring jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  std::string result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilByteArrayUtils::bytesToString((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = jenv->NewStringUTF((&result)->c_str()); 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilByteArrayUtils_1hexToBytes(JNIEnv *jenv, jclass jcls, jstring jarg1) {
  jbyteArray jresult = 0 ;
  std::string *arg1 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null string");
    return 0;
  }
  const char *arg1_pstr = (const char *)jenv->GetStringUTFChars(jarg1, 0); 
  if (!arg1_pstr) return 0;
  std::string arg1_str(arg1_pstr);
  arg1 = &arg1_str;
  jenv->ReleaseStringUTFChars(jarg1, arg1_pstr); 
  {
    try {
      result = virgil::crypto::VirgilByteArrayUtils::hexToBytes((std::string const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jstring JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilByteArrayUtils_1bytesToHex_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jboolean jarg2) {
  jstring jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  bool arg2 ;
  std::string result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  arg2 = jarg2 ? true : false; 
  {
    try {
      result = virgil::crypto::VirgilByteArrayUtils::bytesToHex((virgil::crypto::VirgilByteArray const &)*arg1,arg2);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = jenv->NewStringUTF((&result)->c_str()); 
  return jresult;
}


SWIGEXPORT jstring JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilByteArrayUtils_1bytesToHex_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jstring jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  std::string result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilByteArrayUtils::bytesToHex((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return 0;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return 0; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return 0; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return 0; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return 0; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return 0; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return 0; 
      };
    }
  }
  jresult = jenv->NewStringUTF((&result)->c_str()); 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilByteArrayUtils(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilByteArrayUtils *arg1 = (virgil::crypto::VirgilByteArrayUtils *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilByteArrayUtils **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (virgil::crypto::VirgilCryptoException &e) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, e.what());
      return ;
    }
    
    /*@SWIG:/usr/share/swig2.0/exception.i,263,SWIG_CATCH_STDEXCEPT@*/  /* catching std::exception  */
    catch (std::invalid_argument& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::domain_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_ValueError, e.what()); return ; 
      };
    } catch (std::overflow_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_OverflowError, e.what()); return ; 
      };
    } catch (std::out_of_range& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::length_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_IndexError, e.what()); return ; 
      };
    } catch (std::runtime_error& e) {
      {
        SWIG_JavaException(jenv, SWIG_RuntimeError, e.what()); return ; 
      };
    } catch (std::exception& e) {
      {
        SWIG_JavaException(jenv, SWIG_SystemError, e.what()); return ; 
      };
    }
    /*@SWIG@*/
    catch (...) {
      {
        SWIG_JavaException(jenv, SWIG_UnknownError, "Unknown exception"); return ; 
      };
    }
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&baseptr = *(virgil::crypto::foundation::VirgilHash **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&baseptr = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&baseptr = *(virgil::crypto::VirgilCustomParams **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipher_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::VirgilCipherBase **)&baseptr = *(virgil::crypto::VirgilCipher **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilChunkCipher_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::VirgilCipherBase **)&baseptr = *(virgil::crypto::VirgilChunkCipher **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilStreamCipher_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::VirgilCipherBase **)&baseptr = *(virgil::crypto::VirgilStreamCipher **)&jarg1;
    return baseptr;
}

SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_swig_1module_1init(JNIEnv *jenv, jclass jcls) {
  int i;
  
  static struct {
    const char *method;
    const char *signature;
  } methods[4] = {
    {
      "SwigDirector_VirgilDataSource_hasData", "(Lcom/virgilsecurity/crypto/VirgilDataSource;)Z" 
    },
    {
      "SwigDirector_VirgilDataSource_read", "(Lcom/virgilsecurity/crypto/VirgilDataSource;)[B" 
    },
    {
      "SwigDirector_VirgilDataSink_isGood", "(Lcom/virgilsecurity/crypto/VirgilDataSink;)Z" 
    },
    {
      "SwigDirector_VirgilDataSink_write", "(Lcom/virgilsecurity/crypto/VirgilDataSink;[B)V" 
    }
  };
  Swig::jclass_virgil_crypto_javaJNI = (jclass) jenv->NewGlobalRef(jcls);
  if (!Swig::jclass_virgil_crypto_javaJNI) return;
  for (i = 0; i < (int) (sizeof(methods)/sizeof(methods[0])); ++i) {
    Swig::director_methids[i] = jenv->GetStaticMethodID(jcls, methods[i].method, methods[i].signature);
    if (!Swig::director_methids[i]) return;
  }
}


#ifdef __cplusplus
}
#endif

