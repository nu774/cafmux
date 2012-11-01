#ifndef _UTIL_H
#define _UTIL_H

#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <string>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <stdexcept>
#include <cerrno>
#include <stdint.h>
#include "strutil.h"

#ifdef _MSC_VER
#ifdef _M_IX86
inline int lrint(double x)
{
    int n;
    _asm {
	fld x
	fistp n
    }
    return n;
}
#else
#include <emmintrin.h>
inline int lrint(double x)
{
    return _mm_cvtsd_si32(_mm_load_sd(&x));
}
#endif
#endif

#if !defined(_MSC_VER) && !defined(__MINGW32__)
inline int _wtoi(const wchar_t *s) { return std::wcstol(s, 0, 10); }
#endif

namespace util {
    template <typename T, size_t size>
    inline size_t sizeof_array(const T (&)[size]) { return size; }

    struct fourcc {
	uint32_t nvalue;
	char svalue[5];
	explicit fourcc(uint32_t v) : nvalue(v)
	{
	    for (int i = 3; i >= 0; --i, v >>= 8)
		svalue[i] = v & 0xff;
	    svalue[4] = 0;
	}
	explicit fourcc(const char *s) : nvalue(0)
	{
	    std::memcpy(svalue, s, 4);
	    svalue[4] = 0;
	    const unsigned char *p = reinterpret_cast<const unsigned char *>(s);
	    nvalue = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
	}
	operator const char *() const { return svalue; }
	operator uint32_t() const { return nvalue; }
    };

    inline
    void *xcalloc(size_t count, size_t size)
    {
	void *memory = std::calloc(count, size);
	if (!memory) throw std::bad_alloc();
	return memory;
    }

    /*
    template <typename ForwardIterator>
    bool is_strict_ordered(ForwardIterator begin, ForwardIterator end)
    {
	if (begin == end)
	    return true;
	for (ForwardIterator it; it = begin, ++begin != end; )
	    if (*it >= *begin)
		return false;
	return true;
    }
    */

    template <typename T>
    class AutoDynaCast {
	T *m_pointer;
    public:
	AutoDynaCast(T *p): m_pointer(p) {}
	template <typename U>
	operator U*() { return dynamic_cast<U*>(m_pointer); }
    };

    inline void check_eof(bool expr)
    {
	if (!expr) throw std::runtime_error("Premature EOF");
    }

    class MemorySink8 {
	char *m_ptr;
    public:
	MemorySink8(void *ptr): m_ptr(reinterpret_cast<char*>(ptr)) {}
	void put(uint32_t value) { *m_ptr++ = value; }
    };

    class MemorySink16LE {
	char *m_ptr;
    public:
	MemorySink16LE(void *ptr): m_ptr(reinterpret_cast<char*>(ptr)) {}
	void put(uint32_t value)
	{
	    *m_ptr++ = value;
	    *m_ptr++ = value >> 8;
	}
    };

    class MemorySink24LE {
	char *m_ptr;
    public:
	MemorySink24LE(void *ptr): m_ptr(reinterpret_cast<char*>(ptr)) {}
	void put(uint32_t value)
	{
	    *m_ptr++ = value;
	    *m_ptr++ = value >> 8;
	    *m_ptr++ = value >> 16;
	}
    };

    class MemorySink32LE {
	char *m_ptr;
    public:
	MemorySink32LE(void *ptr): m_ptr(reinterpret_cast<char*>(ptr)) {}
	void put(uint32_t value)
	{
	    *m_ptr++ = value;
	    *m_ptr++ = value >> 8;
	    *m_ptr++ = value >> 16;
	    *m_ptr++ = value >> 24;
	}
    };

    inline
    uint32_t bitcount(uint32_t bits)
    {
	bits = (bits & 0x55555555) + (bits >> 1 & 0x55555555);
	bits = (bits & 0x33333333) + (bits >> 2 & 0x33333333);
	bits = (bits & 0x0f0f0f0f) + (bits >> 4 & 0x0f0f0f0f);
	bits = (bits & 0x00ff00ff) + (bits >> 8 & 0x00ff00ff);
	return (bits & 0x0000ffff) + (bits >>16 & 0x0000ffff);
    }

    /* XXX: assumes little endian host */
    inline uint16_t l2host16(uint16_t n) { return n; }
    inline uint32_t l2host32(uint32_t n) { return n; }

    inline uint16_t b2host16(uint16_t n)
    {
	return (n >> 8) | (n << 8);
    }
    inline uint32_t b2host32(uint32_t n)
    {
	return (b2host16(n & 0xffff) << 16) | b2host16(n >> 16);
    }
    inline uint64_t b2host64(uint64_t n)
    {
	return (static_cast<uint64_t>(b2host32(n & 0xffffffff)) << 32) |
		b2host32(n >> 32);
    }
    inline uint32_t h2big32(uint32_t n)
    {
	return b2host32(n);
    }

    void bswap16buffer(uint8_t *buffer, size_t size);

    void bswap16buffer(uint8_t *buffer, size_t size);

    void bswap24buffer(uint8_t *buffer, size_t size);

    void bswap32buffer(uint8_t *buffer, size_t size);

    void bswap64buffer(uint8_t *buffer, size_t size);

    inline void throw_crt_error(const std::string &message)
    {
	std::stringstream ss;
	ss << message << ": " << std::strerror(errno);
	throw std::runtime_error(ss.str());
    }

    inline void throw_crt_error(const std::wstring &message)
    {
	std::stringstream ss;
	ss << strutil::w2us(message) << ": " << std::strerror(errno);
	throw std::runtime_error(ss.str());
    }
}

#define CHECKCRT(expr) \
    do { \
	if (expr) { \
	    util::throw_crt_error(#expr); \
	} \
    } while (0)
#endif
