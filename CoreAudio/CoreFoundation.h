#ifndef CoreFoundation_H__
#define CoreFoundation_H__

#include "MacTypes.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef UInt32 CFTypeID;
typedef SInt32 CFIndex;
typedef const void * CFTypeRef;
typedef const struct __CFAllocator * CFAllocatorRef;
typedef const struct __CFString * CFStringRef;
typedef struct __CFString * CFMutableStringRef;
typedef const struct __CFDictionary * CFDictionaryRef;
typedef struct __CFDictionary * CFMutableDictionaryRef;
typedef const struct __CFArray * CFArrayRef;
typedef struct __CFArray * CFMutableArrayRef;
typedef const struct __CFURL * CFURLRef;

typedef struct {
    CFIndex location;
    CFIndex length;
} CFRange;

CFTypeID CFGetTypeID(CFTypeRef cf);
CFTypeRef CFRetain(CFTypeRef cf);
void CFRelease(CFTypeRef cf);

CFTypeID CFStringGetTypeID(void);
CFStringRef CFStringCreateWithCharacters(CFAllocatorRef alloc, const UniChar *chars, CFIndex numChars);
CFIndex CFStringGetLength(CFStringRef theString);
void CFStringGetCharacters(CFStringRef theString, CFRange range, UniChar *buffer);
#define CFSTR(cStr)  __CFStringMakeConstantString("" cStr "")
CFStringRef  __CFStringMakeConstantString(const char *cStr);

CFTypeID CFArrayGetTypeID(void);
CFIndex CFArrayGetCount(CFArrayRef theArray);
const void *CFArrayGetValueAtIndex(CFArrayRef theArray, CFIndex idx);

typedef void (*CFDictionaryApplierFunction)(const void *key, const void *value, void *context);
CFTypeID CFDictionaryGetTypeID(void);
CFIndex CFDictionaryGetCount(CFDictionaryRef theDict);
const void *CFDictionaryGetValue(CFDictionaryRef theDict, const void *key);
void CFDictionaryGetKeysAndValues(CFDictionaryRef theDict, const void **keys, const void **values);
void CFDictionaryApplyFunction(CFDictionaryRef theDict, CFDictionaryApplierFunction applier, void *context);

typedef enum {
    kCFURLPOSIXPathStyle = 0,
    kCFURLHFSPathStyle,
    kCFURLWindowsPathStyle
} CFURLPathStyle;

CFTypeID CFURLGetTypeID(void);
CFURLRef CFURLCreateWithFileSystemPath(CFAllocatorRef allocator, CFStringRef filePath, CFURLPathStyle pathStyle, Boolean isDirectory);

#ifdef __cplusplus
}
#endif

#endif
