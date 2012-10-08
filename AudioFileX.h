#ifndef AudioFileX_H
#define AudioFileX_H

#include <string>
#include <vector>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <stdint.h>
#include "CoreAudio/AudioFile.h"
#include "strutil.h"

#define FOURCC(a,b,c,d) (((a)<<24)|((b)<<16)|((c)<<8)|(d))

typedef std::shared_ptr<const __CFString> CFStringPtr;
typedef std::shared_ptr<const __CFDictionary> CFDictionaryPtr;

class CoreAudioException: public std::runtime_error
{
    long m_error_code;
public:
    CoreAudioException(const std::string &s, long code)
	: std::runtime_error(s)
    {
	m_error_code = code;
    }
    long code() const { return m_error_code; }
};

#define CHECKCA(expr) \
    do { \
	long err = expr; \
	if (err) { \
	    std::string msg = afutil::make_coreaudio_error(err, #expr); \
	    std::stringstream ss; \
	    ss << err << ": " << #expr; \
	    throw CoreAudioException(msg, err); \
	} \
    } while (0)

namespace afutil {
    std::string make_coreaudio_error(long code, const char *s)
    {
	std::stringstream ss;
	if (code == FOURCC('t','y','p','?'))
	    return "Unsupported file type";
	else if (code == FOURCC('f','m','t','?'))
	    return "Data format is not supported for this file type";
	int i;
	for (i = 0; i < 4; ++i)
	    if (!isprint(code & 0xff))
		break;
	if (i == 4)
	    ss << s << ": "
	       << static_cast<char>(code >> 24)
	       << static_cast<char>((code >> 16) & 0xff)
	       << static_cast<char>((code >> 8) & 0xff)
	       << static_cast<char>(code & 0xff);
	else
	    ss << s << ": " << code;
	return ss.str();
    }
    std::wstring CF2W(CFStringRef str)
    {
	CFIndex length = CFStringGetLength(str);
	if (!length) return L"";
	std::vector<UniChar> buffer(length);
	CFRange range = { 0, length };
	CFStringGetCharacters(str, range, &buffer[0]);
	return std::wstring(buffer.begin(), buffer.end());
    }
    inline CFStringPtr W2CF(std::wstring s)
    {
	CFStringRef sref = CFStringCreateWithCharacters(0,
		reinterpret_cast<const UniChar*>(s.c_str()), s.size());
	return CFStringPtr(sref, CFRelease);
    }
    uint32_t getTypesForExtension(const wchar_t *fname)
    {
	std::wstring ext = strutil::wslower(PathFindExtensionW(fname));
	CFStringPtr cfsp = W2CF(ext.substr(1));
	CFStringRef cfsr = cfsp.get();
	UInt32 type = 0;
	UInt32 size = sizeof(type);
	CHECKCA(AudioFileGetGlobalInfo(kAudioFileGlobalInfo_TypesForExtension,
				       sizeof(CFStringRef),
				       &cfsr, &size, &type));
	return type;
    }
    void getReadableTypes(std::vector<uint32_t> *result)
    {
	UInt32 size;
	CHECKCA(AudioFileGetGlobalInfoSize(kAudioFileGlobalInfo_ReadableTypes,
					   0, 0, &size));
	std::vector<uint32_t> vec(size / sizeof(uint32_t));
	CHECKCA(AudioFileGetGlobalInfo(kAudioFileGlobalInfo_ReadableTypes,
				       0, 0, &size, &vec[0]));
	result->swap(vec);
    }
    void getWritableTypes(std::vector<uint32_t> *result)
    {
	UInt32 size;
	CHECKCA(AudioFileGetGlobalInfoSize(kAudioFileGlobalInfo_WritableTypes,
					   0, 0, &size));
	std::vector<uint32_t> vec(size / sizeof(uint32_t));
	CHECKCA(AudioFileGetGlobalInfo(kAudioFileGlobalInfo_WritableTypes,
				       0, 0, &size, &vec[0]));
	result->swap(vec);
    }
    std::wstring getFileTypeName(uint32_t type)
    {
	CFStringRef name;
	UInt32 size = sizeof(name);
	CHECKCA(AudioFileGetGlobalInfo(kAudioFileGlobalInfo_FileTypeName,
				       sizeof(UInt32), &type, &size, &name));
	CFStringPtr _(name, CFRelease);
	return CF2W(name);
    }
    void getExtensionsForType(uint32_t type, std::vector<std::wstring> *vec)
    {
	CFArrayRef aref;
	UInt32 size = sizeof(aref);
	CHECKCA(AudioFileGetGlobalInfo(kAudioFileGlobalInfo_ExtensionsForType,
				       sizeof(UInt32), &type, &size, &aref));
	std::shared_ptr<const __CFArray> _(aref, CFRelease);
	CFIndex count = CFArrayGetCount(aref);
	std::vector<std::wstring> result;
	for (CFIndex i = 0; i < count; ++i) {
	    CFStringRef value =
		static_cast<CFStringRef>(CFArrayGetValueAtIndex(aref, i));
	    result.push_back(CF2W(value));
	}
	vec->swap(result);
    }
}


class AudioFileX {
    std::shared_ptr<OpaqueAudioFileID> m_file;
public:
    AudioFileX() {}
    AudioFileX(AudioFileID file, bool takeOwn)
    {
	attach(file, takeOwn);
    }
    void attach(AudioFileID file, bool takeOwn)
    {
	struct F {
	    static OSStatus dispose(AudioFileID af) { return 0; }
	};
	m_file.reset(file, takeOwn ? AudioFileClose : F::dispose);
    }
    operator AudioFileID() { return m_file.get(); }

    // property accessors
    uint32_t getFileFormat()
    {
	UInt32 value;
	UInt32 size = sizeof value;
	CHECKCA(AudioFileGetProperty(m_file.get(),
		    kAudioFilePropertyFileFormat, &size, &value));
	return value;
    }
    void getDataFormat(AudioStreamBasicDescription *result)
    {
	UInt32 size = sizeof(AudioStreamBasicDescription);
	CHECKCA(AudioFileGetProperty(m_file.get(),
		    kAudioFilePropertyDataFormat, &size, result));
    }
    uint64_t getAudioDataPacketCount()
    {
	UInt64 value;
	UInt32 size = sizeof value;
	CHECKCA(AudioFileGetProperty(m_file.get(),
		    kAudioFilePropertyAudioDataPacketCount,
		    &size, &value));
	return value;
    }
    void getPacketTableInfo(AudioFilePacketTableInfo *result)
    {
	UInt32 size = sizeof(AudioFilePacketTableInfo);
	CHECKCA(AudioFileGetProperty(m_file.get(),
				     kAudioFilePropertyPacketTableInfo,
				     &size, result));
    }
    void setPacketTableInfo(const AudioFilePacketTableInfo *info)
    {
	CHECKCA(AudioFileSetProperty(m_file.get(),
				     kAudioFilePropertyPacketTableInfo,
				     sizeof(AudioFilePacketTableInfo),
				     info));
    }
    void getChannelLayout(std::shared_ptr<AudioChannelLayout> *layout)
    {
	UInt32 size;
	UInt32 writable;
	CHECKCA(AudioFileGetPropertyInfo(m_file.get(),
		    kAudioFilePropertyChannelLayout, &size, &writable));
	std::shared_ptr<AudioChannelLayout> acl(
	    reinterpret_cast<AudioChannelLayout*>(std::malloc(size)),
	    std::free);
	CHECKCA(AudioFileGetProperty(m_file.get(),
		kAudioFilePropertyChannelLayout, &size, acl.get()));
	layout->swap(acl);
    }
    void setChannelLayout(const AudioChannelLayout *layout)
    {
	UInt32 size = offsetof(AudioChannelLayout, mChannelDescriptions[1])
	    + std::max(0, int(layout->mNumberChannelDescriptions) - 1) *
	    sizeof(AudioChannelDescription);
	CHECKCA(AudioFileSetProperty(m_file.get(),
				     kAudioFilePropertyChannelLayout,
				     size,
				     layout));
    }
    void getMagicCookieData(std::vector<uint8_t> *cookie)
    {
	UInt32 size;
	UInt32 writable;
	CHECKCA(AudioFileGetPropertyInfo(m_file.get(),
					 kAudioFilePropertyMagicCookieData,
					 &size, &writable));
	if (size > 0) {
	    std::vector<uint8_t> vec(size);
	    CHECKCA(AudioFileGetProperty(m_file.get(),
					 kAudioFilePropertyMagicCookieData,
					 &size, &vec[0]));
	    cookie->swap(vec);
	} else {
	    cookie->clear();
	}
    }
    void setMagicCookieData(const uint8_t *cookie, size_t size)
    {
	UInt32 len = size;
	CHECKCA(AudioFileSetProperty(m_file.get(),
				     kAudioFilePropertyMagicCookieData,
				     len,
				     cookie));
    }
    void setReserveDuration(double duration)
    {
	UInt32 size = sizeof(duration);
	CHECKCA(AudioFileSetProperty(m_file.get(),
				     kAudioFilePropertyReserveDuration,
				     size,
				     &duration));
    }
    uint32_t getPacketSizeUpperBound()
    {
	UInt32 len;
	UInt32 size = sizeof(len);
	CHECKCA(AudioFileGetProperty(m_file.get(),
				     kAudioFilePropertyPacketSizeUpperBound,
				     &size, &len));
	return len;
    }
    CFDictionaryPtr getInfoDictionary()
    {
	CFDictionaryRef dict;
	UInt32 size = sizeof dict;
	CHECKCA(AudioFileGetProperty(m_file.get(),
		    kAudioFilePropertyInfoDictionary,
		    &size, &dict));
	return CFDictionaryPtr(dict, CFRelease);
    }
    void setInfoDictionary(CFDictionaryRef dict)
    {
	UInt32 size = sizeof(dict);
	CHECKCA(AudioFileSetProperty(m_file.get(),
				     kAudioFilePropertyInfoDictionary,
				     size, &dict));
    }
};

#endif
