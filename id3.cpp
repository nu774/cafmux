#include "id3.h"
#include "utf8_codecvt_facet.hpp"
#include "strutil.h"
#include "util.h"
#include "AudioFileX.h"

namespace id3 {
    struct id3info {
	const char *AFKey;
	const char *id3Key;
    } id3keymap[] = {
	{ kAFInfoDictionary_Artist,              "TPE1" },
	{ kAFInfoDictionary_Album,               "TALB" },
	{ kAFInfoDictionary_Tempo,               "TBPM" },
	{ kAFInfoDictionary_KeySignature,        "TKEY" },
	{ kAFInfoDictionary_TrackNumber,         "TRCK" },
	{ kAFInfoDictionary_Year,                "TYER" },
	{ kAFInfoDictionary_Composer,            "TCOM" },
	{ kAFInfoDictionary_Lyricist,            "TEXT" },
	{ kAFInfoDictionary_Genre,               "TCON" },
	{ kAFInfoDictionary_Title,               "TIT2" },
	{ kAFInfoDictionary_RecordedDate,        "TRDA" },
	{ kAFInfoDictionary_Comments,            "COMM" },
	{ kAFInfoDictionary_Copyright,           "TCOP" },
	{ kAFInfoDictionary_EncodingApplication, "TSSE" },
	{ kAFInfoDictionary_ISRC,                "TSRC" },
	{ kAFInfoDictionary_SubTitle,            "TIT3" },
	{ 0,                                     0      }
    };
    const char *get_id3name(const char *afkey)
    {
	const struct id3info *pmap = id3keymap;
	for (; pmap->AFKey; pmap++)
	    if (!std::memcmp(afkey, pmap->AFKey, 4))
		return pmap->id3Key;
	return 0;
    }
    bool all_ascii(const wchar_t *s)
    {
	bool ascii = true;
	while (*s++ && ascii)
	    if (*s > 0x7f)
		ascii = false;
	return ascii;
    }
    void get_sync_value(uint32_t value, uint8_t *result)
    {
	for (size_t i = 0; i < 4; ++i)
	    result[i] = value >> ((3 - i) * 7) & 0x7f;
    }
    void build_text_frame_value(const wchar_t *value,
				std::vector<uint8_t> *result, bool ascii)
    {
	size_t len = std::wcslen(value);
	std::vector<uint8_t> vec;
	if (!ascii) {
	    vec.resize((len + 2) * 2 + 1);
	    vec[0] = 1;
	    uint16_t bom = 0xfeff;
	    std::memcpy(&vec[1], &bom, 2);
	    /* XXX: assumes sizeof(wchar_t) == 2 and encoded in UTF-16 */
	    std::memcpy(&vec[3], value, len << 1);
	} else {
	    vec.resize(len + 2);
	    vec[0] = 0;
	    std::string s = strutil::w2m(value, utf8_codecvt_facet());
	    std::memcpy(&vec[1], s.c_str(), len);
	}
	result->swap(vec);
    }
    void build_text_frame(const char *key, const wchar_t *value,
		     std::vector<uint8_t> *result)
    {
	std::vector<uint8_t> vec(10), buf;
	const char *name = get_id3name(key);
	if (!name)
	    return;
	std::memcpy(&vec[0], name, 4);
	build_text_frame_value(value, &buf, all_ascii(value));
	uint32_t size = util::h2big32(buf.size());
	std::memcpy(&vec[4], &size, 4);
	std::copy(buf.begin(), buf.end(), std::back_inserter(vec));
	result->swap(vec);
    }
    void build_comment_frame(const char *lang, const wchar_t *desc,
			     const wchar_t *value, std::vector<uint8_t> *res)
    {
	std::vector<uint8_t> vec(10), buf;
	std::memcpy(&vec[0], "COMM", 4);
	bool ascii = all_ascii(desc) && all_ascii(value);

	build_text_frame_value(desc, &buf, ascii);
	vec.push_back(buf[0]);
	std::copy(lang, lang + std::strlen(lang), std::back_inserter(vec));
	std::copy(buf.begin() + 1, buf.end(), std::back_inserter(vec));
	buf.clear();

	build_text_frame_value(value, &buf, ascii);
	std::copy(buf.begin() + 1, buf.end(), std::back_inserter(vec));

	uint32_t size = util::h2big32(vec.size() - 10);
	std::memcpy(&vec[4], &size, 4);
	res->swap(vec);
    }
    void build_id3tag(CFDictionaryRef dict,
		      const AudioFilePacketTableInfo *packet_info,
		      uint32_t prefetch_point,
		      std::vector<uint8_t> *result)
    {
	std::vector<uint8_t> vec(10);
	std::memcpy(&vec[0], "ID3\x03", 4);
	struct dict_callback {
	    static void f(const void *k, const void *v, void *c)
	    {
		std::vector<uint8_t> *vp =
		    static_cast<std::vector<uint8_t>*>(c);
		std::wstring wkey =
		    afutil::CF2W(static_cast<CFStringRef>(k));
		std::wstring wvalue =
		    afutil::CF2W(static_cast<CFStringRef>(v));
		std::string skey = strutil::w2m(wkey, utf8_codecvt_facet());
		std::vector<uint8_t> frame;
		build_text_frame(skey.c_str(), wvalue.c_str(), &frame);
		if (frame.size())
		    std::copy(frame.begin(), frame.end(),
			      std::back_inserter(*vp));
	    }
	};
	if (dict)
	    CFDictionaryApplyFunction(dict, &dict_callback::f, &vec);
	if (packet_info->mPrimingFrames || packet_info->mRemainderFrames) {
	    const char *tmpl =
		" 00000000 %08X %08X %016llX 00000000 %08X 00000000 00000000"
		" 00000000 00000000 00000000 00000000";
	    char buf[256];
	    std::sprintf(buf, tmpl, packet_info->mPrimingFrames,
			 packet_info->mRemainderFrames,
			 packet_info->mNumberValidFrames,
			 prefetch_point);
	    std::wstring ws = strutil::m2w(buf, utf8_codecvt_facet());
	    std::vector<uint8_t> frame;
	    build_comment_frame("eng", L"iTunPGAP", L"0", &frame);
	    std::copy(frame.begin(), frame.end(), std::back_inserter(vec));
	    build_comment_frame("eng", L"iTunSMPB", ws.c_str(), &frame);
	    std::copy(frame.begin(), frame.end(), std::back_inserter(vec));
	}
	uint32_t size = 256;
	while (size < vec.size())
	    size <<= 1;
	vec.resize(size);
	get_sync_value(size - 10, &vec[6]);
	result->swap(vec);
    }
}
