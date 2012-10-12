#include <cstdio>
#include <io.h>
#include <fcntl.h>
#define NOMINMAX
#include <windows.h>
#include <shlwapi.h>
#include <delayimp.h>
#include <crtdbg.h>
#include "utf8_codecvt_facet.hpp"
#include "strutil.h"
#include "util.h"
#include "AudioFileX.h"
#include "mpa.h"
#include "id3.h"
#include "version.h"

namespace mpa {
    void generate_vbr_header(const uint8_t *reference,
			     const uint64_t *packet_pos,
			     size_t packet_count,
			     uint64_t total_bytes,
			     std::vector<uint8_t> *result)
    {
	MPAHeader header(reference);
	header.m_bitrate = 5; /* 64 for MPEG 1 Layer III */
	header.m_padding = 0;
	std::vector<uint8_t> buf(header.frame_size());
	header.get_bytes(&buf[0]);
	size_t pos = 4 + header.side_information_size();
	std::memcpy(&buf[pos], "Xing", 4), pos += 4;
	/* FRAMES_FLAG | BYTES_FLAG | TOC_FLAG */
	std::memcpy(&buf[pos], "\x00\x00\x00\x07", 4), pos += 4;
	uint32_t n = util::h2big32(packet_count);
	std::memcpy(&buf[pos], &n, 4), pos += 4;
	n = util::h2big32(total_bytes + header.frame_size());
	std::memcpy(&buf[pos], &n, 4), pos += 4;

	unsigned percent = 0;
	uint64_t toc[100];
	for (size_t i = 0; i < packet_count; ++i)
	    while (i * 100 / packet_count >= percent)
		toc[percent++] = packet_pos[i];

	size_t off = header.frame_size();
	for (size_t i = 0; i < 100; ++i)
	    buf[pos++] = static_cast<uint8_t>((toc[i] + off) * 255.0 /
					      (total_bytes + off) + 0.5);
	pos += 4; /* we don't write vbr quality scale */
	std::sprintf(reinterpret_cast<char*>(&buf[pos]),
		     "cafmux %s", cafmux_version);
	result->swap(buf);
    }
}

namespace mp4 {
    bool test_if_mp4(FILE *fp)
    {
	fpos_t cur;
	std::fgetpos(fp, &cur);
	fseeko(fp, 0, SEEK_SET);
	char buf[8];
	if (std::fread(buf, 1, 8, fp) != 8)
	    return false;
	std::fsetpos(fp, &cur);
	return std::memcmp(&buf[4], "ftyp", 4) == 0;
    }
    uint32_t next_box(FILE *fp, char *name, int64_t *rest)
    {
	if (rest && *rest < 8)
	    return 0;
	uint32_t atom_size;
	if ((std::fread(&atom_size, 4, 1, fp) < 1) ||
	    (std::fread(name, 1, 4, fp) < 4))
	    return 0;
	atom_size = util::b2host32(atom_size);
	if (rest)
	    *rest -= atom_size;
	return atom_size - 8;
    }
    uint32_t seek_to_box(FILE *fp, const char *name)
    {
	for (;;) {
	    uint32_t atom_size;
	    char atom_name[4];
	    if ((atom_size = next_box(fp, atom_name, 0)) == 0)
		return 0;
	    if (!std::memcmp(atom_name, name, 4))
		return atom_size;
	    if (fseeko(fp, atom_size, SEEK_CUR) != 0)
		return 0;
	}
    }
    /* path is like moov/trak/mdia/minf: first match */
    uint32_t seek_to_path(FILE *fp, const char *path)
    {
	std::vector<char> vpath(std::strlen(path) + 1);
	char *bufp = &vpath[0];
	std::strcpy(bufp, path);
	char *box;
	uint32_t atom_size = 0;
	while ((box = strutil::strsep(&bufp, "/")) != 0)
	    if ((atom_size = seek_to_box(fp, box)) == 0)
		return 0;
	return atom_size;
    }
    bool get_iTunSMPB(FILE *fp, std::string *result)
    {
	uint32_t atom_size;
	if (!(atom_size = seek_to_path(fp, "moov/udta/meta")) ||
	    atom_size < 4)
	    return false;
	if (fseeko(fp, 4, SEEK_CUR) != 0)
	    return false;
	int64_t ilst_size = seek_to_path(fp, "ilst");
	if (!ilst_size)
	    return false;
	char name[4];
	while ((atom_size = next_box(fp, name, &ilst_size)) != 0) {
	    if (std::memcmp(name, "----", 4)) {
		if (fseeko(fp, atom_size, SEEK_CUR) != 0)
		    return false;
		continue;
	    }
	    int64_t limit = atom_size;
	    fpos_t pos;
	    std::fgetpos(fp, &pos);
	    bool found = false;
	    std::vector<char> data;
	    while ((atom_size = next_box(fp, name, &limit)) != 0) {
		if (!std::memcmp(name, "name", 4)) {
		    if (atom_size < 12) // 4 + strlen("iTunSMPB")
			break;
		    std::vector<char> buf(atom_size);
		    if (std::fread(&buf[0], 1, atom_size, fp) != 12)
			return false;
		    if (std::memcmp(&buf[4], "iTunSMPB", 8))
			break;
		    found = true;
		} else if (!std::memcmp(name, "data", 4)) {
		    data.resize(atom_size);
		    if (std::fread(&data[0], 1, atom_size, fp) != atom_size)
			return false;
		} else if (fseeko(fp, atom_size, SEEK_CUR) != 0) {
		    return false;
		}
	    }
	    std::fsetpos(fp, &pos);
	    if (fseeko(fp, limit, SEEK_CUR) != 0)
		return false;
	    if (found) {
		std::string ss(data.begin() + 8, data.end());
		result->swap(ss);
		return true;
	    }
	}
	return false;
    }
    bool get_priming_info(FILE *fp, AudioFilePacketTableInfo *info)
    {
	fpos_t pos;
	bool result = false;
	std::fgetpos(fp, &pos);
	std::string data;
	fseeko(fp, 0, SEEK_SET);
	if ((result = get_iTunSMPB(fp, &data)) == true) {
	    uint32_t a, b, c;
	    uint64_t d;
	    if (std::sscanf(data.c_str(), "%x %x %x %llx",
			    &a, &b, &c, &d) != 4)
		result = false;
	    else {
		info->mPrimingFrames = b;
		info->mRemainderFrames = c;
		info->mNumberValidFrames = d;
	    }
	}
	std::fsetpos(fp, &pos);
	return result;
    }
}

namespace caf {
    uint64_t next_chunk(FILE *fp, char *name)
    {
	uint64_t size;
	if (std::fread(name, 1, 4, fp) != 4 || std::fread(&size, 8, 1, fp) != 1)
	    return 0;
	return util::b2host64(size);
    }
    bool get_info(FILE *fp, std::vector<char> *info)
    {
	fpos_t pos;
	std::fgetpos(fp, &pos);
	fseeko(fp, 8, SEEK_SET);
	uint64_t chunk_size;
	char chunk_name[4];
	bool found = false;
	while ((chunk_size = next_chunk(fp, chunk_name)) > 0) {
	    if (std::memcmp(chunk_name, "info", 4)) {
		if (fseeko(fp, chunk_size, SEEK_CUR) != 0)
		    break;
	    } else {
		std::vector<char> buf(chunk_size);
		if (std::fread(&buf[0], 1, buf.size(), fp) != buf.size())
		    break;
		info->swap(buf);
		found = true;
		break;
	    }
	}
	std::fsetpos(fp, &pos);
	return found;
    }
    /*
     * Loads CoreFoundation.dll constants.
     * Since DATA cannot be delayimp-ed, we have to manually
     * load it using .
     */
    void *load_cf_constant(const char *name)
    {
	HMODULE cf = GetModuleHandleA("CoreFoundation.dll");
	if (!cf)
	    util::throw_win32_error("CoreFouncation.dll", GetLastError());
	return GetProcAddress(cf, name);
    }
    bool get_info_dictionary(FILE *fp, CFDictionaryPtr *dict)
    {
	std::vector<char> info;
	if (!get_info(fp, &info) || info.size() < 4)
	    return false;
	// inside of info tag is delimited with NUL char.
	std::vector<std::string> tokens;
	{
	    const char *infop = &info[0] + 4;
	    const char *endp = &info[0] + info.size();
	    do {
		tokens.push_back(std::string(infop));
		infop += tokens.back().size() + 1;
	    } while (infop < endp);
	}
	// get some constants manually
	const CFDictionaryKeyCallBacks *kcb
	    = static_cast<const CFDictionaryKeyCallBacks *>(
		load_cf_constant("kCFTypeDictionaryKeyCallBacks"));
	const CFDictionaryValueCallBacks *vcb
	    = static_cast<const CFDictionaryValueCallBacks *>(
		load_cf_constant("kCFTypeDictionaryValueCallBacks"));

	CFMutableDictionaryRef dictref =
	    CFDictionaryCreateMutable(0, tokens.size() >> 1, kcb, vcb);
	utf8_codecvt_facet u8codec;
	CFDictionaryPtr dictptr(dictref, CFRelease);
	for (size_t i = 0; i < tokens.size() >> 1; ++i) {
	    CFStringPtr key =
		afutil::W2CF(strutil::m2w(tokens[2 * i], u8codec));
	    CFStringPtr value =
		afutil::W2CF(strutil::m2w(tokens[2 * i + 1], u8codec));
	    CFDictionarySetValue(dictref, key.get(), value.get());
	}
	dict->swap(dictptr);
	return true;
    }
}

namespace callback {
    const int ioErr = -36;

    OSStatus read(void *cookie, SInt64 pos, UInt32 count, void *data,
		  UInt32 *nread)
    {
	FILE *fp = static_cast<FILE*>(cookie);
	if (fseeko(fp, pos, SEEK_SET) == -1)
	    return ioErr;
	*nread = std::fread(data, 1, count, fp);
	return *nread >= 0 ? 0 : ioErr;
    }

    OSStatus write(void *cookie, SInt64 pos, UInt32 count, const void *data,
		   UInt32 *nwritten)
    {
	FILE *fp = static_cast<FILE*>(cookie);
	if (fseeko(fp, pos, SEEK_SET) == -1)
	    return ioErr;
	*nwritten = std::fwrite(data, 1, count, fp);
	return *nwritten == count ? 0 : ioErr;
    }

    SInt64 size(void *cookie)
    {
	FILE *fp = static_cast<FILE*>(cookie);
	return _filelengthi64(_fileno(fp));
    }

    OSStatus truncate(void *cookie, SInt64 size)
    {
	FILE *fp = static_cast<FILE*>(cookie);
	return _chsize_s(_fileno(fp), size) == 0 ? 0 : ioErr;
    }
}

static
void get_tags(FILE *ifp, AudioFile &iaf, CFDictionaryPtr *dict)
{
    if (iaf.getFileFormat() == kAudioFileCAFType)
	/*
	 * CoreAudio seems to *save* tags into CAF, 
	 * but not to *load* it from CAF (why?).
	 * Anyway, therefore we try to manually load it.
	 */
	caf::get_info_dictionary(ifp, dict);
    else {
	try {
	    dict->swap(iaf.getInfoDictionary());
	} catch (const CoreAudioException &e) {
	    if (!e.isNotSupportedError())
		throw;
	}
    }
}

static
void setup_audiofile(FILE *ifp, AudioFileX &iaf, AudioFileX &oaf)
{
    AudioStreamBasicDescription asbd;
    iaf.getDataFormat(&asbd);

    uint64_t packet_count = iaf.getAudioDataPacketCount();
    double length_in_seconds = 
	packet_count * asbd.mFramesPerPacket / asbd.mSampleRate;

    try {
	std::shared_ptr<AudioChannelLayout> acl;
	iaf.getChannelLayout(&acl);
	oaf.setChannelLayout(acl.get());
    } catch (const CoreAudioException &e) {
	if (!e.isNotSupportedError())
	    throw;
    }

    try {
	std::vector<uint8_t> cookie;
	iaf.getMagicCookieData(&cookie);
	if (cookie.size())
	    oaf.setMagicCookieData(&cookie[0], cookie.size());
    } catch (const CoreAudioException &e) {
	if (!e.isNotSupportedError())
	    throw;
    }
    CFDictionaryPtr dict;
    get_tags(ifp, iaf, &dict);
    if (dict.get()) {
	try {
	    oaf.setInfoDictionary(dict.get());
	} catch (const CoreAudioException &e) {
	    if (!e.isNotSupportedError())
		throw;
	}
    }

    try {
	oaf.setReserveDuration(length_in_seconds);
    } catch (const CoreAudioException &e) {
	if (!e.isNotSupportedError())
	    throw;
    }
}

/*
 * AudioFile properly *writes* PacketTableInfo to M4A (as iTunSMPB).
 * However, it doesn't *read* it from M4A iTunSMPB.
 */
static
void get_packet_table_info(AudioFileX &af, FILE *fp,
			   AudioFilePacketTableInfo *info)
{
    try {
	af.getPacketTableInfo(info);
    } catch (const CoreAudioException &e) {
	if (!e.isNotSupportedError())
	    throw;
    }
    uint32_t iformat = af.getFileFormat();
    AudioFilePacketTableInfo itinfo = { 0 };
    if (mp4::test_if_mp4(fp))
	mp4::get_priming_info(fp, &itinfo);

    if (itinfo.mPrimingFrames || itinfo.mRemainderFrames) {
	AudioStreamBasicDescription asbd;
	af.getDataFormat(&asbd);
	uint64_t packet_count = af.getAudioDataPacketCount();

	uint64_t total = itinfo.mNumberValidFrames +
	    itinfo.mPrimingFrames + itinfo.mRemainderFrames;
	/* sanity check */
	if (total == asbd.mFramesPerPacket * packet_count)
	    *info = itinfo;
    }
}

static
void show_format(const std::wstring &ifilename)
{
    std::shared_ptr<FILE> ifp(util::open_file(ifilename, L"rb"));

    AudioFileID iafid;
    try {
	CHECKCA(AudioFileOpenWithCallbacks(ifp.get(), callback::read, 0, 
					   callback::size, 0, 0, &iafid));
    } catch (const CoreAudioException &e) {
	std::stringstream ss;
	ss << strutil::w2m(ifilename) << ": " << e.what();
	throw std::runtime_error(ss.str());
    }
    AudioFileX iaf(iafid, true);
    AudioStreamBasicDescription asbd;
    iaf.getDataFormat(&asbd);
    std::wprintf(L"%s\n", afutil::getASBDFormatName(&asbd).c_str());
}

inline bool is_mpeg(uint32_t format)
{
    return format == kAudioFileMP1Type || format == kAudioFileMP2Type ||
	format == kAudioFileMP3Type;
}

static
void process(const std::wstring &ifilename, const std::wstring &ofilename,
	     uint32_t oformat)
{
    std::shared_ptr<FILE> ifp(util::open_file(ifilename, L"rb"));

    AudioFileID iafid;
    try {
	CHECKCA(AudioFileOpenWithCallbacks(ifp.get(), callback::read, 0, 
					   callback::size, 0, 0, &iafid));
    } catch (const CoreAudioException &e) {
	std::stringstream ss;
	ss << strutil::w2m(ifilename) << ": " << e.what();
	throw std::runtime_error(ss.str());
    }
    AudioFileX iaf(iafid, true);
    AudioStreamBasicDescription asbd;
    iaf.getDataFormat(&asbd);

    if (oformat == kAudioFileAIFFType &&
	asbd.mFormatID != FOURCC('l','p','c','m'))
	oformat = kAudioFileAIFCType;

    std::shared_ptr<FILE> ofp(util::open_file(ofilename, L"wb+"));
    AudioFileID oafid;
    try {
	CHECKCA(AudioFileInitializeWithCallbacks(ofp.get(),
						 callback::read,
						 callback::write,
						 callback::size,
						 callback::truncate,
						 oformat, &asbd,
						 0, &oafid));
    } catch (const CoreAudioException &e) {
	std::stringstream ss;
	ss << strutil::w2m(ofilename) << ": " << e.what();
	if (e.code() == FOURCC('f','m','t','?')) {
	    ss << "\n" << "Data format: ";
	    ss << strutil::w2m(afutil::getASBDFormatName(&asbd),
			       utf8_codecvt_facet());
	}
	ofp.reset();
	DeleteFileW(ofilename.c_str());
	throw std::runtime_error(ss.str());
    }
    AudioFileX oaf(oafid, true);
    if (is_mpeg(oformat))
    {
	/*
	 * We don't use AudioFile and directly write instead.
	 */
	oaf.close();
	fseeko(ofp.get(), 0, SEEK_SET);
	_chsize_s(_fileno(ofp.get()), 0);
    }
    else
	setup_audiofile(ifp.get(), iaf, oaf);

    uint32_t packet_size = iaf.getPacketSizeUpperBound();
    size_t buffer_size = packet_size;
    uint32_t packets_at_once = 1;
    while (packet_size * packets_at_once < 4096) {
	packets_at_once <<= 1;
	buffer_size <<= 1;
    }
    uint64_t packet_count = iaf.getAudioDataPacketCount();

    std::vector<uint8_t> buffer(buffer_size);
    AudioFilePacketTableInfo packet_table = { 0 };
    get_packet_table_info(iaf, ifp.get(), &packet_table);

    int64_t pos = 0;
    int64_t bytes_written = 0;
    std::vector<AudioStreamPacketDescription> aspd(packets_at_once);
    std::vector<uint64_t> packet_pos;
    UInt32 prev_nbytes = 0;
    bool cbr = true;
    try {
	while (pos < packet_count) {
	    UInt32 nbytes = buffer_size;
	    UInt32 npackets = packets_at_once;
	    CHECKCA(AudioFileReadPacketData(iafid, false, &nbytes, &aspd[0],
					    pos, &npackets, &buffer[0]));
	    if (!npackets)
		break;
	    if (asbd.mFormatID == FOURCC('a','l','a','c') &&
		oformat != kAudioFileCAFType) {
		/*
		 * AudioFile treats ALAC as constantly framed when reading;
		 * We rather want frame length variably expressed with stss
		 * in case of m4a.
		 */
		if (pos + npackets >= packet_count) {
		    aspd[packet_count - pos - 1].mVariableFramesInPacket
			= asbd.mFramesPerPacket - packet_table.mRemainderFrames;
		}
	    }
	    /*
	     * At least AudioFileWritePackets seems to fail for ima4,
	     * therefore we use AudioFileWritePackets() only when
	     * packet information is in use for the format.
	     */
	    if (is_mpeg(oformat))
		std::fwrite(&buffer[0], 1, nbytes, ofp.get());
	    else if (aspd[0].mDataByteSize)
		CHECKCA(AudioFileWritePackets(oafid, false, nbytes, &aspd[0],
					      pos, &npackets, &buffer[0]));
	    else
		CHECKCA(AudioFileWriteBytes(oafid, false, bytes_written,
					    &nbytes, &buffer[0]));

	    pos += npackets;
	    if (aspd[0].mDataByteSize) {
		for (size_t i = 0; i < npackets; ++i) {
		    packet_pos.push_back(bytes_written);
		    bytes_written += aspd[i].mDataByteSize;
		}
	    } else
		bytes_written += nbytes;
	    if (prev_nbytes && std::abs(int(nbytes) - int(prev_nbytes)) > 1)
		cbr = false;
	    prev_nbytes = nbytes;
	    double percent = 100.0 * pos / packet_count;
	    std::fwprintf(stderr, L"\r%.0f%% processed", percent);
	    std::fflush(stderr);
	}
    } catch (...) {
	std::putwc('\n', stderr);
	throw;
    }
    std::putwc('\n', stderr);
    packet_count = pos;
    if (is_mpeg(oformat)) {
	std::vector<uint8_t> xing_header;
	if (!cbr) {
	    mpa::generate_vbr_header(&buffer[0], &packet_pos[0],
				     packet_pos.size(), bytes_written,
				     &xing_header);
	}
	std::vector<uint8_t> id3tag;
	CFDictionaryPtr info_dict;
	get_tags(ifp.get(), iaf, &info_dict);
	{
	    uint64_t prefetch_pos = 0;
	    if (packet_pos.size() > 7) {
		prefetch_pos = xing_header.size() +
		    packet_pos[packet_pos.size() - 8];
	    }
	    if (packet_table.mPrimingFrames ||
		packet_table.mRemainderFrames ||
		info_dict.get())
		id3::build_id3tag(info_dict.get(), &packet_table,
				  prefetch_pos, &id3tag);
	}
	if (id3tag.size() || xing_header.size()) {
	    util::shift_file_content(ofp.get(),
				     id3tag.size() + xing_header.size());
	    fseeko(ofp.get(), 0, SEEK_SET);
	    if (id3tag.size())
		std::fwrite(&id3tag[0], 1, id3tag.size(), ofp.get());
	    if (xing_header.size())
		std::fwrite(&xing_header[0], 1, xing_header.size(), ofp.get());
	}
    }
    if (!is_mpeg(oformat) && (asbd.mFormatID != FOURCC('a','l','a','c') ||
	oformat == kAudioFileCAFType)) {
	if (packet_table.mPrimingFrames || packet_table.mRemainderFrames) {
	    if (!packet_table.mNumberValidFrames) {
		/* take care of MP3 iTunSMPB */
		packet_table.mNumberValidFrames =
		    packet_count * asbd.mFramesPerPacket -
		    packet_table.mPrimingFrames -
		    packet_table.mRemainderFrames;
	    }
	    try {
		oaf.setPacketTableInfo(&packet_table);
	    } catch (...) {
	    }
	}
    }
    std::fflush(stderr);
}

static
void print_type_info(uint32_t type)
{
    std::wstring name = afutil::getFileTypeName(type);
    std::vector<std::wstring> extensions;
    afutil::getExtensionsForType(type, &extensions);
    std::wprintf(L"%s", name.c_str());
    const wchar_t *sep = L" (";
    for (size_t j = 0; j < extensions.size(); ++j) {
	std::wprintf(L"%s%s", sep, extensions[j].c_str());
	sep = L", ";
    }
    std::wprintf(L")\n");
}
static
void list_readable_types()
{
    std::vector<uint32_t> types;
    afutil::getReadableTypes(&types);
    for (size_t i = 0; i < types.size(); ++i)
	print_type_info(types[i]);
}

static
void list_writable_types()
{
    std::vector<uint32_t> types;
    afutil::getWritableTypes(&types);
    for (size_t i = 0; i < types.size(); ++i)
	print_type_info(types[i]);
}

static
void set_dll_directories()
{
    SetDllDirectoryW(L"");
    DWORD sz = GetEnvironmentVariableW(L"PATH", 0, 0);
    std::vector<wchar_t> vec(sz);
    sz = GetEnvironmentVariableW(L"PATH", &vec[0], sz);
    std::wstring searchPaths(&vec[0], &vec[sz]);

    HKEY hKey;
    const wchar_t *subkey =
	L"SOFTWARE\\Apple Inc.\\Apple Application Support";
    if (SUCCEEDED(RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0,
				KEY_READ, &hKey))) {
	std::shared_ptr<HKEY__> hKeyPtr(hKey, RegCloseKey);
	DWORD size;
	if (SUCCEEDED(RegQueryValueExW(hKey, L"InstallDir", 0, 0, 0, &size))) {
	    std::vector<wchar_t> vec(size/sizeof(wchar_t));
	    if (SUCCEEDED(RegQueryValueExW(hKey, L"InstallDir", 0, 0,
			reinterpret_cast<LPBYTE>(&vec[0]), &size))) {
		std::wstringstream ss;
		ss << &vec[0] << L";" << searchPaths;
		searchPaths = ss.str();
	    }
	}
    }
    std::wstring dir = util::get_module_directory() + L"QTfiles";
    std::wstringstream ss;
    ss << dir << L";" << searchPaths;
    searchPaths = ss.str();
    SetEnvironmentVariableW(L"PATH", searchPaths.c_str());
}

static
FARPROC WINAPI dll_failure_hook(unsigned notify, PDelayLoadInfo pdli)
{
    util::throw_win32_error(pdli->szDll, pdli->dwLastError);
    return 0;
}

void usage()
{
    std::fwprintf(stderr,
L"cafmux %hs\n"
L"usage: cafmux -p             (print available formats)\n"
L"       cafmux -i INFILE      (print audio format of INFILE)\n"
L"       cafmux INFILE OUTFILE (remux INFILE to OUTFILE)\n"
    , cafmux_version);
    std::exit(1);
}

int wmain(int argc, wchar_t **argv)
{
#ifdef _DEBUG
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF|_CRTDBG_CHECK_ALWAYS_DF);
#endif
    _setmode(1, _O_U8TEXT);
    _setmode(2, _O_U8TEXT);

    bool opt_p = false;
    wchar_t *opt_i = 0;

    for (++argv, --argc; *argv && **argv == '-'; ++argv, --argc) {
	if (argv[0][1] == 'p')
	    opt_p = true;
	else if (argv[0][1] == 'i') {
	    if (argv[0][2])
		opt_i = argv[0] + 2;
	    else if (argv[1]) {
		opt_i = argv[1];
		++argv, --argc;
	    } else
		usage();
	}
    }
    if (!opt_p && !opt_i && argc < 2)
	usage();

    try {
        set_dll_directories();
	__pfnDliFailureHook2 = dll_failure_hook;
	if (opt_p)
	    list_readable_types();
	else if (opt_i)
	    show_format(opt_i);
	else {
	    uint32_t type = afutil::getTypesForExtension(argv[1]);
	    process(argv[0], argv[1], type);
	}
	return 0;
    } catch (const std::exception & e) {
	std::fwprintf(stderr, L"ERROR: %s\n",
		 strutil::m2w(e.what(), utf8_codecvt_facet()));
	return 2;
    }
}
