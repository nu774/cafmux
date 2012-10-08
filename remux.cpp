#include <cstdio>
#include <io.h>
#include <fcntl.h>
#define NOMINMAX
#include <windows.h>
#include <shlwapi.h>
#include <delayimp.h>
#include "utf8_codecvt_facet.hpp"
#include "strutil.h"
#include "AudioFileX.h"

#define fseeko _fseeki64

namespace util {
    inline uint32_t b2host32(uint32_t n)
    {
	return _byteswap_ulong(n);
    }

    void throw_crt_error(const std::string &message)
    {
	std::stringstream ss;
	ss << message << ": " << std::strerror(errno);
	throw std::runtime_error(ss.str());
    }

    void throw_crt_error(const std::wstring &message)
    {
	std::stringstream ss;
	utf8_codecvt_facet u8;
	ss << strutil::w2m(message, u8) << ": " << std::strerror(errno);
	throw std::runtime_error(ss.str());
    }
    void throw_win32_error(const std::wstring &msg, DWORD code)
    {
	LPWSTR pszMsg;
	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		       FORMAT_MESSAGE_FROM_SYSTEM,
		       0,
		       code,
		       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		       (LPWSTR)&pszMsg,
		       0,
		       0);
	std::wstringstream ss;
	if (pszMsg) {
	    strutil::squeeze(pszMsg, L"\r\n");
	    ss << msg << L": " << pszMsg;
	    LocalFree(pszMsg);
	}
	else if (code < 0xfe00)
	    ss << code << L": " << msg;
	else
	    ss << std::hex << code << L": " << msg;
	throw std::runtime_error(strutil::w2m(ss.str(), utf8_codecvt_facet()));
    }
    void throw_win32_error(const std::string &msg, DWORD code)
    {
	throw_win32_error(strutil::m2w(msg, utf8_codecvt_facet()), code);
    }
    std::shared_ptr<FILE> open_file(const std::wstring &fname,
				    const wchar_t *mode)
    {
	FILE * fp = _wfopen(fname.c_str(), mode);
	if (!fp) throw_crt_error(fname);
	return std::shared_ptr<FILE>(fp, std::fclose);
    }
    std::wstring GetModuleFileNameX(HMODULE module)
    {
	std::vector<wchar_t> buffer(32);
	DWORD cclen = GetModuleFileNameW(module, &buffer[0],
					 static_cast<DWORD>(buffer.size()));
	while (cclen >= buffer.size() - 1) {
	    buffer.resize(buffer.size() * 2);
	    cclen = GetModuleFileNameW(module, &buffer[0],
				       static_cast<DWORD>(buffer.size()));
	}
	return std::wstring(&buffer[0], &buffer[cclen]);
    }
    std::wstring get_module_directory()
    {
	std::wstring selfpath = GetModuleFileNameX(0);
	const wchar_t *fpos = PathFindFileNameW(selfpath.c_str());
	return selfpath.substr(0, fpos - selfpath.c_str());
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
void setup_audiofile(AudioFileX &iaf, AudioFileX &oaf)
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
	if (e.code() != FOURCC('c','h','k','?') &&
	    e.code() != FOURCC('p','t','y','?'))
	    throw;
    }

    try {
	std::vector<uint8_t> cookie;
	iaf.getMagicCookieData(&cookie);
	if (cookie.size())
	    oaf.setMagicCookieData(&cookie[0], cookie.size());
    } catch (const CoreAudioException &e) {
	if (e.code() != FOURCC('c','h','k','?') &&
	    e.code() != FOURCC('p','t','y','?'))
	    throw;
    }
    try {
	CFDictionaryPtr dict = iaf.getInfoDictionary();
	oaf.setInfoDictionary(dict.get());
    } catch (const CoreAudioException &e) {
	if (e.code() != FOURCC('c','h','k','?') &&
	    e.code() != FOURCC('p','t','y','?'))
	    throw;
    }

    try {
	oaf.setReserveDuration(length_in_seconds);
    } catch (const CoreAudioException &e) {
	if (e.code() != FOURCC('c','h','k','?') &&
	    e.code() != FOURCC('p','t','y','?'))
	    throw;
    }
}

static
void process(const std::wstring ifilename, const std::wstring ofilename,
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
    if (asbd.mFormatID == FOURCC('a','l','a','c') &&
	oformat == kAudioFileMPEG4Type)
	oformat = kAudioFileM4AType;

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
	ofp.reset();
	DeleteFileW(ofilename.c_str());
	throw std::runtime_error(ss.str());
    }
    AudioFileX oaf(oafid, true);
    setup_audiofile(iaf, oaf);

    uint32_t packet_size = iaf.getPacketSizeUpperBound();
    size_t buffer_size = packet_size;
    uint32_t packets_at_once = 1;
    while (packet_size * packets_at_once < 4096) {
	packets_at_once <<= 2;
	buffer_size <<= 2;
    }
    std::vector<uint8_t> buffer(buffer_size);
    uint64_t packet_count = iaf.getAudioDataPacketCount();
    AudioFilePacketTableInfo packet_table;
    /*
     *	AudioFile properly *writes* PacketTableInfo to M4A (as iTunSMPB).
     *	However, it doesn't *read* it from M4A iTunSMPB.
     */
    {
	try {
	    iaf.getPacketTableInfo(&packet_table);
	} catch (const CoreAudioException &e) {
	    if (e.code() != FOURCC('c','h','k','?') &&
		e.code() != FOURCC('p','t','y','?'))
		throw;
	}
	uint32_t iformat = iaf.getFileFormat();
	AudioFilePacketTableInfo itinfo = { 0 };
	if (mp4::test_if_mp4(ifp.get()))
	    mp4::get_priming_info(ifp.get(), &itinfo);

	if (itinfo.mPrimingFrames || itinfo.mRemainderFrames) {
	    uint64_t total = itinfo.mNumberValidFrames +
		itinfo.mPrimingFrames + itinfo.mRemainderFrames;
	    /* sanity check */
	    if (total == asbd.mFramesPerPacket * packet_count)
		packet_table = itinfo;
	}
    }

    int64_t pos = 0;
    int64_t bytes_written = 0;
    std::vector<AudioStreamPacketDescription> aspd(packets_at_once);
    try {
	while (pos < packet_count) {
	    UInt32 nbytes = buffer_size;
	    UInt32 npackets = packets_at_once;
	    CHECKCA(AudioFileReadPacketData(iafid, false, &nbytes, &aspd[0],
					    pos, &npackets, &buffer[0]));
	    if (!npackets) break;
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
	    if (aspd[0].mDataByteSize)
		CHECKCA(AudioFileWritePackets(oafid, false, nbytes, &aspd[0],
					      pos, &npackets, &buffer[0]));
	    else
		CHECKCA(AudioFileWriteBytes(oafid, false, bytes_written,
					    &nbytes, &buffer[0]));
	    pos += npackets;
	    bytes_written += nbytes;
	    double percent = 100.0 * pos / packet_count;
	    std::fwprintf(stderr, L"\r%.0f%% processed", percent);
	    std::fflush(stderr);
	}
	if (asbd.mFormatID == FOURCC('a','l','a','c') &&
	    oformat != kAudioFileCAFType)
	    std::memset(&packet_table, 0, sizeof(packet_table));
	if (packet_table.mPrimingFrames || packet_table.mRemainderFrames) {
	    try {
		oaf.setPacketTableInfo(&packet_table);
	    } catch (...) {
		//
	    }
	}
    } catch (...) {
	std::putwc('\n', stderr);
	throw;
    }
    std::fwprintf(stderr, L"...done\n");
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
    fputws(
L"usage: cafmux -p  (print available formats)\n"
L"       cafmux INFILE OUTFILE\n"
    , stderr);
    std::exit(1);
}

int wmain(int argc, wchar_t **argv)
{
    _setmode(1, _O_U8TEXT);
    _setmode(2, _O_U8TEXT);

    wchar_t *opt_query = 0;

    bool opt_p = false;
    for (++argv, --argc; *argv && **argv == '-'; ++argv, --argc) {
	if (argv[0][1] == 'p')
	    opt_p = true;
    }
    if (!opt_p && argc < 2)
	usage();

    try {
        set_dll_directories();
	__pfnDliFailureHook2 = dll_failure_hook;
	if (opt_p) {
	    list_readable_types();
	} else {
	    uint32_t type = afutil::getTypesForExtension(argv[1]);
	    process(argv[0], argv[1], type);
	}
	return 0;
    } catch (const std::exception & e) {
	fwprintf(stderr, L"ERROR: %s\n",
		 strutil::m2w(e.what(), utf8_codecvt_facet()));
	return 2;
    }
}
