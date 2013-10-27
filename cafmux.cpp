#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <assert.h>
#include <io.h>
#include <fcntl.h>
#define NOMINMAX
#include <windows.h>
#include <shlwapi.h>
#include <delayimp.h>
#include <crtdbg.h>
#include "wgetopt.h"
#include "strutil.h"
#include "util.h"
#include "AudioFileX.h"
#include "mpa.h"
#include "id3.h"
#include "dl.h"
#include "version.h"

#define lseek64 _lseeki64

namespace util {
    void shift_file_content(int fd, int64_t space)
    {
        int64_t current_size = _filelengthi64(fd);
        int64_t begin, end = current_size;
        char buf[8192];
        for (; (begin = std::max(0LL, end - 8192)) < end; end = begin) {
            _lseeki64(fd, begin, SEEK_SET);
            read(fd, buf, end - begin);
            _lseeki64(fd, begin + space, SEEK_SET);
            write(fd, buf, end - begin);
        }
    }
}

namespace mp4 {
    bool test_if_mp4(int fd)
    {
        util::FilePositionSaver _(fd);
        lseek64(fd, 0, SEEK_SET);
        char buf[8];
        if (read(fd, buf, 8) != 8)
            return false;
        return std::memcmp(&buf[4], "ftyp", 4) == 0;
    }
    uint32_t next_box(int fd, char *name, int64_t *rest)
    {
        if (rest && *rest < 8)
            return 0;
        uint32_t atom_size;
        if (read(fd, &atom_size, 4) < 4 || read(fd, name, 4) < 4)
            return 0;
        atom_size = util::b2host32(atom_size);
        if (rest)
            *rest -= atom_size;
        return atom_size - 8;
    }
    uint32_t seek_to_box(int fd, const char *name)
    {
        for (;;) {
            uint32_t atom_size;
            char atom_name[4];
            if ((atom_size = next_box(fd, atom_name, 0)) == 0)
                return 0;
            if (!std::memcmp(atom_name, name, 4))
                return atom_size;
            if (lseek64(fd, atom_size, SEEK_CUR) < 0)
                return 0;
        }
    }
    /* path is like moov/trak/mdia/minf: first match */
    uint32_t seek_to_path(int fd, const char *path)
    {
        strutil::Tokenizer<char> tokens(path, "/");
        char *box;
        uint32_t atom_size = 0;
        while ((box = tokens.next()) != 0)
            if ((atom_size = seek_to_box(fd, box)) == 0)
                return 0;
        return atom_size;
    }
    bool get_iTunSMPB(int fd, std::string *result)
    {
        util::FilePositionSaver _(fd);
        lseek64(fd, 0, SEEK_SET);

        uint32_t atom_size;
        if (!(atom_size = seek_to_path(fd, "moov/udta/meta")) || atom_size < 4)
            return false;
        if (lseek64(fd, 4, SEEK_CUR) < 0)
            return false;
        int64_t ilst_size = seek_to_path(fd, "ilst");
        if (!ilst_size)
            return false;
        char name[4];
        while ((atom_size = next_box(fd, name, &ilst_size)) != 0) {
            if (std::memcmp(name, "----", 4)) {
                if (lseek64(fd, atom_size, SEEK_CUR) < 0)
                    return false;
                continue;
            }
            int64_t limit = atom_size;
            int64_t pos = lseek64(fd, 0, SEEK_CUR);
            int64_t end = pos + limit;
            bool found = false;
            std::vector<char> data;
            while ((atom_size = next_box(fd, name, &limit)) != 0) {
                if (!std::memcmp(name, "name", 4)) {
                    if (atom_size < 12) // 4 + strlen("iTunSMPB")
                        break;
                    std::vector<char> buf(atom_size);
                    if (read(fd, &buf[0], atom_size) != atom_size)
                        return false;
                    limit -= atom_size;
                    if (std::memcmp(&buf[4], "iTunSMPB", 8))
                        break;
                    found = true;
                } else if (!std::memcmp(name, "data", 4)) {
                    data.resize(atom_size);
                    if (read(fd, &data[0], atom_size) != atom_size)
                        return false;
                    limit -= atom_size;
                } else {
                    if (lseek64(fd, atom_size, SEEK_CUR) < 0)
                        return false;
                    limit -= atom_size;
                }
            }
            if (found) {
                std::string ss(data.begin() + 8, data.end());
                result->swap(ss);
                return true;
            }
            if (lseek64(fd, end, SEEK_SET) < 0)
                return false;
        }
        return false;
    }
    bool get_priming_info(int fd, AudioFilePacketTableInfo *info)
    {
        bool result = false;
        std::string data;
        if ((result = get_iTunSMPB(fd, &data)) == true) {
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
        return result;
    }
}

namespace caf {
    uint64_t next_chunk(int fd, char *name)
    {
        uint64_t size;
        if (read(fd, name, 4) != 4 || read(fd, &size, 8) != 8)
            return 0;
        return util::b2host64(size);
    }
    bool get_info(int fd, std::vector<char> *info)
    {
        util::FilePositionSaver _(fd);
        lseek64(fd, 8, SEEK_SET);

        uint64_t chunk_size;
        char chunk_name[4];
        bool found = false;
        while ((chunk_size = next_chunk(fd, chunk_name)) > 0) {
            if (std::memcmp(chunk_name, "info", 4)) {
                if (lseek64(fd, chunk_size, SEEK_CUR) < 0)
                    break;
            } else {
                std::vector<char> buf(chunk_size);
                if (read(fd, &buf[0],  buf.size()) != buf.size())
                    break;
                info->swap(buf);
                found = true;
                break;
            }
        }
        return found;
    }
    bool get_info_dictionary(int fd, CFDictionaryPtr *dict)
    {
        std::vector<char> info;
        if (!get_info(fd, &info) || info.size() < 4)
            return false;

        uint32_t nent;
        std::memcpy(&nent, &info[0], 4);
        nent = util::b2host32(nent);

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
        nent = std::min(nent, tokens.size() >> 1);
        CFMutableDictionaryRef dictref = cautil::CreateDictionary(nent);
        CFDictionaryPtr dictptr(dictref, CFRelease);

        for (size_t i = 0; i < nent; ++i) {
            CFStringPtr key =
                cautil::W2CF(strutil::us2w(tokens[2 * i]));
            CFStringPtr value =
                cautil::W2CF(strutil::us2w(tokens[2 * i + 1]));
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
        int fd = fileno(static_cast<FILE*>(cookie));
        if (lseek64(fd, pos, SEEK_SET) == -1)
            return ioErr;
        int n = ::read(fd, data, count);
        *nread = std::max(n, 0);
        return n >= 0 ? 0 : ioErr;
    }

    OSStatus write(void *cookie, SInt64 pos, UInt32 count, const void *data,
                   UInt32 *nwritten)
    {
        int fd = fileno(static_cast<FILE*>(cookie));
        if (lseek64(fd, pos, SEEK_SET) == -1)
            return ioErr;
        int n = ::write(fd, data, count);
        *nwritten = std::max(n, 0);
        return n >= 0 ? 0 : ioErr;
    }

    SInt64 size(void *cookie)
    {
        int fd = fileno(static_cast<FILE*>(cookie));
        return _filelengthi64(fd);
    }

    OSStatus truncate(void *cookie, SInt64 size)
    {
        int fd = fileno(static_cast<FILE*>(cookie));
        return _chsize_s(fd, size) == 0 ? 0 : ioErr;
    }
}

static
void show_format(const std::wstring &ifilename)
{
    std::shared_ptr<FILE> ifp(win32::fopen(ifilename, L"rb"));

    AudioFileID iafid;
    try {
        CHECKCA(AudioFileOpenWithCallbacks(ifp.get(), callback::read,
                                           0, callback::size, 0, 0, &iafid));
    } catch (const CoreAudioException &e) {
        std::stringstream ss;
        ss << strutil::w2us(ifilename) << ": " << e.what();
        throw std::runtime_error(ss.str());
    }
    AudioFileX iaf(iafid, true);
    AudioStreamBasicDescription asbd;
    iaf.getDataFormat(&asbd);
    std::vector<AudioFormatListItem> aflist;
    iaf.getFormatList(&aflist);
    std::wprintf(L"%s\n", afutil::getASBDFormatName(aflist[0].mASBD).c_str());
}

inline bool is_mpeg(uint32_t format)
{
    return format == kAudioFileMP1Type || format == kAudioFileMP2Type ||
        format == kAudioFileMP3Type;
}

class Remuxer {
    std::shared_ptr<FILE> m_ifp, m_ofp;
    AudioFileX m_iaf, m_oaf;
    uint32_t m_oformat;
    uint64_t m_current_packet;
    uint64_t m_packet_count;
    uint64_t m_bytes_processed;
    uint64_t m_offset;
    std::vector<uint64_t> m_packet_pos;
    std::vector<uint8_t> m_buffer;
    std::vector<AudioStreamPacketDescription> m_aspd;
    AudioStreamBasicDescription m_asbd;
    uint32_t m_channel_layout_tag;
    AudioFilePacketTableInfo m_packet_info;
public:
    Remuxer(const std::wstring &ifilename, const std::wstring &ofilename,
            uint32_t oformat)
        : m_oformat(oformat), m_current_packet(0), m_offset(0),
          m_bytes_processed(0)
    {
        m_ifp = win32::fopen(ifilename, L"rb");
        AudioFileID iafid;
        try {
            CHECKCA(AudioFileOpenWithCallbacks(m_ifp.get(),
                                               callback::read, 0, 
                                               callback::size, 0, 0, &iafid));
        } catch (const CoreAudioException &e) {
            std::stringstream ss;
            ss << strutil::w2us(ifilename) << ": " << e.what();
            throw std::runtime_error(ss.str());
        }
        m_iaf.attach(iafid, true);
        std::vector<AudioFormatListItem> aflist;
        m_iaf.getFormatList(&aflist);
        m_asbd = aflist[0].mASBD;
        m_channel_layout_tag = aflist[0].mChannelLayoutTag;

        if (is_mpeg(oformat)) {
            if (m_asbd.mFormatID != FOURCC('.','m','p','1') &&
                m_asbd.mFormatID != FOURCC('.','m','p','2') &&
                m_asbd.mFormatID != FOURCC('.','m','p','3'))
            {
                std::stringstream ss;
                ss << strutil::w2us(ofilename)
                   << ": Data format is not supported for this file type";
                ss << "\n" << "Data format: ";
                ss << strutil::w2us(afutil::getASBDFormatName(m_asbd));
                throw std::runtime_error(ss.str());
            }
        }
        uint32_t max_packet_size = m_iaf.getMaximumPacketSize();
        m_packet_count = m_iaf.getAudioDataPacketCount();
        uint32_t packet_at_once = 1;
        {
            uint32_t packet_size = m_iaf.getPacketSizeUpperBound();
            // sanity check to avoid infinite loop
            if (packet_size == 0)
                throw std::runtime_error("Can't retrieve packet size");
            size_t buffer_size = packet_size;
            while (packet_size * packet_at_once < 4096) {
                packet_at_once <<= 1;
                buffer_size <<= 1;
            }
            m_buffer.resize(buffer_size);
        }
        std::memset(&m_packet_info, 0, sizeof m_packet_info);
        getPacketTableInfo(&m_packet_info);
        m_aspd.resize(packet_at_once);

        m_ofp = win32::fopen(ofilename, L"wb+");
        if (is_mpeg(oformat))
            return;

        if (oformat == kAudioFileAIFFType &&
            m_asbd.mFormatID != FOURCC('l','p','c','m'))
            oformat = kAudioFileAIFCType;
        else if (oformat == kAudioFileAIFCType &&
            m_asbd.mFormatID == FOURCC('l','p','c','m'))
            oformat = kAudioFileAIFFType;

        AudioFileID oafid;
        try {
            CHECKCA(AudioFileInitializeWithCallbacks(m_ofp.get(),
                                                     callback::read,
                                                     callback::write,
                                                     callback::size,
                                                     callback::truncate,
                                                     oformat, &m_asbd,
                                                     0, &oafid));
        } catch (const CoreAudioException &e) {
            std::stringstream ss;
            ss << strutil::w2us(ofilename) << ": " << e.what();
            if (e.code() == FOURCC('f','m','t','?')) {
                ss << "\n" << "Data format: ";
                ss << strutil::w2us(afutil::getASBDFormatName(m_asbd));
            }
            m_ofp.reset();
            DeleteFileW(ofilename.c_str());
            throw std::runtime_error(ss.str());
        }
        m_oaf.attach(oafid, true);
        setupAudioFile();
    }

    ~Remuxer()
    {
        m_iaf.close();
        m_oaf.close();
    }
    uint64_t packetCount() const { return m_packet_count; }
    uint64_t currentPacket() const { return m_current_packet; }
    double sampleRate() const { return m_asbd.mSampleRate; }

    void trim(uint64_t begin, uint64_t end)
    {
        assert(m_current_packet == 0);
        if (begin >= end)
            throw std::runtime_error("Invalid trim: start >= end ");
        int fpp = m_asbd.mFramesPerPacket;
        int64_t sample_count;
        if (m_packet_info.mNumberValidFrames)
            sample_count = m_packet_info.mNumberValidFrames;
        else
            sample_count = m_packet_count * fpp;
        if (begin > sample_count)
            throw std::runtime_error("Trim start exceeds the length");
        if (end > sample_count)
            end = sample_count;

        int64_t start = begin;
        unsigned enc_delay = m_packet_info.mPrimingFrames;

        int overlapped_frames = 0; // required for MDCT based codec

        switch (m_asbd.mFormatID) {
        case kAudioFormatMPEGLayer3:
            if (!enc_delay)
                throw std::runtime_error("Cannot detect enc_delay of input. "
                                         "Cannot trim without them.");
            overlapped_frames = 576;
            break;
        case kAudioFormatMPEG4AAC:
            if (!enc_delay)
                throw std::runtime_error("Cannot detect enc_delay of input. "
                                         "Cannot trim without them.");
            if (m_oformat == kAudioFileAAC_ADTSType ||
                m_oformat == kAudioFileMPEG4Type)
                throw std::runtime_error("Cannot trim to ADTS or MP4. "
                                         "Use m4a/m4b/caf instead");
            overlapped_frames = fpp;
            break;
        case kAudioFormatMPEGLayer1:
        case kAudioFormatMPEGLayer2:
        case kAudioFormatMPEG4AAC_HE:
        case kAudioFormatMPEG4AAC_HE_V2:
            {
                std::stringstream ss;
                ss << "Trimming of this format is not supported: ";
                ss << strutil::w2us(afutil::getASBDFormatName(m_asbd));
                throw std::runtime_error(ss.str().c_str());
            }
        default:
            {
                std::stringstream ss;
                ss << "Trimming of this format is only available for caf output: ";
                ss << strutil::w2us(afutil::getASBDFormatName(m_asbd));
                if (fpp != 1 && m_oformat != kAudioFileCAFType)
                    throw std::runtime_error(ss.str().c_str());
            }
        }
        int64_t start_packet =
            std::max(start + enc_delay - overlapped_frames, 0LL) / fpp;
        /*
         * handle aditional inter frame dependency due to bit reservoir of mp3
         */
        if (m_asbd.mFormatID == kAudioFormatMPEGLayer3) {
            unsigned main_data_begin;
            unsigned size;
            unsigned sum = 0;
            getMP3FrameInfo(start_packet, &main_data_begin, 0);
            for (; start_packet > 0 && sum < main_data_begin; sum += size)
                getMP3FrameInfo(--start_packet, 0, &size);
        }
        int64_t new_enc_delay = start + enc_delay - (start_packet * fpp);
        int64_t final_frame = end + enc_delay + fpp;
        if (m_asbd.mFormatID == kAudioFormatMPEGLayer3)
            final_frame += fpp;
        int64_t final_packet = (final_frame - 1)/ fpp;
        if (final_packet > m_packet_count)
            final_packet = m_packet_count;

        m_offset = start_packet;
        m_packet_count = final_packet - start_packet;
        if (m_asbd.mFramesPerPacket > 1) {
            m_packet_info.mPrimingFrames = new_enc_delay;
            m_packet_info.mNumberValidFrames = end - begin;
            m_packet_info.mRemainderFrames =
                m_packet_count * fpp - new_enc_delay - end + begin;
        }
    }

    int process()
    {
        UInt32 nbytes = 0;
        int64_t rest = m_packet_count - m_current_packet;
        if (!rest)
            return 0;
        UInt32 npackets =
            readPackets(m_offset + m_current_packet, rest, &nbytes);
        if (!npackets)
            return 0;
        if (m_asbd.mFormatID == FOURCC('a','l','a','c') &&
            m_oformat != kAudioFileCAFType) {
            /*
             * AudioFile treats ALAC as constantly framed when reading;
             * We rather want frame length variably expressed with stss
             * in case of m4a.
             */
            if (m_current_packet + npackets >= m_packet_count) {
                size_t pos = m_packet_count - m_current_packet - 1;
                m_aspd[pos].mVariableFramesInPacket
                    = m_asbd.mFramesPerPacket - m_packet_info.mRemainderFrames;
            }
        }
        /*
         * At least AudioFileWritePackets seems to fail for ima4,
         * therefore we use AudioFileWritePackets() only when
         * packet information is in use for the format.
         */
        if (is_mpeg(m_oformat))
            write(ofd(), &m_buffer[0], nbytes);
        else if (requiresPacketTable())
            CHECKCA(AudioFileWritePackets(m_oaf, false, nbytes, &m_aspd[0],
                                          m_current_packet, &npackets,
                                          &m_buffer[0]));
        else
            CHECKCA(AudioFileWriteBytes(m_oaf, false, m_bytes_processed,
                                        &nbytes, &m_buffer[0]));

        m_current_packet += npackets;
        for (size_t i = 0; i < npackets; ++i) {
            if (m_asbd.mBytesPerPacket == 0)
                m_packet_pos.push_back(m_bytes_processed);
            if (m_aspd[0].mDataByteSize)
                m_bytes_processed += m_aspd[i].mDataByteSize;
            else
                m_bytes_processed += m_asbd.mBytesPerPacket;
        }
        return npackets;
    }
    void finalize()
    {
        m_packet_count = m_current_packet;
        AudioFilePacketTableInfo &pi = m_packet_info;
        if (is_mpeg(m_oformat)) {
            std::vector<uint8_t> xing_header;
            if (!isCBR())
                generateXingHeader(&xing_header);
            std::vector<uint8_t> id3tag;
            CFDictionaryPtr info_dict;
            getTags(&info_dict);
            {
                uint64_t prefetch_pos = 0;
                if (m_packet_pos.size() > 7) {
                    prefetch_pos = xing_header.size() +
                        m_packet_pos[m_packet_pos.size() - 8];
                }
                if (pi.mPrimingFrames || pi.mRemainderFrames ||
                    info_dict.get())
                    id3::build_id3tag(info_dict.get(), &pi, prefetch_pos,
                                      &id3tag);
            }
            if (id3tag.size() || xing_header.size()) {
                util::shift_file_content(ofd(),
                                         id3tag.size() + xing_header.size());
                lseek64(ofd(), 0, SEEK_SET);
                if (id3tag.size())
                    write(ofd(), &id3tag[0], id3tag.size());
                if (xing_header.size())
                    write(ofd(), &xing_header[0], xing_header.size());
            }
        } else if (m_asbd.mFormatID != FOURCC('a','l','a','c') ||
                   m_oformat == kAudioFileCAFType) {
            if (pi.mPrimingFrames || pi.mRemainderFrames) {
                try {
                    m_oaf.setPacketTableInfo(m_packet_info);
                } catch (...) {}
            }
        }
    }
private:
    int ifd() { return fileno(m_ifp.get()); }
    int ofd() { return fileno(m_ofp.get()); }

    bool requiresPacketTable()
    {
        return m_asbd.mBytesPerFrame == 0 || m_asbd.mFramesPerPacket == 0;
    }
    void setupAudioFile()
    {
        try {
            if (m_asbd.mFormatID == FOURCC('a','a','c','p')) {
                AudioChannelLayout acl = { 0 };
                acl.mChannelLayoutTag = m_channel_layout_tag;
                m_oaf.setChannelLayout(acl);
            } else {
                std::shared_ptr<AudioChannelLayout> acl;
                m_iaf.getChannelLayout(&acl);
                m_oaf.setChannelLayout(*acl.get());
            }
        } catch (const CoreAudioException &e) {
            if (!e.isNotSupportedError())
                throw;
        }

        try {
            std::vector<uint8_t> cookie;
            m_iaf.getMagicCookieData(&cookie);
            if (cookie.size())
                m_oaf.setMagicCookieData(&cookie[0], cookie.size());
        } catch (const CoreAudioException &e) {
            if (!e.isNotSupportedError())
                throw;
        }
        CFDictionaryPtr dict;
        getTags(&dict);
        if (dict.get()) {
            if (m_oformat == kAudioFileAIFFType ||
                m_oformat == kAudioFileAIFCType) {
                std::vector<uint8_t> id3;
                id3::build_id3tag(dict.get(), 0, 0, &id3);
                m_oaf.setUserData(FOURCC('I','D','3',' '), 0, &id3[0],
                                  id3.size());
            } else {
                try {
                    CFIndex n = CFDictionaryGetCount(dict.get());
                    if (n) m_oaf.setInfoDictionary(dict.get());
                } catch (const CoreAudioException &e) {
                    if (!e.isNotSupportedError())
                        throw;
                }
            }
        }

        try {
            if (requiresPacketTable()) {
                double length_in_seconds = m_packet_count *
                    m_asbd.mFramesPerPacket / m_asbd.mSampleRate;
                m_oaf.setReserveDuration(length_in_seconds);
            }
        } catch (const CoreAudioException &e) {
            if (!e.isNotSupportedError())
                throw;
        }
    }
    void getPacketTableInfo(AudioFilePacketTableInfo *info)
    {
        uint64_t ptotal = m_asbd.mFramesPerPacket * m_packet_count;
        /*
         * In case of AAC in MP4, we want to read iTunSMPB ourself.
         * Otherwise, go the standard way.
         */
        bool isAAC = (m_asbd.mFormatID == FOURCC('a','a','c',' ') ||
                      m_asbd.mFormatID == FOURCC('a','a','c','h') ||
                      m_asbd.mFormatID == FOURCC('a','a','c','p') ||
                      m_asbd.mFormatID == FOURCC('p','a','a','c'));
        if (!isAAC || !mp4::test_if_mp4(ifd())) {
            try {
                m_iaf.getPacketTableInfo(info);
                AudioFilePacketTableInfo &pi = *info;
                if ((pi.mPrimingFrames || pi.mRemainderFrames) &&
                    !pi.mNumberValidFrames) {
                    /*
                     * Take care of iTunSMPB in MP3.
                     * CoreAudio fills only mPrimingFrames and mRemainderFrames
                     */
                    pi.mNumberValidFrames =
                        ptotal - pi.mPrimingFrames - pi.mRemainderFrames;
                }
            } catch (const CoreAudioException &e) {
                if (!e.isNotSupportedError())
                    throw;
            }
            return;
        }
        AudioFilePacketTableInfo itinfo = { 0 };
        mp4::get_priming_info(ifd(), &itinfo);

        if (itinfo.mPrimingFrames || itinfo.mRemainderFrames) {
            uint64_t itotal = itinfo.mNumberValidFrames +
                itinfo.mPrimingFrames + itinfo.mRemainderFrames;

            if (m_asbd.mFormatID == FOURCC('a','a','c','h') ||
                m_asbd.mFormatID == FOURCC('a','a','c','p'))
            {
                if (itotal == ptotal) {
                    /*
                     * Looks like iTunSMPB of the source is counted in 
                     * upsampled scale
                     */
                    itinfo.mPrimingFrames >>= 1;
                    itinfo.mNumberValidFrames >>= 1;
                    itinfo.mRemainderFrames = ptotal / 2
                        - itinfo.mPrimingFrames - itinfo.mNumberValidFrames;
                    *info = itinfo;
                } else if (itotal == ptotal / 2)
                    *info = itinfo;
            } else if (itotal == ptotal)
                *info = itinfo;
        }
    }
    unsigned readPackets(uint64_t pos, unsigned npackets, UInt32 *nbytes)
    {
        *nbytes = m_buffer.size();
        UInt32 n = std::min(static_cast<unsigned>(m_aspd.size()), npackets);
        if (n > 0)
            CHECKCA(AudioFileReadPacketData(m_iaf, false, nbytes, &m_aspd[0],
                                            pos, &n, &m_buffer[0]));
        return n;
    }
    void getTags(CFDictionaryPtr *dict)
    {
        uint32_t format = m_iaf.getFileFormat();
        if (format == kAudioFileCAFType)
            /*
             * CoreAudio seems to *save* tags into CAF, 
             * but not to *load* it from CAF (why?).
             * Anyway, therefore we try to manually load it.
             */
            caf::get_info_dictionary(ifd(), dict);
        else if (format == kAudioFileAIFFType || format == kAudioFileAIFCType) {
            std::vector<uint8_t> id3;
            try {
                m_iaf.getUserData(FOURCC('I','D','3',' '), 0, &id3);
                id3::convert_to_caf_dictionary(&id3[0], id3.size(), dict);
            } catch (const CoreAudioException &e) {
                if (!e.isNotSupportedError())
                    throw;
            }
        } else {
            try {
                m_iaf.getInfoDictionary(dict);
            } catch (const CoreAudioException &e) {
                if (!e.isNotSupportedError())
                    throw;
            }
        }
    }
    bool isCBR()
    {
        if (m_asbd.mBytesPerPacket)
            return true;
        int prev_distance = 0;
        for (size_t i = 1; i < m_packet_pos.size(); ++i) {
            int distance = m_packet_pos[i] - m_packet_pos[i - 1];
            if (i > 1 && std::abs(distance - prev_distance) > 1)
                return false;
            prev_distance = distance;
        }
        if (m_packet_pos.size() > 1) {
            int distance =
                m_bytes_processed - m_packet_pos[m_packet_pos.size()-1];
            return std::abs(distance - prev_distance) < 2;
        }
        return true;
    }
    void generateXingHeader(std::vector<uint8_t> *result)
    {
        MPAHeader header(&m_buffer[0]);
        header.m_bitrate = 6;
        header.m_protection = 0;
        while (header.frame_size() < 176) {
            ++header.m_bitrate;
        }
        header.m_padding = 0;
        std::vector<uint8_t> buf(header.frame_size());
        header.get_bytes(&buf[0]);
        size_t pos = header.side_info_end();
        std::memcpy(&buf[pos], "Xing", 4), pos += 4;
        /* FRAMES_FLAG | BYTES_FLAG | TOC_FLAG */
        std::memcpy(&buf[pos], "\x00\x00\x00\x07", 4), pos += 4;
        uint32_t n = util::h2big32(m_packet_count);
        std::memcpy(&buf[pos], &n, 4), pos += 4;
        n = util::h2big32(m_bytes_processed + header.frame_size());
        std::memcpy(&buf[pos], &n, 4), pos += 4;

        unsigned percent = 0;
        uint64_t toc[100];
        for (size_t i = 0; i < m_packet_count; ++i)
            while (i * 100 / m_packet_count >= percent)
                toc[percent++] = m_packet_pos[i];

        size_t off = header.frame_size();
        for (size_t i = 0; i < 100; ++i)
            buf[pos++] = static_cast<uint8_t>((toc[i] + off) * 255.0 /
                                              (m_bytes_processed + off) + 0.5);
        pos += 4; /* we don't write vbr quality scale */
        std::sprintf(reinterpret_cast<char*>(&buf[pos]),
                     "cafmux %s", cafmux_version);
        result->swap(buf);
    }
    void getMP3FrameInfo(uint64_t packet, unsigned *main_data_begin,
                         unsigned *main_data_size)
    {
        UInt32 nbytes;
        readPackets(packet, 1, &nbytes);
        MPAHeader hdr(&m_buffer[0]);
        unsigned sis = hdr.side_info_start();
        unsigned mdb = m_buffer[sis];
        if (hdr.version_index() == 0)
            mdb  = (mdb << 1) | ((m_buffer[sis + 1] & 0x80) >> 7);
        if (main_data_begin)
            *main_data_begin = mdb;
        if (main_data_size)
            *main_data_size  = hdr.frame_size() - hdr.side_info_end();
    }
};

static
bool parse_timespec(const wchar_t *spec, double sample_rate, int64_t *result)
{
    int hh, mm, ssi, ff = 0, sign = 1;
    wchar_t a, b;
    double ss;
    if (!spec || !*spec)
        return false;
    if (std::swscanf(spec, L"%lld%c%c", result, &a, &b) == 2 && a == L's')
        return true;
    if (spec[0] == L'-') {
        sign = -1;
        ++spec;
    }
    if (std::swscanf(spec, L"%d:%d:%lf%c", &hh, &mm, &ss, &a) == 3)
        ss = ss + ((hh * 60.0) + mm) * 60.0;
    else if (std::swscanf(spec, L"%d:%lf%c", &mm, &ss, &a) == 2)
        ss = ss + mm * 60.0;
    else if (std::swscanf(spec, L"%lf%c", &ss, &a) == 1)
        ;
    else if (std::swscanf(spec, L"%d:%d:%d%c", &mm, &ssi, &ff, &a) == 4 &&
             a == L'f')
        ss = ff / 75.0 + ((mm * 60.0) + ssi);
    else if (std::swscanf(spec, L"%d:%d%c", &ssi, &ff, &a) == 3 && a == L'f')
        ss = ff / 75.0 + ssi;
    else if (std::swscanf(spec, L"%d%c", &ff, &a) == 2 && a == L'f')
        ss = ff / 75.0;
    else
        return false;

    *result = sign * static_cast<int64_t>(sample_rate * ss + .5);
    return true;
}
    
static
void process(const std::wstring &ifilename, const std::wstring &ofilename,
             uint32_t oformat, const wchar_t *start, const wchar_t *end)
{
    Remuxer remuxer(ifilename, ofilename, oformat);

    int64_t start_pos = 0, end_pos = INT64_MAX;
    if (start && !parse_timespec(start, remuxer.sampleRate(), &start_pos))
        throw std::runtime_error("Invalid timespec for -s");
    if (end && !parse_timespec(end, remuxer.sampleRate(), &end_pos))
        throw std::runtime_error("Invalid timespec for -e");
    if (start || end)
        remuxer.trim(start_pos, end_pos);

    int percent = 0;
    try {
        uint64_t total = remuxer.packetCount();
        while (remuxer.process()) {
            int p = 100.0 * remuxer.currentPacket() / total + 0.5;
            if (p != percent) {
                std::fwprintf(stderr, L"\r%d%% processed", p);
                percent = p;
            }
        }
    } catch (...) {
        std::putwc('\n', stderr);
        throw;
    }
    std::putwc('\n', stderr);
    remuxer.finalize();
}

static
std::string format_fcc(uint32_t fcc)
{
    uint8_t ch[5] = { 0 };
    ch[0] = fcc >> 24;
    ch[1] = (fcc >> 16) & 0xff;
    ch[2] = (fcc >> 8) & 0xff;
    ch[3] = fcc & 0xff;
    std::stringstream ss;
    for (size_t i = 0; i < 4; ++i) {
        if (std::isprint(ch[i], std::locale("C")))
            ss << static_cast<char>(ch[i]);
        else
            ss << "\\" << std::setw(3) << std::setfill('0')
               << std::oct << static_cast<int>(ch[i]);
    }
    return ss.str();
}

static
void print_type_info(uint32_t type)
{
    std::wstring name = afutil::getFileTypeName(type);
    std::vector<std::wstring> extensions;
    afutil::getExtensionsForType(type, &extensions);
    std::wprintf(L"%hs: %s", format_fcc(type).c_str(), name.c_str());
    const wchar_t *sep = L" (";
    for (size_t j = 0; j < extensions.size(); ++j) {
        std::wprintf(L"%s%s", sep, extensions[j].c_str());
        sep = L", ";
    }
    std::wprintf(L")\n");
    std::vector<uint32_t> codecs;
    afutil::getAvailableFormatIDs(type, &codecs);
    for (size_t i = 0; i < codecs.size(); ++i) {
        AudioStreamBasicDescription asbd =  { 0 };
        asbd.mFormatID = codecs[i];
        try {
            std::wprintf(L"    %hs: %s\n", format_fcc(codecs[i]).c_str(),
                         afutil::getASBDFormatName(asbd).c_str());
        } catch (...) {}
    }
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
std::wstring getAppleApplicationSupportPath()
{
    HKEY hKey = 0;
    const wchar_t *subkey =
        L"SOFTWARE\\Apple Inc.\\Apple Application Support";
    LSTATUS rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0,
                               KEY_READ, &hKey);
    if (rc == ERROR_SUCCESS) {
        std::shared_ptr<HKEY__> hKeyPtr(hKey, RegCloseKey);
        DWORD size;
        rc = RegQueryValueExW(hKey, L"InstallDir", 0, 0, 0, &size);
        if (rc == ERROR_SUCCESS) {
            std::vector<wchar_t> vec(size/sizeof(wchar_t));
            rc = RegQueryValueExW(hKey, L"InstallDir", 0, 0,
                                  reinterpret_cast<LPBYTE>(&vec[0]), &size);
            if (rc == ERROR_SUCCESS)
                return &vec[0];
        }
    }
    return L"";
}

static
std::string getCoreAudioToolboxVersion(HMODULE hDll)
{
    HRSRC hRes = FindResourceExW(hDll,
                                 RT_VERSION,
                                 MAKEINTRESOURCEW(VS_VERSION_INFO),
                                 MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US));
    std::string data;
    {
        DWORD cbres = SizeofResource(hDll, hRes);
        HGLOBAL hMem = LoadResource(hDll, hRes);
        if (hMem) {
            char *pc = static_cast<char*>(LockResource(hMem));
            if (pc && cbres)
                data.assign(pc, cbres);
            FreeResource(hMem);
        }
    }
    // find dwSignature of VS_FIXEDFILEINFO
    std::stringstream ss;
    size_t pos = data.find("\xbd\x04\xef\xfe");
    if (pos != std::string::npos) {
        VS_FIXEDFILEINFO vfi;
        std::memcpy(&vfi, data.c_str() + pos, sizeof vfi);
        WORD v[4];
        v[0] = HIWORD(vfi.dwFileVersionMS);
        v[1] = LOWORD(vfi.dwFileVersionMS);
        v[2] = HIWORD(vfi.dwFileVersionLS);
        v[3] = LOWORD(vfi.dwFileVersionLS);
        ss << v[0] << "." << v[1] << "." << v[2] << "." << v[3];
    }
    return ss.str();
}

static
HMODULE load_coreaudio_toolbox()
{
    std::wstring path = win32::get_module_directory();
    std::vector<std::wstring> candidates;
    candidates.push_back(path);
    candidates.push_back(path + L"QTfiles\\");
    if ((path = getAppleApplicationSupportPath()) != L"") {
        if (path.back() != L'\\')
            path.push_back(L'\\');
        candidates.push_back(path);
    }
    std::vector<std::wstring>::const_iterator it;
    HMODULE hmod = 0;
    for (it = candidates.begin(); it != candidates.end(); ++it) {
        path = *it + L"CoreAudioToolbox.dll";
        hmod = LoadLibraryExW(path.c_str(), 0,
                              LOAD_WITH_ALTERED_SEARCH_PATH);
        if (hmod)
            break;
    }
    if (!hmod) {
        throw std::runtime_error("Cannot load CoreAudioToolbox.dll");
    }
    return hmod;
}

static
FARPROC WINAPI dll_failure_hook(unsigned notify, PDelayLoadInfo pdli)
{
    win32::throw_error(pdli->szDll, pdli->dwLastError);
    return 0;
}

void usage()
{
    std::fwprintf(stderr,
L"cafmux %hs\n"
L"usage: cafmux -p             (print available formats)\n"
L"       cafmux -i INFILE      (print audio format of INFILE)\n"
L"       cafmux [-s START][-e END] INFILE OUTFILE (remux INFILE to OUTFILE)\n"
L"\n"
L"when given -s or -e, sub portion of the INFILE is extracted.\n"
L"when -s is omitted, extraction start from the beginning of the input.\n"
L"when -e is omitted, extraction ends at the end of the input.\n"
L"(trimming by -s and/or -e is only available for LPCM, LC-AAC, and MP3)\n"
L"\n"
L"START/END accept following formats:\n"
L"  <integer>s             Offset in number of samples, followed by \"s\"\n"
L"  [[hh:]mm:]ss[.sss..]   Offset in seconds.\n"
L"                         Parts enclosed by brackets can be ommited\n"
L"  <[[mm:]ss:]ff>f        Offset in CD frames, followed by \"f\"\n"
L"                         (1 frame = 1/75 second).\n"
    , cafmux_version);
    std::exit(1);
}

int wmain(int argc, wchar_t **argv)
{
#ifdef _DEBUG
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF|_CRTDBG_CHECK_ALWAYS_DF);
#endif
    _setmode(0, _O_BINARY);
    _setmode(1, _O_U8TEXT);
    _setmode(2, _O_U8TEXT);
    std::setbuf(stderr, 0);

    bool opt_p = false;
    wchar_t *opt_i = 0, *opt_s = 0, *opt_e = 0;

    int ch;
    while ((ch = getopt::getopt(argc, argv, L"pi:s:e:")) != -1) {
        switch (ch) {
        case 'p':
            opt_p = true;
            break;
        case 'i':
            opt_i = getopt::optarg;
            break;
        case 's':
            opt_s = getopt::optarg;
            break;
        case 'e':
            opt_e = getopt::optarg;
            break;
        default:
            usage();
        }
    }
    argc -= getopt::optind;
    argv += getopt::optind;
    if (!opt_p && !opt_i && argc < 2)
        usage();

    try {
        __pfnDliFailureHook2 = dll_failure_hook;
        std::shared_ptr<HINSTANCE__> C(load_coreaudio_toolbox(), FreeLibrary);
        std::string ver = getCoreAudioToolboxVersion(C.get());
        std::fwprintf(stderr, L"CoreAudioToolbox %hs\n", ver.c_str());
        if (opt_p) {
            list_readable_types();
        } else if (opt_i) {
            show_format(opt_i);
        } else {
            uint32_t type = afutil::getTypesForExtension(argv[1]);
            process(argv[0], argv[1], type, opt_s, opt_e);
        }
        return 0;
    } catch (const std::exception & e) {
        std::fwprintf(stderr, L"ERROR: %s\n", strutil::us2w(e.what()));
        return 2;
    }
}
