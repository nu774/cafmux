#include "mpa.h"
#include "bitstream.h"

void MPAHeader::fill(const uint8_t *data)
{
    BitStream bs(data, 4);
    m_sync           = bs.get(11);
    m_version        = bs.get(2);
    m_layer          = bs.get(2);
    m_protection     = bs.get(1);
    m_bitrate        = bs.get(4);
    m_sampling_rate  = bs.get(2);
    m_padding        = bs.get(1);
    m_private_bit    = bs.get(1);
    m_channel_mode   = bs.get(2);
    m_mode_extension = bs.get(2);
    m_copywrite      = bs.get(1);
    m_original       = bs.get(1);
    m_emphasis       = bs.get(2);
    if (m_sync != 0x7ff || m_version == 1 || m_layer == 0 || 
        m_sampling_rate == 3 || m_bitrate == 0 || m_bitrate == 15)
        throw std::runtime_error("Invalid MPEG Frame Header");
}

void MPAHeader::get_bytes(uint8_t *data) const
{
    BitStream bs;
    bs.put(m_sync, 11);
    bs.put(m_version, 2);
    bs.put(m_layer, 2);
    bs.put(m_protection, 1);
    bs.put(m_bitrate, 4);
    bs.put(m_sampling_rate, 2);
    bs.put(m_padding, 1);
    bs.put(m_private_bit, 1);
    bs.put(m_channel_mode, 2);
    bs.put(m_mode_extension, 2);
    bs.put(m_copywrite, 1);
    bs.put(m_original, 1);
    bs.put(m_emphasis, 2);
    std::memcpy(data, bs.data(), 4);
}
