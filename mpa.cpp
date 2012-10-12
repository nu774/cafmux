#include "mpa.h"
#include "bitstream.h"

void MPAHeader::fill(const uint8_t *data)
{
    BitStream bs(data, 4);
    this->m_sync = bs.get(11);
    this->m_version = bs.get(2);
    this->m_layer = bs.get(2);
    this->m_protection = bs.get(1);
    this->m_bitrate = bs.get(4);
    this->m_sampling_rate = bs.get(2);
    this->m_padding = bs.get(1);
    this->m_private_bit = bs.get(1);
    this->m_channel_mode = bs.get(2);
    this->m_mode_extension = bs.get(2);
    this->m_copywrite = bs.get(1);
    this->m_original = bs.get(1);
    this->m_emphasis = bs.get(2);
    if (this->m_version == 1)
	throw std::runtime_error("Unsupported MPEG audio version");
}

void MPAHeader::get_bytes(uint8_t *data) const
{
    BitStream bs;
    bs.put(this->m_sync, 11);
    bs.put(this->m_version, 2);
    bs.put(this->m_layer, 2);
    bs.put(this->m_protection, 1);
    bs.put(this->m_bitrate, 4);
    bs.put(this->m_sampling_rate, 2);
    bs.put(this->m_padding, 1);
    bs.put(this->m_private_bit, 1);
    bs.put(this->m_channel_mode, 2);
    bs.put(this->m_mode_extension, 2);
    bs.put(this->m_copywrite, 1);
    bs.put(this->m_original, 1);
    bs.put(this->m_emphasis, 2);
    std::memcpy(data, bs.data(), 4);
}
