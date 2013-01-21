#ifndef MPA_H
#define MPA_H

#include <string>
#include <stdint.h>

struct MPAHeader {
    unsigned m_sync: 11;
    unsigned m_version: 2;
    unsigned m_layer: 2;
    unsigned m_protection: 1;
    unsigned m_bitrate: 4;
    unsigned m_sampling_rate: 2;
    unsigned m_padding: 1;
    unsigned m_private_bit: 1;
    unsigned m_channel_mode: 2;
    unsigned m_mode_extension: 2;
    unsigned m_copywrite: 1;
    unsigned m_original: 1;
    unsigned m_emphasis: 2;

    MPAHeader() { std::memset(this, 0, sizeof(MPAHeader)); }
    MPAHeader(const uint8_t *data)
    {
        fill(data);
    }
    void fill(const uint8_t *data);
    void get_bytes(uint8_t *data) const;
    const char *version() const
    {
        static const char *tab[] = { "2.5", "reserved", "2", "1" };
        return tab[m_version];
    }
    uint32_t version_index() const
    {
        static uint32_t tab[] = { 2, 0xff, 1, 0 };
        return tab[m_version];
    }
    uint32_t layer() const
    {
        return 4 - m_layer;
    }
    uint32_t layer_index() const
    {
        return 3 - m_layer;
    }
    int is_mono() const
    {
        return m_channel_mode == 3;
    }
    uint32_t bitrate() const
    {
        static const uint32_t tab[3][3][15] = {
            {
                {0,32,64,96,128,160,192,224,256,288,320,352,384,416,448,},
                {0,32,48,56, 64, 80, 96,112,128,160,192,224,256,320,384,},
                {0,32,40,48, 56, 64, 80, 96,112,128,160,192,224,256,320,}
            },
            {
                {0,32,48,56,64,80,96,112,128,144,160,176,192,224,256,},
                {0,8,16,24,32,40,48,56,64,80,96,112,128,144,160,},
                {0,8,16,24,32,40,48,56,64,80,96,112,128,144,160,}
            },
            {
                {0,32,48,56,64,80,96,112,128,144,160,176,192,224,256,},
                {0,8,16,24,32,40,48,56,64,80,96,112,128,144,160,},
                {0,8,16,24,32,40,48,56,64,80,96,112,128,144,160,}
            }
        };
        return tab[version_index()][layer_index()][m_bitrate];
    }
    uint32_t sampling_rate() const
    {
        static const uint32_t tab[3][3] = {
            { 44100, 48000, 32000 },
            { 22050, 24000, 16000 },
            { 11025, 12000, 8000  }
        };
        return tab[version_index()][m_sampling_rate];
    }
    uint32_t samples_per_frame() const
    {
        static const uint32_t tab[3][3] = {
            { 384, 1152, 1152 },
            { 384, 1152, 576  },
            { 384, 1152, 576  },
        };
        return tab[version_index()][layer_index()];
    }
    uint32_t frame_size() const
    {
        static const uint32_t spfdiv8[3][3] = {
            { 12, 144, 144 }, { 12, 144, 72 }, { 12, 144, 72 }
        };
        static const uint32_t slot_size[3] = { 4, 1, 1 };
        return (spfdiv8[version_index()][layer_index()] * bitrate() * 1000
            / sampling_rate() + m_padding) * slot_size[layer_index()];
    }
    uint32_t side_information_size() const
    {
        static const uint32_t tab[3][2] = {
            { 32, 17 }, { 17, 9 }, { 17, 9 }
        };
        return tab[version_index()][is_mono()];
    }
};

#endif
