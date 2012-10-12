#ifndef ID3_H
#define ID3_H

#include <vector>
#include <stdint.h>
#include "CoreAudio/AudioFile.h"

namespace id3 {
    void build_id3tag(CFDictionaryRef dict,
		      const AudioFilePacketTableInfo *packet_info,
		      uint32_t prefetch_point,
		      std::vector<uint8_t> *result);
}
#endif
