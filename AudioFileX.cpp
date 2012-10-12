#include "AudioFileX.h"

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
}
