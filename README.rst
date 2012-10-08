=========================================
cafmux - CoreAudioToolbox remuxer (win32)
=========================================

Remux audio files with the help of Audio File Services of CoreAudioToolbox.

Usage:
    cafmux -p  (prints available formats)

    cafmux INFILE OUTFILE

Notice
------
1) This program doesn't convert LPCM sample format. Therefore you cannot 
   remux big endian LPCM format(such as AIFF) to little one(such as WAV), etc.
2) MP4 container is available, but available codecs are quite limited.
3) M4A, M4B and MP4 are distinguished by CoreAudio;
   You cannot mux ALAC into (standard) MP4.
   Also, You cannot write iTunSMPB(important for gapless playback)
   into MP4.
   Therefore, you should almost always use M4A for writing (instead of MP4).
4) CoreAudio says AC3 is available (thus printed in -p), but actually is not.

How to build
------------
You need Microsoft Visual C++ 2010 to build cafmux.
