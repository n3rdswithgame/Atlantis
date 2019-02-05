#include "rom.h"

namespace gba {

	rom::rom(const std:vector<u8>& r) : raw(r) {
		u8* ptr = raw.data();
		//TODO: populate header;
	}

}
