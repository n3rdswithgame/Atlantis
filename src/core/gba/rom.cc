#include "rom.h"

#include <string>
#include <vector>

#include "common/file.h"
#include "common/logger.h"


namespace gba::rom {


	rom::rom(const std::string& filename) : raw(file::readFrom(filename)){
		populateHeader();
	}

	rom::rom(const std::vector<u8>& r) : raw(r) {
		populateHeader();
	}

	void rom::populateHeader() {
		//TODO: implement
	}

} //namespace gba::rom