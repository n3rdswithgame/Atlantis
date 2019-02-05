#ifndef FILE_H
#define FILE_H

#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "logger.h"
#include "types.h"

namespace file {
	inline std::vector<u8> readFrom(std::string fileName) {
		std::fstream file(fileName, std::ios::binary | std::ios::in);

		if(!file.is_open()){
			CRITICAL("Failed to open file: {}", fileName);
			return {};
		}
		STATUS("Opened file: {}", fileName);

		file.seekg(0, std::ios::end);//seek to the end
		std::vector<u8> raw(static_cast<size_t>(file.tellg()));//reserve raw with the needed size hold everything
		file.seekg(0); //reset to beginning of file

		file.read(reinterpret_cast<char*>(raw.data()), static_cast<std::streamoff>(raw.size()));

		return raw;
	}
}

#endif