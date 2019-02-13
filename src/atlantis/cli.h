#ifndef ATLANTIS_CLI
#define ATLANTIS_CLI

#include <string>

namespace atlantis {
	struct cli_args {
		std::string rom_path  = "";
		std::string bios_path = "";
	};
} //atlantis

#endif //ATLANTOS_CLI