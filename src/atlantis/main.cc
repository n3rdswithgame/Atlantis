#include <iostream>
#include <optional>
#include <string>
#include <type_traits>

#include <clara.hpp>

#include "cli.h"
#include "ver.h"

#include "common/logger.h"

#include "core/mem.h"
#include "core/gba/gba.h"



std::optional<atlantis::cli_args> parseArgs(int argc, char** argv) {
	using namespace clara;
	
	bool show_help = false;
	bool show_ver = false;

	atlantis::cli_args 	cli_args;
	auto cli = Opt(cli_args.rom_path, "rom")["-r"]["--rom-path"]("the rom to open")
		| Opt(cli_args.bios_path, "bios")["-b"]["--bios-path"]("the gba bios")
		| Opt(show_ver)["-v"]["--ver"]["--version"]("show the version")
		| Help(show_help)
	;

	auto result = cli.parse(Args(argc, argv));


	if(!result){
		FATAL("failed to parse commandline args");
		return std::nullopt;
	}

	if(show_help) {
		std::cout << cli << "\n";
		return std::nullopt;
	} else if(show_ver) {
		std::cout << "atlantis: version "<< VERSION <<"\n";
		return std::nullopt;
	}

	return cli_args;
}


int validateArgs(atlantis::cli_args& args) {
	int ret = 0;

	if(args.rom_path == "") {
		FATAL("rom path was not passed");
		ret = -1;
	}
	if (args.bios_path == "") {
		FATAL("bios path was not passed");
		ret = -1;
	}

	return ret;
}

int main(int argc, char** argv)
{
	auto cli_args = parseArgs(argc, argv);
	if(!cli_args) {
		return -1;
	}

	atlantis::cli_args& args = *cli_args;

	if(int ret = validateArgs(args);
		ret != 0) {
		return ret;
	}
	

	gba::gba gba(args.rom_path);

    return 0;
}