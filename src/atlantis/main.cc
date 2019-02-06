#include <iostream>
#include <optional>
#include <string>
#include <type_traits>

//#include <clara.hpp>

#include "cli.h"
#include "ver.h"

#include "common/logger.h"

#include "core/mem.h"
#include "core/gba/gba.h"

#include "core/arm/ins/ins.h"


//std::optional<atlantis::cli_args> parseArgs(int argc, char** argv) {
//	using namespace clara;
//	
//	bool show_help = false;
//	bool show_ver = false;
//
//	atlantis::cli_args cli_args;
//	auto cli = Opt(cli_args.rom_name, "rom")["-r"]["--rom-name"]("the rom to open")
//		| Opt(show_ver)["-v"]["--ver"]["--version"]("show the version")
//		| Help(show_help)
//	;
//
//	auto result = cli.parse(Args(argc, argv));
//
//
//	if(!result){
//		DEBUG("failed to parse commandline args");
//		return std::nullopt;
//	}
//
//	if(show_help) {
//		std::cout << cli << "\n";
//		return std::nullopt;
//	} else if(show_ver) {
//		std::cout << "atlantis: version "<< VERSION <<"\n";
//		return std::nullopt;
//	}
//
//	return cli_args;
//}

template<typename T>
void test() {
	T  i(arm::cpu::reg::r1, arm::cpu::reg::r0, arm::cpu::reg::r2);
	DEBUG("{:08x}", static_cast<size_t>(i) );
}

int main(int argc, char** argv)
{
	(void)argc;
	(void)argv;	

	test<arm::ins::Add>();
	test<arm::ins::AddS>();
	
	test<arm::ins::Eor>();
	test<arm::ins::EorS>();
	
	test<arm::ins::Mov>();
	test<arm::ins::MovS>();
	
	test<arm::ins::Rsb>();
	test<arm::ins::RsbS>();
	
	test<arm::ins::Mvn>();
	test<arm::ins::MvnS>();



	//auto cli_args = parseArgs(argc, argv);

	//if(!cli_args) {
	//	return -1;
	//}

	//atlantis::cli_args& args = *cli_args;

	//if(args.rom_name == "") {
	//	FATAL("rom name was not passed");
	//	return -1;
	//}

	//gba::gba gba(args.rom_name);

    return 0;
}