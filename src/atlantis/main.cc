#include <iostream>
#include <optional>
#include <type_traits>


#include "cli.h"

#include "common/logger.h"

#include "core/mem.h"


std::optional<atlantis::cli_args> parseArgs(int, char**) {
	
	//if(parse(argc, argv, cli)) {

	//} else {
	//	std::cout << usage_lines(cli, "atlantis");
	//	return std::nullopt;
	//}

	//return cli_args;

	return {};
}

int main(int argc, char** argv)
{
	auto cli_args = parseArgs(argc, argv);

	(void)cli_args;	

	//if(!cli_args) {
	//	return -1;
	//}

	//atlantis::cli_args& args = *cli_args;

	//(void)args;

	DEBUG("Color Test");
	STATUS("Color Test");
	WARNING("Color Test");
	ERROR("Color Test");
	CRITICAL("Color Test");
	FATAL("Color Test");

	DEBUG("Color Test");
	STATUS("Color Test");
	WARNING("Color Test");
	ERROR("Color Test");
	CRITICAL("Color Test");
	FATAL("Color Test");

	std::cout <<"This is some test text" << '\n';
	std::cout <<"This is some test text";
	std::cout <<"This is some test text" << '\n';
	std::cout <<"This is some test text" << '\n';
	std::cout <<"This is some test text" << '\n';

    return 0;
}