#include "common/logger.h"

#include "core/mem.h"

#include <iostream>
#include <type_traits>

#include <clipp.h>

void parseArgs(int argc, char** argv) {
	//TODO: implement later
	//for now this is just to silence the unused argument
	//warning in main, but will eventually do this proper
	argv[0][0] = static_cast<s8>(argc & 0xff); 
}

int main(int argc, char** argv)
{
	parseArgs(argc, argv);

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