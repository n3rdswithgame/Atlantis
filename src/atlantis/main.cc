#include "common/logger.h"

#include "core/cpu.h"
#include "core/mem.h"
#include <type_traits>

void parseArgs(int argc, char** argv) {
	//TODO: implement later
	//for now this is just to silence the unused argument
	//warning in main, but will eventually do this proper
	argv[0][0] = static_cast<s8>(argc & 0xff); 
}

int main(int argc, char** argv)
{
	parseArgs(argc, argv);

    return 0;
}