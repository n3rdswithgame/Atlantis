#include "common/logger.h"
#include "core/mem.h"
#include <type_traits>

int main(int argc, char** argv)
{
	DEBUG("{}", std::is_trivially_destructible<mem::region>::value);

    return 0;
}