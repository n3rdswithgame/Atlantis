#include "common/logger.h"

#include "core/cpu.h"
#include "core/mem.h"
#include <type_traits>

int main(int argc, char** argv)
{
	DEBUG("{}", std::is_trivially_destructible<mem::region>::value);

	DEBUG("unbanking {} to {}", cpu::gpr_t::r7, cpu::unbankReg(cpu::mode_t::usr, cpu::gpr_t::r7));

    return 0;
}