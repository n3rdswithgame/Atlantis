#include <catch2/catch.hpp>

#include <numeric>

#include "../../src/core/cpu.h"

TEST_CASE("Testing cpu register unbanking", "[unbanking]") {
	
	using cpu::reg;
	using cpu::mode_t;
	using cpu::gpr_t;

	cpu::state cpu;
	std::iota(cpu.gpr.begin(), cpu.gpr.end(), 0);


	SECTION("user mode") {
		cpu.current_mode = mode_t::usr;

		REQUIRE(cpu[reg::r0] == gpr_t::r0);
		REQUIRE(cpu[reg::r1] == gpr_t::r1);
		REQUIRE(cpu[reg::r2] == gpr_t::r2);
		REQUIRE(cpu[reg::r3] == gpr_t::r3);
		REQUIRE(cpu[reg::r4] == gpr_t::r4);
		REQUIRE(cpu[reg::r5] == gpr_t::r5);
		REQUIRE(cpu[reg::r6] == gpr_t::r6);
		REQUIRE(cpu[reg::r7] == gpr_t::r7);
		REQUIRE(cpu[reg::r8] == gpr_t::r8);
		REQUIRE(cpu[reg::r9] == gpr_t::r9);
		REQUIRE(cpu[reg::r10] == gpr_t::r10);
		REQUIRE(cpu[reg::r11] == gpr_t::r11);
		REQUIRE(cpu[reg::r12] == gpr_t::r12);
		REQUIRE(cpu[reg::sp]  == gpr_t::r13);
		REQUIRE(cpu[reg::lr]  == gpr_t::r14);
		REQUIRE(cpu[reg::pc]  == gpr_t::r15);
	}

	SECTION("fast interupt request mode") {
		cpu.current_mode = mode_t::fiq;

		REQUIRE(cpu[reg::r0] == gpr_t::r0);
		REQUIRE(cpu[reg::r1] == gpr_t::r1);
		REQUIRE(cpu[reg::r2] == gpr_t::r2);
		REQUIRE(cpu[reg::r3] == gpr_t::r3);
		REQUIRE(cpu[reg::r4] == gpr_t::r4);
		REQUIRE(cpu[reg::r5] == gpr_t::r5);
		REQUIRE(cpu[reg::r6] == gpr_t::r6);
		REQUIRE(cpu[reg::r7] == gpr_t::r7);

		REQUIRE(cpu[reg::r8] == gpr_t::r8_fiq);
		REQUIRE(cpu[reg::r9] == gpr_t::r9_fiq);
		REQUIRE(cpu[reg::r10] == gpr_t::r10_fiq);
		REQUIRE(cpu[reg::r11] == gpr_t::r11_fiq);
		REQUIRE(cpu[reg::r12] == gpr_t::r12_fiq);
		REQUIRE(cpu[reg::sp]  == gpr_t::r13_fiq);
		REQUIRE(cpu[reg::lr]  == gpr_t::r14_fiq);
		REQUIRE(cpu[reg::pc]  == gpr_t::r15);
	}


	SECTION("interupt request mode") {
		cpu.current_mode = mode_t::irq;

		REQUIRE(cpu[reg::r0] == gpr_t::r0);
		REQUIRE(cpu[reg::r1] == gpr_t::r1);
		REQUIRE(cpu[reg::r2] == gpr_t::r2);
		REQUIRE(cpu[reg::r3] == gpr_t::r3);
		REQUIRE(cpu[reg::r4] == gpr_t::r4);
		REQUIRE(cpu[reg::r5] == gpr_t::r5);
		REQUIRE(cpu[reg::r6] == gpr_t::r6);
		REQUIRE(cpu[reg::r7] == gpr_t::r7);
		REQUIRE(cpu[reg::r8] == gpr_t::r8);
		REQUIRE(cpu[reg::r9] == gpr_t::r9);
		REQUIRE(cpu[reg::r10] == gpr_t::r10);
		REQUIRE(cpu[reg::r11] == gpr_t::r11);
		REQUIRE(cpu[reg::r12] == gpr_t::r12);

		REQUIRE(cpu[reg::sp]  == gpr_t::r13_irq);
		REQUIRE(cpu[reg::lr]  == gpr_t::r14_irq);
		REQUIRE(cpu[reg::pc]  == gpr_t::r15);
	}

	SECTION("supervisor mode") {
		cpu.current_mode = mode_t::svc;

		REQUIRE(cpu[reg::r0] == gpr_t::r0);
		REQUIRE(cpu[reg::r1] == gpr_t::r1);
		REQUIRE(cpu[reg::r2] == gpr_t::r2);
		REQUIRE(cpu[reg::r3] == gpr_t::r3);
		REQUIRE(cpu[reg::r4] == gpr_t::r4);
		REQUIRE(cpu[reg::r5] == gpr_t::r5);
		REQUIRE(cpu[reg::r6] == gpr_t::r6);
		REQUIRE(cpu[reg::r7] == gpr_t::r7);
		REQUIRE(cpu[reg::r8] == gpr_t::r8);
		REQUIRE(cpu[reg::r9] == gpr_t::r9);
		REQUIRE(cpu[reg::r10] == gpr_t::r10);
		REQUIRE(cpu[reg::r11] == gpr_t::r11);
		REQUIRE(cpu[reg::r12] == gpr_t::r12);

		REQUIRE(cpu[reg::sp]  == gpr_t::r13_svc);
		REQUIRE(cpu[reg::lr]  == gpr_t::r14_svc);
		REQUIRE(cpu[reg::pc]  == gpr_t::r15);
	}

	SECTION("abort mode") {
		cpu.current_mode = mode_t::abt;

		REQUIRE(cpu[reg::r0] == gpr_t::r0);
		REQUIRE(cpu[reg::r1] == gpr_t::r1);
		REQUIRE(cpu[reg::r2] == gpr_t::r2);
		REQUIRE(cpu[reg::r3] == gpr_t::r3);
		REQUIRE(cpu[reg::r4] == gpr_t::r4);
		REQUIRE(cpu[reg::r5] == gpr_t::r5);
		REQUIRE(cpu[reg::r6] == gpr_t::r6);
		REQUIRE(cpu[reg::r7] == gpr_t::r7);
		REQUIRE(cpu[reg::r8] == gpr_t::r8);
		REQUIRE(cpu[reg::r9] == gpr_t::r9);
		REQUIRE(cpu[reg::r10] == gpr_t::r10);
		REQUIRE(cpu[reg::r11] == gpr_t::r11);
		REQUIRE(cpu[reg::r12] == gpr_t::r12);

		REQUIRE(cpu[reg::sp]  == gpr_t::r13_abt);
		REQUIRE(cpu[reg::lr]  == gpr_t::r14_abt);
		REQUIRE(cpu[reg::pc]  == gpr_t::r15);
	}

	SECTION("system mode") {
		cpu.current_mode = mode_t::sys;

		REQUIRE(cpu[reg::r0] == gpr_t::r0);
		REQUIRE(cpu[reg::r1] == gpr_t::r1);
		REQUIRE(cpu[reg::r2] == gpr_t::r2);
		REQUIRE(cpu[reg::r3] == gpr_t::r3);
		REQUIRE(cpu[reg::r4] == gpr_t::r4);
		REQUIRE(cpu[reg::r5] == gpr_t::r5);
		REQUIRE(cpu[reg::r6] == gpr_t::r6);
		REQUIRE(cpu[reg::r7] == gpr_t::r7);
		REQUIRE(cpu[reg::r8] == gpr_t::r8);
		REQUIRE(cpu[reg::r9] == gpr_t::r9);
		REQUIRE(cpu[reg::r10] == gpr_t::r10);
		REQUIRE(cpu[reg::r11] == gpr_t::r11);
		REQUIRE(cpu[reg::r12] == gpr_t::r12);
		REQUIRE(cpu[reg::sp]  == gpr_t::r13);
		REQUIRE(cpu[reg::lr]  == gpr_t::r14);
		REQUIRE(cpu[reg::pc]  == gpr_t::r15);
	}

	SECTION("undefined mode") {
		cpu.current_mode = mode_t::und;

		REQUIRE(cpu[reg::r0] == gpr_t::r0);
		REQUIRE(cpu[reg::r1] == gpr_t::r1);
		REQUIRE(cpu[reg::r2] == gpr_t::r2);
		REQUIRE(cpu[reg::r3] == gpr_t::r3);
		REQUIRE(cpu[reg::r4] == gpr_t::r4);
		REQUIRE(cpu[reg::r5] == gpr_t::r5);
		REQUIRE(cpu[reg::r6] == gpr_t::r6);
		REQUIRE(cpu[reg::r7] == gpr_t::r7);
		REQUIRE(cpu[reg::r8] == gpr_t::r8);
		REQUIRE(cpu[reg::r9] == gpr_t::r9);
		REQUIRE(cpu[reg::r10] == gpr_t::r10);
		REQUIRE(cpu[reg::r11] == gpr_t::r11);
		REQUIRE(cpu[reg::r12] == gpr_t::r12);

		REQUIRE(cpu[reg::sp]  == gpr_t::r13_und);
		REQUIRE(cpu[reg::lr]  == gpr_t::r14_und);
		REQUIRE(cpu[reg::pc]  == gpr_t::r15);
	}

}