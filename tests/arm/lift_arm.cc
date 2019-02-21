#include <catch2/catch.hpp>

#include "moc.h"

#include <array>

#include "common/logger.h"

#include "core/arm/arm.h"
#include "core/arm/lifter.h"
#include "core/mem.h"
#include "core/mmu.h"

constexpr size_t const_4kb = 0x1000;

constexpr mem::map<moc_arm> genMemMap() {

	mem::map<moc_arm> memmap{};

	for(size_t i = 0; i < memmap.size(); i++) {
		memmap[i].start = static_cast<addr_t>(i * const_4kb);
		memmap[i].end = static_cast<addr_t>((i + 1) * const_4kb - 1);

		memmap[i].timings[0] = static_cast<s64>(i * 4 + 0);
		memmap[i].timings[1] = static_cast<s64>(i * 4 + 1);
		memmap[i].timings[2] = static_cast<s64>(i * 4 + 2);
	}
	return memmap;
}

template<typename... RawIns>
std::array<arm::ins_t, sizeof...(RawIns)> Setup(moc_arm region, RawIns... rawIns) {
	//auto nop = [](auto arg) {return arg};
	std::array<u32, sizeof...(RawIns)> backing{};
	std::array<u32, sizeof...(RawIns)> machine_code = {static_cast<u32>(rawIns)...};

	mem::map<moc_arm> memmap = genMemMap();
	mmu::mmu<moc_arm> mmu(memmap);
	arm::Lifter<moc_arm> lift(mmu);

	mem::region_t& r = mmu[region];
	//this is fine as the values will first be written to below in the mmu.write<u32> method call
	//on little endian machines this could techincally be machine_code.data() instead of
	//backing.data(), but idk if that would work on bigendian machines and this is guarenteed
	//to be portable
	r.mem = reinterpret_cast<u8*>(backing.data());
	
	std::array<arm::ins_t, sizeof...(RawIns)> inss = {};

	addr_t base = r.start;
	for(addr_t i = 0; i < backing.size(); i++) {
		addr_t addr = static_cast<addr_t>(base + i*sizeof(backing[0]));
		mmu.write<u32>(addr, machine_code[i]);
		inss[i] = lift.fetch(addr);
	}

	return inss;
}

TEST_CASE("Testing ARM Data Processing instructions", "[arm.DataProcessing]") {
	
	using arm::cpu::reg;
	using arm::cond;
	using arm::operation;
	using arm::operand::op_type;
	using arm::operand::modifier_type;
	auto setup = [](auto... inss) {
		return Setup(moc_arm::data_processing, inss...);
	};

	SECTION("adc") {
		auto inss = setup(
			0x10a15003, //  0: adcne	r5,r1,r3
			0x80b77002, //  1: adcShi   r7, r2
			0xe2a2570e, //  2: adc		r5, r2, #0x380000
			0xe0b42206, //  3: adcs		r2, r4, r6, lsl #4
			0xe0a31712, //  4: adc		r1, r3, r2, asl r7
			0x00a31932, //  5: adceq	r1, r3, r2, lsr r9
			0x30b31322  //  6: adcScc	r1, r3, r2, lsr #6
		);
		for(size_t i = 0; i < inss.size(); i++){
			INFO("Checking operand for inss[" << i << ']');
			REQUIRE(inss[i].op == operation::Adc);
		}
		{
			INFO("Checking everything else for inss[1]");
			REQUIRE(inss[0].cond == cond::ne);
			REQUIRE(inss[0].operands[0].negate == false);
			REQUIRE(inss[0].operands[0].type == op_type::gpr);
			REQUIRE(inss[0].operands[0].mod == modifier_type::empty);
			REQUIRE(inss[0].operands[0].val == static_cast<s32>(reg::r5));
		}
	}
}

TEST_CASE("Status and Mode instructions", "[arm.StatusMode]") {

	using arm::cpu::reg;
	using arm::cond;
	using arm::operation;
	using arm::operand::op_type;
	using arm::operand::modifier_type;
	auto setup = [](auto... inss) {
		return Setup(moc_arm::status_mode, inss...);
	};

	SECTION("mrs") {
		auto inss = setup(
			0xe10f0000, // 0: mrs r0, cpsr
			0xe14f1000  // 1: mrs r1, spsr
		);

		for(size_t i = 0; i < inss.size(); i++){
			INFO("Checking condition for inss[" << i << ']');
			REQUIRE(inss[i].op == operation::Mrs);
		}
	}

	SECTION("msr") {
		//TODO: do
	}

}

TEST_CASE("Testing ARM Branching instructions", "[arm.Branching]") {

	using arm::cpu::reg;
	using arm::cond;
	using arm::operation;
	using arm::operand::op_type;
	using arm::operand::modifier_type;
	auto setup = [](auto... inss) {
		return Setup(moc_arm::b, inss...);
	};

	SECTION("b") {
		auto inss = setup(
			0xea00048b //  0: b 0x1234
		);
		for(size_t i = 0; i < inss.size(); i++){
			INFO("Checking condition for inss[" << i << ']');
			REQUIRE(inss[i].op == operation::B);
		}
	}
}

TEST_CASE("Loads and Stores, words and bytes", "[arm.WordByte]") {
	using arm::cpu::reg;
	using arm::cond;
	using arm::operation;
	using arm::operand::op_type;
	using arm::operand::modifier_type;
	auto setup = [](auto... inss) {
		return Setup(moc_arm::single_data_transfer, inss...);
	};

	SECTION("ldr") {
		auto inss = setup(
			0xe5910000, 	//  0: ldr  r0,  [r1]
			0xe5910000, 	//  1: ldr  r0,  [r1]
			0xe5932004, 	//  2: ldr  r2,  [r3, #4]
			0xe7154002, 	//  3: ldr  r4,  [r5, -r2]
			0xe7176108, 	//  4: ldr  r6,  [r7, -r8, LSL #2]
			0xe53a9004, 	//  5: ldr  r9,  [r10, #-4]!
			0xe7bcb000, 	//  6: ldr  r11, [r12, r0]!
			0xe7321083, 	//  7: ldr  r1,  [r2, -r3, LSL #1]!
			0xe5954000, 	//  8: ldr  r4,  [r5]
			0xe4154009, 	//  9: ldr  r4,  [r5], #-9
			0xe6176008, 	// 10: ldr  r6,  [r7], -r8
			0xe6909401	 	// 11: ldr  r9,  [r0], r1, LSL #8
		);

		for(size_t i = 0; i < inss.size(); i++){
			INFO("Checking condition for inss[" << i << ']');
			REQUIRE(inss[i].op == operation::Ldr);
		}

	}

	SECTION("ldrt") {
		auto inss = setup(
			0xe4b10000  	//  0: ldrt r0,  [r1]
		);
		
		for(size_t i = 0; i < inss.size(); i++){
			INFO("Checking condition for inss[" << i << ']');
			REQUIRE(inss[i].op == operation::Ldrt);
		}
	}
}

TEST_CASE("Block data transfer", "[arm.BlockData]") {

	using arm::cpu::reg;
	using arm::cond;
	using arm::operation;
	using arm::operand::op_type;
	using arm::operand::modifier_type;
	auto setup = [](auto... inss) {
		return Setup(moc_arm::block_data, inss...);
	};


	SECTION("ldm") {
		auto inss = setup(
			0xe890001c, //  0: ldm r0, {r2 - r4}
			0xe8d11f00  //  1: ldm r1, {r8 - r12}^
		);

		(void)inss;

	}

	SECTION("push") {
		auto inss = setup(
			0xe92d427d 	//  0: push {r0, r2, r3, r4, r5, r6, r9, lr}
		);

		(void)inss;
	}
}

TEST_CASE("Random instructions ", "[random]") {
	using arm::cpu::reg;
	using arm::cond;
	using arm::operation;
	using arm::operand::op_type;
	using arm::operand::modifier_type;
	auto setup = [](auto... inss) {
		return Setup(moc_arm::random_ins, inss...);
	};

	SECTION("cap") {
		//This section is a list of instructions taken from a capstone unit tests
		auto inss = setup(
			0xe52de004,	//  0: str	lr, [sp, #-0x4]!
			0xe52283e0,	//  1: str	r8, [r2, #-0x3e0]!
			0x0e0302f1,	//  2: mcreq	p0x2, #0x0, r0, c0x3, c0x1, #0x7
			0xe3a00000,	//  3: mov	r0, #0x0 
			0xe7c13002,	//  4: strb	r3, [r1, r2]
			0xe3530000,	//  5: cmp	r3, #0x0
			0xe2a10002,	//  6: adc r0, r1, r2
			0xe0a00121,	//  7: adc	r0, r0, r1, lsr #2
			0xe0b00121,	//  8: adcs	r0, r0, r1, lsr #2
			0xe0a10332,	//  9: adc	r0, r1, r2, lsr r3
			0xe0a10122,	// 10: adc	r0, r1, r2, lsr #2
			0x504f6165,	// 11: subpl	r6, pc, r5, ror #2
			0xe5533030,	// 12: ldrb	r3, [r3, #-0x30]
			0xe1df10b6,	// 13: ldrh	r1, [pc, #0x6]
			0xef9f0002,	// 14: svc #0x9f0002
			0xea27c000,	// 15: b 0x9F0002: FIXME: disasm as "b	#0x9f0000"
			0xe1a01312,	// 16: lsl r1, r2, r3
			0xe1a01182,	// 17: lsl	r1, r2, #0x3
			0xe1a0c000,	// 18: mov ip, r0
			0xe3120002,	// 19: tst r2, #2
			0xe1a01251,	// 20: asr r1, r2
			0xe6ef1072,	// 21: uxtb r1, r2
			0xeeb70ae0,	// 22: vcvt.f64.f32	d0, s1
			0xe1910f9f,	// 23: ldrex	r0, [r1]
			0xf420060f,	// 24: vld1.8	{d0, d1, d2}, [r0]
			0xe6a10072,	// 25: sxtab r0, r1, r2
			0xf2840650,	// 26: vmov.i32	q0, #0x40000000
			0xeeb8e073,	// 27: mrc	p0, #5, lr, c8, c3, #3
			0xe6810212,	// 28: pkhbt	r0, r1, r2, lsl #0x4
			0xe6a00012,	// 29: ssat	r0, #0x1, r2
			0xe92d6003,	// 30: push	{r0, r1, sp, lr}
			0xf460408f,	// 31: vld4.32	{d20, d21, d22, d23}, [r0]
			0xe1c200d0,	// 32: ldrd	r0, r1, [r2]
			0xf5d0f008,	// 33: pld	[r0, #0x8]
			//0xecbc8b10,	// 34: ldc	p11, c8, [r12], #64
			0xe1d230d4,	// 35: ldrsb	r3, [r2, #0x4] 
			0xf2be0f11,	// 36: vcvt.s32.f32	d0, d1, #2
			0xe1700101,	// 37: cmn	r0, r1, lsl #2
			0xe2910006,	// 38: adds	r0, r1, #6
			0xf57ff05b,	// 39: dmb	ish
			0xe8bd2000,	// 40: ldm	sp!, {sp}
			0xe8bda000,	// 41: pop {sp, pc}
			0x000E0490,	// 42: muleq	lr, r0, r4
			0x000E2490,	// 44: muleq	lr, r0, r4
			0xe15f10b6	// 44: ldrh	r1, [pc, #-6]
		);
		std::array ops = {
			operation::Str,
			operation::Str,
			operation::Mcr,
			operation::Mov,
			operation::Strb,
			operation::Cmp,
			operation::Adc,
			operation::Adc,
			operation::Adc,
			operation::Adc,
			operation::Adc,
			operation::Sub,
			operation::Ldrb,
			operation::Ldrh,
			operation::Svc,
			operation::B,
			operation::Lsl,
			operation::Lsl,
			operation::Mov,
			operation::Tst,
			operation::Asr,
			operation::Uxtb,
			operation::Vcvt,
			operation::Ldrex,
			operation::Vld1,
			operation::Sxtab,
			operation::Vmov,
			operation::Mrc,
			operation::Pkhbt,
			operation::Ssat,
			operation::Push,
			operation::Vld4,
			operation::Ldrd,
			operation::Pld,
			//operation::Ldc, //Appears to be wrong in the captsone unit test 
			operation::Ldrsb,
			operation::Vcvt,
			operation::Cmn,
			operation::Add,
			operation::Dmb,
			operation::Ldm,
			operation::Pop,
			operation::Mul,
			operation::Mul,
			operation::Ldrh
		};
		for(size_t i = 0; i < inss.size(); i++){
			INFO("Checking condition for inss[" << i << ']');
			REQUIRE(inss[i].op == ops[i]);
		}
	}
}