	#include <catch2/catch.hpp>

#include "moc.h"

#include "core/mem.h"
#include "core/mmu.h"
#include "common/types.h"

#include "common/logger.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <vector>

constexpr size_t moc_reg_size = 0x1000;

std::array<std::array<u8, moc_reg_size>, moc_region::count> regs = {};
constexpr std::array<addr_t, moc_region::count> start_addr = {
	0x0000'0000,
	0x2000'0000,
	0x4000'0000,
	0x5000'0000,
};

#define make_moc_region(r)																				\
	make_region(r,															/*name*/					\
		start_addr[moc_region::r],											/*start*/					\
		start_addr[moc_region::r] + moc_reg_size,							/*end*/						\
		1 + 4*static_cast<s64>(moc_region::r),								/*byte  timeing*/			\
		2 + 4*static_cast<s64>(moc_region::r),								/*hword timeing*/			\
		3 + 4*static_cast<s64>(moc_region::r)								/*word  timeing*/			\
	)

mem::map<moc_region> make_moc_memmap() {
	mem::map<moc_region> memmap = {
		make_moc_region(reg_1),
		make_moc_region(reg_2),
		make_moc_region(reg_3),
		make_moc_region(reg_4),
	};

	for(size_t i = moc_region::reg_1; i < moc_region::count; i++) {
		memmap[i].mem = regs[i].data();
	}

	return memmap;
}

TEST_CASE("Testing valid mmu operations", "[valid_mmu]") {

	mem::map<moc_region> memmap = make_moc_memmap();
	mmu::mmu<moc_region> mmu(memmap);


	SECTION("check mmu read and endian") {
		//first word is 0x41424344
		regs[moc_region::reg_1][0] = 0x41;
		regs[moc_region::reg_1][1] = 0x42;
		regs[moc_region::reg_1][2] = 0x43;
		regs[moc_region::reg_1][3] = 0x44;

		auto read_word  = mmu.read<u32>(0);
		auto read_hword = mmu.read<u16>(0);
		auto read_byte  = mmu.read<u8 >(0);

		REQUIRE(read_byte. status == mem::error::success);
		REQUIRE(read_hword.status == mem::error::success);
		REQUIRE(read_word. status == mem::error::success);

		REQUIRE(read_byte.read_val  == 0x41);
		REQUIRE(read_hword.read_val == 0x4241);
		REQUIRE(read_word.read_val  == 0x44434241);
	}

	SECTION("check mmu write and endian") {
		

		mmu.write<u32>(4, 0x32323232);
		auto read_after_word  = mmu.read<u32>(4);
		
		mmu.write<u16>(4, 0x1616);
		auto read_after_hword = mmu.read<u32>(4);
		
		mmu.write<u8 >(4, 0x08);
		auto read_after_byte  = mmu.read<u32>(4);

		REQUIRE(read_after_word. read_val == 0x32323232);
		REQUIRE(read_after_hword.read_val == 0x32321616);
		REQUIRE(read_after_byte. read_val == 0x32321608);

		REQUIRE(mmu.read<u8>(6).read_val == regs[moc_region::reg_1][6]);
		
		REQUIRE(read_after_byte. status == mem::error::success);
		REQUIRE(read_after_hword.status == mem::error::success);
		REQUIRE(read_after_word. status == mem::error::success);
	}

	SECTION("check mmu read timings") {
		for(size_t i = 0; i < moc_region::count; i++) {
			addr_t access_addr = start_addr[i] + 0x8;

			//set the value for reading just to ensure its initiliazed
			mmu.write<u32>(access_addr, 0x31415926);
			auto read_byte  = mmu.read<u8 >(access_addr);
			auto read_hword = mmu.read<u16>(access_addr);
			auto read_word  = mmu.read<u32>(access_addr);

			REQUIRE(read_byte. status == mem::error::success);
			REQUIRE(read_hword.status == mem::error::success);
			REQUIRE(read_word. status == mem::error::success);

			REQUIRE(read_byte. timing == memmap[i].timings[0]);
			REQUIRE(read_hword.timing == memmap[i].timings[1]);
			REQUIRE(read_word. timing == memmap[i].timings[2]);

		}
	}

	SECTION("check mmu write timings") {
		for(size_t i = 0; i < moc_region::count; i++) {
			addr_t access_addr = start_addr[i] + 0x8;

			auto write_byte  = mmu.write<u8 >(access_addr,0x01);
			auto write_hword = mmu.write<u16>(access_addr,0x2345);
			auto write_word  = mmu.write<u32>(access_addr,0x6789ABCD);

			REQUIRE(write_byte. status == mem::error::success);
			REQUIRE(write_hword.status == mem::error::success);
			REQUIRE(write_word. status == mem::error::success);

			REQUIRE(write_byte. timing == memmap[i].timings[0]);
			REQUIRE(write_hword.timing == memmap[i].timings[1]);
			REQUIRE(write_word. timing == memmap[i].timings[2]);

		}
	}
	
}

TEST_CASE("Testing invalid mmu operations", "[invalid_mmu]") {
	
	mem::map<moc_region> memmap = make_moc_memmap();
	mmu::mmu<moc_region> mmu(memmap);

	SECTION("unaligned reads") {
		std::array hword_reads = {
			mmu.read<u16>(0x00),
			mmu.read<u16>(0x01),
		};

		REQUIRE(hword_reads[0].status == mem::error::success);
		REQUIRE(hword_reads[1].status == mem::error::unaligned);

		std::array word_reads = {
			mmu.read<u32>(0x00),
			mmu.read<u32>(0x01),
			mmu.read<u32>(0x02),
			mmu.read<u32>(0x03),
		};

		REQUIRE(word_reads[0].status == mem::error::success);
		REQUIRE(word_reads[1].status == mem::error::unaligned);
		REQUIRE(word_reads[2].status == mem::error::unaligned);
		REQUIRE(word_reads[3].status == mem::error::unaligned);

	}

	SECTION("unaligned writes") {
		std::array hword_reads = {
			mmu.write<u16>(0x00, 0x0002),
			mmu.write<u16>(0x01, 0x0406),
		};

		REQUIRE(hword_reads[0].status == mem::error::success);
		REQUIRE(hword_reads[1].status == mem::error::unaligned);

		std::array word_reads = {
			mmu.write<u32>(0x00, 0x0004080C),
			mmu.write<u32>(0x01, 0x1014181C),
			mmu.write<u32>(0x02, 0x2024282C),
			mmu.write<u32>(0x03, 0x3034383C),
		};

		REQUIRE(word_reads[0].status == mem::error::success);
		REQUIRE(word_reads[1].status == mem::error::unaligned);
		REQUIRE(word_reads[2].status == mem::error::unaligned);
		REQUIRE(word_reads[3].status == mem::error::unaligned);
	}

	SECTION("unmapped reads") {
		auto read_byte  = mmu.read<u8 >(0xF0000000);
		auto read_hword = mmu.read<u16>(0xF0000000);
		auto read_word  = mmu.read<u32>(0xF0000000);

		REQUIRE(read_byte. status == mem::error::unmapped);
		REQUIRE(read_hword.status == mem::error::unmapped);
		REQUIRE(read_word. status == mem::error::unmapped);
	}

	SECTION("unmapped writes") {
		auto write_byte  = mmu.write<u8 >(0xF0000000, 0xFE);
		auto write_hword = mmu.write<u16>(0xF0000000, 0xDCBA);
		auto write_word	 = mmu.write<u32>(0xF0000000, 0x98765432);

		REQUIRE(write_byte. status == mem::error::unmapped);
		REQUIRE(write_hword.status == mem::error::unmapped);
		REQUIRE(write_word. status == mem::error::unmapped);
	}
}


TEST_CASE("Testing signed mmu operations", "[signed_mmu]") {
	mem::map<moc_region> memmap = make_moc_memmap();
	mmu::mmu<moc_region> mmu(memmap);

	SECTION("singed reads unsigned writes [sruw]"){
		auto sruw = [&](auto s, addr_t addr) -> reg_t {
			using S = decltype(s);
			using U = typename std::make_unsigned<S>::type;

			mmu.write<U>(addr, static_cast<U>(s));
			auto read = mmu.read<S>(addr);
			return read.read_val;
		};
		
		#define SRUW(val) REQUIRE(val == sruw(val, 0x100))


		SRUW( 8);		//unsigned byte
		SRUW(-8);		//  signed byte

		SRUW( 300);		//unsigned hword
		SRUW(-300);		//  signed hword
		
		SRUW( 66000);	//unsigned hword
		SRUW(-66000);	//  signed hword
	}

	SECTION("unsigned reads signed writes [ursw]"){
		auto ursw = [&](auto u, addr_t addr) -> reg_t {
			using U = decltype(u);
			using S = typename std::make_signed<U>::type;

			mmu.write<S>(addr, static_cast<S>(u));
			auto read = mmu.read<U>(addr);
			return read.read_val;
		};
		
		#define URSW(val) REQUIRE(val == ursw(val, 0x100))


		URSW( 8);		//unsigned byte
		URSW(-8);		//  signed byte

		URSW( 300);		//unsigned hword
		URSW(-300);		//  signed hword
		
		URSW( 66000);	//unsigned hword
		URSW(-66000);	//  signed hword
	}
}