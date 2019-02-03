#include <catch2/catch.hpp>

#include "moc.h"

#include <array>

#include "core/arm/arm.h"
#include "core/mem.h"
#include "core/mmu.h"

constexpr size_t const_4kb = 0x1000;

constexpr mem::memmap<moc_arm> genMemMap() {

	mem::memmap<moc_arm> memmap{};

	for(size_t i = 0; i < memmap.size(); i++) {
		memmap[i].start = static_cast<addr_t>(i * const_4kb);
		memmap[i].end = static_cast<addr_t>((i + 1) * const_4kb - 1);

		memmap[i].timings[0] = static_cast<s64>(i * 4 + 0);
		memmap[i].timings[0] = static_cast<s64>(i * 4 + 1);
		memmap[i].timings[0] = static_cast<s64>(i * 4 + 2);
	}
	return memmap;
}

TEST_CASE("Testing ARM Data Processing instructions", "[arm.DataProcessing]") {
	mem::memmap<moc_arm> memmap = genMemMap();

	mmu::mmu<moc_arm> mmu(memmap);

	std::array<u8, const_4kb> backing {};
	mem::region_t& r = mmu[moc_arm::data_processing];
	r.mem = backing.data();
	addr_t base = r.start;

	SECTION("adc r1, r2") {
		mmu.write<u32>()
	}

}