#ifndef GBA_ROM_H
#define GBA_ROM_H

#include "common/logger.h"
#include "common/types.h"

#include <array>
#include <string>
#include <vector>

namespace gba::rom {
	//http://problemkaputt.de/gbatek.htm#gbacartridges
	struct header {
		u32 					b_rom_start 		=  0;		//0x00
		std::array<u8, 156>		logo				= {};		//0x04
		std::array<char, 12>	tite				= {};		//0xA0
		std::array<char, 4>		game_code			= {};		//0xAC
		std::array<char, 2>		maker_code			= {};		//0xB0
		u8						magic_0x96 			= 0x96; 	//0xB2
		u8						main_unit_code		= 0;		//0xB3
		u8						device_type			= 0;		//0xB4
		u8						pad_1[7]			= {};		//0xB5
		u8						ver					= 0;		//0xBC
		u8						comp_check			= 0;		//0xBD
		u8						pad_2[2]			= {};		//0xBE
		//------------------Multiboot below---------------------
		u32						multi_ram_entry		= 0;		//0xC0
		u8						multi_boot_mode		= 0;		//0xC4
		u8						multi_slave_num		= 0;		//0xC5
		u8						multi_pad_3[26]		= {};		//0xC6
		u32						multi_joybus_entry	= 0;		//0xE0
	};
	class rom {
		std::vector<u8> raw;
		header 			head;

		void populateHeader();
	public:

		static void test(std::string s);

		rom(const std::string&);
		rom(const std::vector<u8>&);
		
		rom(const rom&) = default;
		rom(rom&&) = default;
		~rom() = default;
		
		u8&	operator[](size_t off) {
			return raw[off];
		}
		size_t size() {
			return raw.size();
		}
	};
} //namespace gba::rom

#endif //GBA_ROM_H