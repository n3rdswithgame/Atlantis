#include "arm.h"

#include <algorithm>
#include <utility>

#include "common/logger.h"

//TODO: write unit tests

namespace arm {

	Lifter::Lifter(mmu::mmu & m) {
		mmu = &m;
		if(cs_err ret = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &cap_arm);
			ret != CS_ERR_OK) {
			FATAL("Error creating ARM capstone engine with error code: {}", ret);
		}

		if(cs_err ret = cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &cap_thumb);
			ret != CS_ERR_OK) {
			FATAL("Error creating THUMB capstone engine with error code: {}", ret);
		}
	}
	Lifter::Lifter(Lifter&& l) {
		mmu = std::exchange(l.mmu, nullptr);
		cap_arm = l.cap_arm;
		cap_thumb = l.cap_thumb;
	}
	Lifter::~Lifter() {
		if(mmu != nullptr) {
			cs_close(&cap_arm);
			cs_close(&cap_thumb);
		}
	}

	arm_ins_t Lifter::fetch_impl(addr_t pc) {
		if((pc & 1) == 0)
			return fetchArm_impl(pc);
		else
			return fetchThumb_impl(pc & (~1U)); // translate pc into address
	}

	arm_ins_t Lifter::fetchArm_impl(addr_t addr) {
		return fetchArch_impl<isa::arm>(addr);
	}

	arm_ins_t Lifter::fetchThumb_impl(addr_t addr) {
		return fetchArch_impl<isa::thumb>(addr); //pc is already translated into an address in fetch_impl
	}


	template<isa i>
	arm_ins_t Lifter::fetchArch_impl(addr_t addr) {
		constexpr size_t num_inst = 1;
		constexpr bool is_arm = (i == isa::arm);

		cs_insn *insn;
		size_t count;

		u32 raw_machine_code; //for the log message
		if constexpr(is_arm) {
			u32 machine_code = mmu->read<u32>(addr).read_val;//no static_cast as read_val is already a reg_t aka u32
			raw_machine_code = machine_code;
			count = cs_disasm(cap_arm, reinterpret_cast<u8*>(&machine_code),
				sizeof(machine_code), addr, num_inst, &insn);
		} else {
			u16 machine_code = static_cast<u16>(mmu->read<u16>(addr).read_val);
			raw_machine_code = machine_code;
			count = cs_disasm(cap_thumb, reinterpret_cast<u8*>(&machine_code),
				sizeof(machine_code), addr, num_inst, &insn);
		}

		if (count == 0) {
			FATAL("Failure to disassemble {0} machine code into instructions\n"
				  "\taddr: 0x{1:08x}\n"
				  "\t raw: 0x{2:08x}",
				  i,
				  addr,
				  raw_machine_code);
			return {};
		}

		arm_ins_t ins{};
		ins.addr = addr;

		if constexpr(is_arm) {
			decodeArm(ins, insn[0].mnemonic, insn[0].op_str);
		} else {
			decodeThumb(ins, insn[0].mnemonic, insn[0].op_str);
		}

		cs_free(insn, num_inst);

		return ins;
	}

	void Lifter::decodeArm(arm_ins_t& ins, std::string_view mnemonic, std::string_view op_str) {
		//TODO: remove reference captures once fully implemented
		//this 1st parser would be alot easier if std::s_v::ends_with existed yet	
		auto conditionalStripper =
			[&](std::string_view mne) -> std::pair<std::string_view, arm::cond> {
				using namespace std::literals;

				size_t len = mne.length();
				if(len < 3)
					return {mne, arm::cond::AL};
				std::string_view m    = mne.substr(0,len-2); //mne except for the last 2 char
				std::string_view cond = mne.substr(len-2, 2); //last 2 chars
				
				if (cond == "eq"sv || cond == "EQ"sv) {
					return {m, arm::cond::EQ};
				} else if (cond == "ne"sv || cond == "NE"sv) {
					return {m, arm::cond::NE};
				} else if (cond == "cs"sv || cond == "CS"sv) {
					return {m, arm::cond::CS};
				} else if (cond == "cc"sv || cond == "CC"sv) {
					return {m, arm::cond::CC};
				} else if (cond == "mi"sv || cond == "MI"sv) {
					return {m, arm::cond::MI};
				} else if (cond == "pl"sv || cond == "PL"sv) {
					return {m, arm::cond::PL};
				} else if (cond == "vs"sv || cond == "VS"sv) {
					return {m, arm::cond::VS};
				} else if (cond == "vc"sv || cond == "VC"sv) {
					return {m, arm::cond::VC};
				} else if (cond == "hi"sv || cond == "HI"sv) {
					return {m, arm::cond::HI};
				} else if (cond == "ls"sv || cond == "LS"sv) {
					return {m, arm::cond::LS};
				} else if (cond == "ge"sv || cond == "GE"sv) {
					return {m, arm::cond::GE};
				} else if (cond == "lt"sv || cond == "LT"sv) {
					return {m, arm::cond::LT};
				} else if (cond == "gt"sv || cond == "GT"sv) {
					return {m, arm::cond::GT};
				} else if (cond == "le"sv || cond == "LE"sv) {
					return {m, arm::cond::LE};
				} else if (cond == "hs"sv || cond == "HS"sv) {
					return {m, arm::cond::HS};
				} else if (cond == "lo"sv || cond == "LO"sv) {
					return {m, arm::cond::LO};
				} else {
					return {mne, arm::cond::AL};
				}
		};

		auto mnemonicParser = [&](std::string_view mne) -> arm::mnemonics {
			//TODO: implement
			FATAL("unknown mnemonic in instruction\n"
				"\tins: {}\t{}\n"
				"\tmne: {}", mnemonic, op_str, mne);
			std::exit(-1);

			return {};
		};

		auto operandParser = [&](std::string_view opstr) -> std::vector<operand_t> {
			//TODO: implement
			FATAL("operandParser not implemented yet");
			std::exit(-1);
			return {};
		};

		auto [mne, cond] = conditionalStripper(mnemonic);
		ins.cond = cond;
		ins.op = mnemonicParser(mne);
		ins.operands = operandParser(op_str);
	}
	void Lifter::decodeThumb(arm_ins_t&, std::string_view mnemonic, std::string_view op) {

	}

} //namespace arm