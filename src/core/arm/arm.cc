#include "arm.h"

#include <algorithm>
#include <utility>

#include "common/logger.h"

#include "core/mem.h"

//TODO: write unit tests

namespace arm {

	void decodeArm(arm_ins_t& ins, std::string_view mnemonic, std::string_view op_str) {
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
			FATAL("operandParser not implemented yet so cannot parse \n"
				"\t{}",
				opstr);
			std::exit(-1);
			return {};
		};

		auto [mne, cond] = conditionalStripper(mnemonic);
		ins.cond = cond;
		ins.op = mnemonicParser(mne);
		ins.operands = operandParser(op_str);
	}
	void decodeThumb(arm_ins_t& ins, std::string_view mnemonic, std::string_view op_str) {
		FATAL("Lifter::decodeThumb is unimplemented so cannout parse \n"
			"\t{}\t{}",
			mnemonic, op_str);
		std::exit(-1);
		ins.cond = arm::cond::AL; //Not until ARMv6 thumb got the IT instruction (and therefore got conditional inst)
	}

} //namespace arm