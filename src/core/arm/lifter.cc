#include "arm.h"

#include <algorithm>
#include <utility>

#include "common/logger.h"

#include "core/mem.h"

//TODO: write unit tests

namespace arm {

	/*void decodeArm(arm_ins_t& ins, std::string_view mnemonic, std::string_view op_str) {
		//TODO: remove reference captures once fully implemented
		//this 1st parser would be alot easier if std::s_v::ends_with existed yet	
		auto conditionalStripper =
			[&](std::string_view mne) -> std::pair<std::string_view, arm::cond> {
				using namespace std::literals;

				size_t len = mne.length();
				if(len < 3)
					return {mne, arm::cond::al};
				std::string_view m    = mne.substr(0,len-2); //mne except for the last 2 char
				std::string_view condition = mne.substr(len-2, 2); //last 2 chars
				
				if (condition == "eq"sv || condition == "EQ"sv) {
					return {m, arm::cond::eq};
				} else if (condition == "ne"sv || condition == "NE"sv) {
					return {m, arm::cond::ne};
				} else if (condition == "cs"sv || condition == "CS"sv) {
					return {m, arm::cond::cs};
				} else if (condition == "cc"sv || condition == "CC"sv) {
					return {m, arm::cond::cc};
				} else if (condition == "mi"sv || condition == "MI"sv) {
					return {m, arm::cond::mi};
				} else if (condition == "pl"sv || condition == "PL"sv) {
					return {m, arm::cond::pl};
				} else if (condition == "vs"sv || condition == "VS"sv) {
					return {m, arm::cond::vs};
				} else if (condition == "vc"sv || condition == "VC"sv) {
					return {m, arm::cond::vc};
				} else if (condition == "hi"sv || condition == "HI"sv) {
					return {m, arm::cond::hi};
				} else if (condition == "ls"sv || condition == "LS"sv) {
					return {m, arm::cond::ls};
				} else if (condition == "ge"sv || condition == "GE"sv) {
					return {m, arm::cond::ge};
				} else if (condition == "lt"sv || condition == "LT"sv) {
					return {m, arm::cond::lt};
				} else if (condition == "gt"sv || condition == "GT"sv) {
					return {m, arm::cond::gt};
				} else if (condition == "le"sv || condition == "LE"sv) {
					return {m, arm::cond::le};
				} else if (condition == "hs"sv || condition == "HS"sv) {
					return {m, arm::cond::hs};
				} else if (condition == "lo"sv || condition == "LO"sv) {
					return {m, arm::cond::lo};
				} else {
					return {mne, arm::cond::al};
				}
		};

		auto mnemonicParser = [&](std::string_view mne) -> arm::operation {
			//TODO: implement
			FATAL("unknown mnemonic in instruction\n"
				"\tins: {}\t{}\n"
				"\tmne: {}", mnemonic, op_str, mne);
			std::exit(-1);

			//return {};
		};

		auto operandParser = [&](std::string_view opstr) -> std::vector<operand_t> {
			//TODO: implement
			FATAL("operandParser not implemented yet so cannot parse \n"
				"\t{}",
				opstr);
			std::exit(-1);
			//return {};
		};

		auto [mne, condition] = conditionalStripper(mnemonic);
		ins.cond = condition;
		ins.op = mnemonicParser(mne);
		ins.operands = operandParser(op_str);
	}
	void decodeThumb(arm_ins_t& ins, std::string_view mnemonic, std::string_view op_str) {
		ins.cond = arm::cond::al; //Not until ARMv6 thumb got the IT instruction (and therefore got conditional inst)

		FATAL("Lifter::decodeThumb is unimplemented so cannout parse \n"
			"\t{}\t{}",
			mnemonic, op_str);
		std::exit(-1);
	}*/

} //namespace arm