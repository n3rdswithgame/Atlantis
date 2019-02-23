#ifndef MOC_H
#define MOC_H

#include "core/targets.h"

#include "core/arm/arm.h"

enum moc_arm : size_t { //not enum class to avoid static_casts
	data_processing,
	mul,
	mul_long,
	bx,
	hword_reg_off,
	hword_imm_off,
	single_data_transfer,
	und,
	block_data,
	b,
	copros_data_trans,
	copros_op,
	copros_reg_trans,
	svc,
	status_mode,

	random_ins,

	count,
};

namespace ast {
	template<>
	struct emu_traits<emu_targets::arm_moc> : arm::emu_traits{

		using region_t	= moc_arm;
		using mmu_t		= mmu::mmu<region_t>;

		//using BB_t	= ast::bb::bb_t<ins_t, isa>;
		//using BBT_t	= ast::bb::tracker_t<ins_t, isa>;

	};
} //namespace ast

using emu_traits = ast::emu_traits<emu_targets::arm_moc>;

#endif //MOC_H