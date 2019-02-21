#ifndef MOC_H
#define MOC_H

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

#endif //MOC_H