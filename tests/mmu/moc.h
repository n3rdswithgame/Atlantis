#ifndef MOC_H
#define MOC_H

enum moc_region : size_t { //not enum class to avoid static_casts
	reg_1,
	reg_2,
	reg_3,
	reg_4,

	count,
};

#endif //MOC_H