#ifndef LIFTER_H
#define LIFTER_H

namespace ast {
	template<class T, typename isa_t, class CRTP>
	class Lifter {
		#define crpt (static_cast<CRTP*>(this))
		
	};
};

#endif //LIFTER_H