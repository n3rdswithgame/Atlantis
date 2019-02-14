#ifndef DEC_STATUS_H
#define DEC_STATUS_H

namespace arm::dec {
	enum class status {
		success = 0,
		nomatch,
		notchecked,
		discard_current_dispatch,
		illformed,
		future, //valid instruction in a later isa version that the active one
	};
} //namespace arm::dec

#endif //DEC_STATUS_H