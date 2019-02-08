#ifndef LOG_LEVEL_H
#define LOG_LEVEL_H

namespace Log {
	enum class Level {
		Debug,
		Status,
		Warning,
		Error,
		Critical,
		Fatal,


		Count

	};
	bool operator<(Level lhs, Level rhs) {
		return static_cast<unsigned>(lhs) <  static_cast<unsigned>(rhs);
	}
	bool operator<=(Level lhs, Level rhs) {
		return static_cast<unsigned>(lhs) <= static_cast<unsigned>(rhs);
	}
} //namespace Log

#endif //LOG_LEVEL_H