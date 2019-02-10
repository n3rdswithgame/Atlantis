#ifndef SINGLETON_H
#define SINGLETON_H

template<class T>
class Singleton {
public:
	static T& get() {
		static T singleton;
		return singleton;
	}
};


#endif //SINGLETON_H