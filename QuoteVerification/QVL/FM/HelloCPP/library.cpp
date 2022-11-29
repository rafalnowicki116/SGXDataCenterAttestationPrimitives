#include <iostream>
#include "library.h"
#include <vector>

extern "C" {
	void hello() {
		std::cout << "Hello, World!" << std::endl;
		std::vector<int> dupa;								
	}
}