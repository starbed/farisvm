all: farisvm

farisvm: example.cpp farisvm.cpp farisvm.hpp spin_rwlock.hpp
	c++ example.cpp farisvm.cpp -lpthread -std=c++11 -O3 -Wall -o farisvm

clean:
	rm -f farisvm
