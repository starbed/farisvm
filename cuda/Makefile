all: abpvm

abpvm: main.cu abpvm.cu abpvm.hpp
	nvcc main.cu abpvm.cu -std=c++11 -O3 -o abpvm

clean:
	rm -f abpvm
