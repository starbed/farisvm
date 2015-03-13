all: abp_regex abp_regex_re2

abp_regex: main.cpp abpvm.cpp abpvm.hpp
	c++ main.cpp abpvm.cpp -std=c++11 -O3 -o abp_regex

abp_regex_re2: main.cpp abpvm.cpp abpvm.hpp
	c++ main.cpp abpvm.cpp -std=c++11 -O3 -DUSE_RE2 -lre2 -o abp_regex_re2

clean:
	rm -f abp_regex abp_regex_re2
