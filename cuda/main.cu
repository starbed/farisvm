#include "abpvm.hpp"

#include <iostream>
#include <fstream>
#include <chrono>

// #define CUIMODE

int
main(int argc, char *argv[])
{
    std::vector<std::string> urls;
    abpvm vm;

    // vm.add_rule("|https:");
    // vm.add_rule("||example.com^index.html");
    // vm.add_rule(".swf|");
    // vm.add_rule("||2-only.page.ne.jp");
    // vm.add_rule("/eas?*^easformat=");
    // vm.add_rule("||csdn.net^*/counter.js");
    // vm.add_rule("@@||cdn.api.twitter.com*http%$script,third-party");
#ifdef CUIMODE
    int init_i = 1;
#else
    int init_i = 2;
#endif

#ifndef CUIMODE
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " urls.txt [filters.txt ...]"
                  << std::endl;
        return -1;
    }

    std::ifstream ifurls(argv[1]);
    std::string url;

    if (ifurls.fail()) {
        std::cerr << "cannot read " << argv[1] << std::endl;
        return -1;
    }

    while (getline(ifurls, url)) {
        urls.push_back(url);
    }

    std::cout << "loaded " << urls.size() << " urls" << std::endl;
#endif

    for (int i = init_i; i < argc; i++) {
        std::ifstream ifs(argv[i]);
        std::string line;

        if (ifs.fail()) {
            continue;
        }

        getline(ifs,line);

        while (getline(ifs, line)) {
            try {
                vm.add_rule(line);
            } catch (abpvm_exception e) {
                std::cerr << e.what() << std::endl;
            }
        }
    }

    // vm.print_asm();

    std::cout << "loaded filters\n" << std::endl;

#ifdef CUIMODE
    for (;;) {
        abpvm_query q;
        std::vector<std::string> result;
        std::string input;
        std::cin >> input;

        q.set_uri(input);

        const auto startTime = std::chrono::system_clock::now();

        vm.match(result, &q, 1);

        const auto endTime = std::chrono::system_clock::now();
        const auto timeSpan = endTime - startTime;

        for (auto &ret: result) {
            std::cout << ret << std::endl;
        }
        std::cout <<
            std::chrono::duration_cast<std::chrono::microseconds>(timeSpan).count()
            << " [us]\n" << std::endl;
    }
#else
    abpvm_query q0;
    q0.set_uri(urls[0]);
    std::vector<std::string> r0;
    vm.match(r0, &q0, 1);

    std::cout << "initialized\n" << std::endl;

    const auto startTime = std::chrono::system_clock::now();

    for (std::string &i: urls) {
        abpvm_query q;
        q.set_uri(i);
        std::vector<std::string> result;
        vm.match(result, &q, 1);
    }

    const auto endTime = std::chrono::system_clock::now();
    const auto timeSpan = endTime - startTime;

    std::cout << "#urls: " << urls.size()
              << "\ntime: " <<
        std::chrono::duration_cast<std::chrono::microseconds>(timeSpan).count() / (double)1000000.0
        << " [s]\n" << std::endl;
#endif // CUIMODE


    return 0;
}
