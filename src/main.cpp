#include "abpvm.hpp"

#include <iostream>
#include <fstream>
#include <chrono>

int
main(int argc, char *argv[])
{
    abpvm vm;

    // vm.add_rule("|https:");
    // vm.add_rule("||example.com^index.html");
    // vm.add_rule(".swf|");
    // vm.add_rule("||2-only.page.ne.jp");
    // vm.add_rule("/eas?*^easformat=");
    // vm.add_rule("||csdn.net^*/counter.js");
    // vm.add_rule("@@||cdn.api.twitter.com*http%$script,third-party");

    for (int i = 1; i < argc; i++) {
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

    vm.print_asm();

    std::cout << "loaded filters\n" << std::endl;

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

    return 0;
}
