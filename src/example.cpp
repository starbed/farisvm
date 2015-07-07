#include "farisvm.hpp"

#include <iostream>

int
main(int argc, char *argv[])
{
    farisvm vm;

    // add filtering rules
    vm.add_rule("||example.com^index", "filter1.txt");
    vm.add_rule(".swf|", "filter2.txt");

    // do matching
    std::vector<farisvm::match_result> result[3];
    farisvm_query query[3];

    query[0].set_uri("https://www.google.com/", "http://referer.com/");
    query[1].set_uri("http://example.com/index.html", "http://referer.com/");
    query[2].set_uri("http://example.com/index.swf", "http://referer.com/");

    vm.match(result, query, 3);

    for (int i = 0; i < 3; i++) {
        std::cout << query[i].get_uri() << std::endl;
        for (auto ret: result[i]) {
            std::cout << "  rule: " << ret.rule
                      << "\n  file: " << ret.file << std::endl;
        }
        std::cout << std::endl;
    }

    return 0;
}
