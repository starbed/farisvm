#include "abpvm.hpp"

#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>

// #define CUIMODE

#define NUM_THREAD 1

std::mutex mtx;

std::string
replace(const std::string &str, const std::string &from, const std::string &to)
{
    std::string ret = str;
    std::string::size_type pos = ret.find(from);
    while(pos != std::string::npos){
        ret.replace(pos, from.size(), to);
        pos = ret.find(from, pos + to.size());
    }

    return ret;
}

void
match(int id, int th_num,
      std::vector<std::string> &urls, std::vector<std::string> &refs, abpvm &vm)
{
    for (int i = id; i < urls.size(); i += th_num) {
        abpvm_query q;
        q.set_uri(urls[i], refs[i]);
        std::vector<abpvm::match_result> result;
        vm.match(&result, &q, 1);
        if (result.size() > 0) {
            std::lock_guard<std::mutex> lock(mtx);
            std::string url = replace(urls[i], "\\", "\\\\");
            url = replace(url, "\\\\\"", "\\\"");
            std::cout << "{\"url\":\"" << replace(urls[i], "\"", "\\\"")
                      << "\",\"result\":[{\"file\":\"" << result[0].file
                      << "\",\"rule\":\"" << result[0].rule << "\"}";
            int j = 0;
            for (auto &ret: result) {
                if (j++ > 0) {
                    std::cout << ",{\"file\":\"" << ret.file
                              << "\",\"rule\":\"" << ret.rule << "\"}";
                }
            }
            std::cout << "]}" << std::endl;
        }
        result.clear();
    }
}

int
main(int argc, char *argv[])
{
    std::vector<std::string> urls;
    std::vector<std::string> refs;
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
    std::string line;

    if (ifurls.fail()) {
        std::cerr << "cannot read " << argv[1] << std::endl;
        return -1;
    }

    int n = 0;
    std::string sp(" ");
    while (getline(ifurls, line)) {
        std::vector<std::string> ret;
        //std::cout << n++ << std::endl;

        split(line, sp, ret);
        urls.push_back(ret[0]);
        //std::cout << ret[0] << std::endl;

        if (ret.size() >= 2) {
            //std::cout << ret[1] << std::endl;
            refs.push_back(ret[1]);
        } else {
            refs.push_back("");
        }
        ret.clear();
    }

    //std::cout << "loaded " << urls.size() << " urls" << std::endl;
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
                vm.add_rule(line, argv[i]);
            } catch (abpvm_exception e) {
                std::cerr << e.what() << std::endl;
            }
        }
    }

    // vm.print_asm();

    //std::cout << "loaded filters\n" << std::endl;

#ifdef CUIMODE
    for (;;) {
        abpvm_query q;
        std::vector<std::string> result;
        std::string input;
        std::cin >> input;

        q.set_uri(input);

        const auto startTime = std::chrono::system_clock::now();

        vm.match(&result, &q, 1);

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
    const auto startTime = std::chrono::system_clock::now();
/*
    for (std::string &i: urls) {
        abpvm_query q;
        q.set_uri(i);
        std::vector<abpvm::match_result> result;
        vm.match(&result, &q, 1);

        if (result.size() > 0) {
            std::cout << i << std::endl;
            for (auto r: result) {
                std::cout << r.file << ": " << r.rule << std::endl;
            }
            std::cout << std::endl;
        }
    }
*/
    std::thread *th[NUM_THREAD];

    int i;
    for (i = 0; i < NUM_THREAD; i++) {
        th[i] = new std::thread(match, i, NUM_THREAD, std::ref(urls),
                                std::ref(refs), std::ref(vm));
    }

    for (i = 0; i < NUM_THREAD; i++) {
        th[i]->join();
        //delete th[i];
    }

    const auto endTime = std::chrono::system_clock::now();
    const auto timeSpan = endTime - startTime;

    // std::cout << "#urls: " << urls.size()
    //           << "\ntime: " <<
    //     std::chrono::duration_cast<std::chrono::microseconds>(timeSpan).count() / (double)1000000.0
    //     << " [s]\n" << std::endl;
#endif // CUIMODE


    return 0;
}
