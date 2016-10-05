# FARIS: the FAst uniform Resource Identifier-Specific filter

## What?

  Uniform resource locator (URL) filtering is a fundamental technology for
intrusion detection, HTTP proxies,
content distribution networks, content-centric networks, and many other application areas.
Some applications adopt URL filtering
to protect user privacy from malicious or insecure websites.
AdBlock Plus is an example of a URL-filtering application, which filters
sites that intend to steal sensitive information.

Unfortunately, AdBlock Plus is implemented inefficiently,
resulting in a slow application that consumes much memory.
Although it provides a domain-specific language (DSL) to represent URLs,
it internally uses regular expressions
and does not take advantage of the benefits of the DSL.
In addition, the number of filter rules become large, which makes matters worse.

Thus, we propose the fast uniform resource identifier-specific filter,
which is a domain-specific pseudo-machine for the DSL,
to improve the performance of AdBlock Plus.
Compared with a conventional implementation
that internally adopts regular expressions,
our proof-of-concept implementation is fast and small memory footprint.

## How to Use

```c
#include "farisvm.hpp"
#include <iostream>

int
main(int argc, char *argv[])
{
    farisvm vm; // create a instance of FARIS

    // add filter rules
    //
    // add_rule(filter, filename)
    //    filter: filter rule of AdBlock Plus
    //    filename: file name of the filter rule
    vm.add_rule("||example.com^index", "filter1.txt");
    vm.add_rule(".swf|", "filter2.txt");

    std::vector<farisvm::match_result> result[3]; // a vector in which the results are stored
    farisvm::query_uri query[3]; // a query object

    // set urls for query object
    //
    // set_uri(uri, referer)
    //     uri: URI
    //     referer: HTTP referer
    query[0].set_uri("https://www.google.com/", "http://referer.com/");
    query[1].set_uri("http://example.com/index.html", "http://referer.com/");
    query[2].set_uri("http://example.com/index.swf", "http://referer.com/");

    // do matching
    //
    // match(result, query, query_num)
    //     result: the results of matching
    //     query: URIs to be matched
    //     query_num: the number or URIs
    vm.match(result, query, 3);

    for (int i = 0; i < 3; i++) {
        std::cout << query[i].get_uri() << std::endl;
        for (auto ret: result[i]) {
            std::cout << "  rule: " << ret.rule                 // print a matched rule
                      << "\n  file: " << ret.file << std::endl; // print the file name of the rule
        }
        std::cout << std::endl;
    }

    return 0;
}
```

## Publication

Yuuki Takano and Ryosuke Miura, "FARIS: Fast and Memory-efficient URL Filter by Domain Specific Machine", IEEE International Conference on IT Convergence and Security 2016 (ICITCS 2016), Sep. 2016, ISBN 987-1-5090-3764-3, pp. 204-210.