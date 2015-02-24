#include "abpvm.hpp"

int
main(int argc, char *argv[])
{
    abpvm vm;

    vm.add_rule("|https:*.ad_");
    vm.add_rule("||2-only.page.ne.jp");
    vm.add_rule("/eas?*^easformat=");
    vm.add_rule("||csdn.net^*/counter.js");

    vm.print_asm();

    return 0;
}
