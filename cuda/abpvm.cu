#include "abpvm.hpp"

#include <algorithm>
#include <iostream>
#include <sstream>
#include <regex>

#include <stdio.h>

#define INST_MAX 4096

#define OP_CHAR        0x00
#define OP_SKIP_TO     0x80
#define OP_SKIP_SCHEME 0x83
#define OP_MATCH       0x84

#define CHAR_TAIL      0
#define CHAR_HEAD      1
#define CHAR_SEPARATOR 2

#define IS_OP_CHAR(INST) (!(0x80 & (INST)))
#define IS_OP_SKIP_SCHEME(INST) ((char)0x83 == (INST))
#define IS_OP_MATCH(INST) ((char)0x84 == (INST))

#define TO_LOWER(CH_) (('A' <= (CH_) && (CH_) <= 'Z') ? (CH_) + ('a' - 'A') : (CH_))
#define UNSIGNED(CH_) (int)(unsigned char)(CH_)

#define gpuErrchk(ans) { gpuAssert((ans), __FILE__, __LINE__); }
inline void
gpuAssert(cudaError_t code, const char *file, int line, bool abort=true)
{
    if (code != cudaSuccess) {
        fprintf(stderr, "GPUassert: %s %s %d\n", cudaGetErrorString(code),
                file, line);
        if (abort) exit(code);
    }
}

// characters for URL by RFC 3986
int urlchar[256] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1,
                    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1,
                    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

// separators
int sepchar[256] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1,
                    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,
                    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

int schemechar[256] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0,
                       1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
                       0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                       1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
                       0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                       1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

__constant__ int  d_urlchar[256];
__constant__ int  d_sepchar[256];
__constant__ int  d_schemechar[256];
__constant__ char d_query[1024 * 8];

__device__
void
cu_print_asm(char **codes, int num_codes)
{
    struct abpvm_head {
        uint32_t flags;
        uint32_t num_inst;
    };

    for (int i = 0; i < 100; i++) {
        abpvm_head *head = (abpvm_head*)codes[i];
        char *inst = codes[i] + sizeof(abpvm_head);

        for (uint32_t j = 0; j < head->num_inst; j++, inst++) {
            if (IS_OP_CHAR(*inst)) {
                printf("char ");
                if (*inst == CHAR_HEAD) {
                    printf("head\n");
                } else if (*inst == CHAR_TAIL) {
                    printf("tail\n");
                } else if (*inst == CHAR_SEPARATOR) {
                    printf("separator\n");
                } else {
                    printf("%c\n", *inst);
                }
            } else if (IS_OP_MATCH(*inst)) {
                printf("match\n");
            } else if (IS_OP_SKIP_SCHEME(*inst)) {
                printf("skip_scheme\n");
            } else {
                char c = 0x7f & *inst;
                printf("skip_to ");
                if (c == CHAR_HEAD) {
                    printf("head\n");
                } else if (c == CHAR_TAIL) {
                    printf("tail\n");
                } else if (c == CHAR_SEPARATOR) {
                    printf("separator\n");
                } else {
                    printf("%c\n", c);
                }
            }
        }

        printf("\n");
    }
}

__global__
void
cu_vmrun(char **codes, int num_codes)
{

};

abpvm_exception::abpvm_exception(const std::string msg) : m_msg(msg)
{

}

abpvm_exception::~abpvm_exception() throw()
{

}

const char*
abpvm_exception::what() const throw()
{
    return m_msg.c_str();
}

void
abpvm_query::set_uri(const std::string &uri)
{
    m_uri = uri;

    size_t colon = m_uri.find(":");
    if (colon == std::string::npos) {
        m_domain = "";
        return;
    }

    size_t begin = colon + 1;
    while (begin < m_uri.size() && m_uri.at(begin) == '/') {
        begin++;
    }

    if (begin >= m_uri.size()) {
        m_domain = "";
        return;
    }

    size_t end = begin + 1;
    while (end < m_uri.size() && m_uri.at(end) != '/') {
        end++;
    }

    m_domain = uri.substr(begin, end - begin);
}

abpvm::abpvm() : m_need_cu_init(true)
{
    gpuErrchk(cudaMemcpyToSymbol(d_urlchar, urlchar, sizeof(urlchar)));
    gpuErrchk(cudaMemcpyToSymbol(d_sepchar, sepchar, sizeof(sepchar)));
    gpuErrchk(cudaMemcpyToSymbol(d_schemechar, schemechar, sizeof(schemechar)));
}

abpvm::~abpvm()
{
    for (auto &p: m_codes) {
        cudaFree(p.d_code);
        delete p.code;
    }

    if (m_d_codes != nullptr) {
        cudaFree(m_d_codes);
    }
}

void
abpvm::init_gpumem()
{
    if (m_need_cu_init) {
        if (m_d_codes != nullptr){
            cudaFree(m_d_codes);
        }
        gpuErrchk(cudaMalloc((void**)&m_d_codes,
                             m_codes.size() * sizeof(m_d_codes[0])));

        int num_codes = m_codes.size();

        for (int i = 0; i < num_codes; i++) {
            abpvm_head *head = (abpvm_head*)m_codes[i].code;
            uint32_t len = head->num_inst + sizeof(*head);
            gpuErrchk(cudaMalloc((void**)&m_codes[i].d_code, len));
            gpuErrchk(cudaMemcpy(m_codes[i].d_code, m_codes[i].code, len,
                                 cudaMemcpyHostToDevice));
            gpuErrchk(cudaMemcpy(&m_d_codes[i], &m_codes[i].d_code, sizeof(char*),
                                 cudaMemcpyHostToDevice));
        }

        m_need_cu_init = false;

        std::cout << "init rules" << std::endl;
    }
}

void
abpvm::match(std::vector<std::string> &result, const abpvm_query *query, int size)
{
    // TODO: check input

    init_gpumem();

    cu_vmrun<<<1, 1>>>(m_d_codes, m_codes.size());
    cudaThreadSynchronize();

    return;

    for (int i = 0; i < size; i++) {
        for (auto &code: m_codes) {
            abpvm_head *head = (abpvm_head*)code.code;
            char *pc = code.code + sizeof(*head);
            bool check_head = false;
            bool ret = false;

            if (*pc == CHAR_HEAD) {
                check_head = true;
                pc++;
            }

            const std::string &uri(query[i].get_uri());
            for (int j = 0; j < uri.size(); j++) {
                const char *sp = uri.c_str() + j;

                ret = vmrun(head, pc, sp);

                if (ret || check_head) {
                    break;
                }
            }

            if (ret) {
                // TODO: check options
                // check domains
                if (code.flags & FLAG_DOMAIN) {
                    const std::string &qd(query[i].get_domain());
                    std::string::const_iterator search_result;

                    for (auto &d: code.ex_domains) {
                        search_result = (*d.bmh)(qd.begin(), qd.end());
                        if (search_result == qd.end()) {
                            continue;
                        }
                    }

                    for (auto &d: code.domains) {
                        search_result = (*d.bmh)(qd.begin(), qd.end());
                        if (search_result != qd.end()) {
                            goto found;
                        }
                    }

                    continue;
                }
found:
                result.push_back(code.original_rule);
            }
        }
    }
}

bool
abpvm::vmrun(const abpvm_head *head, const char *pc, const char *sp)
{
    for (;;) {
        if (IS_OP_CHAR(*pc)) {
            if (*pc == CHAR_SEPARATOR) {
                if (! sepchar[(unsigned char)*sp]) {
                    return false;
                }
            } else {
                if (*pc != *sp) {
                    return false;
                }
            }
            sp++;
        } else if (IS_OP_MATCH(*pc)) {
            return true;
        } else if (IS_OP_SKIP_SCHEME(*pc)) {
            while (*sp !=':') {
                if (! schemechar[(unsigned char)*sp]) {
                    return false;
                }
                sp++;
            }

            sp++;

            while (*sp == '/') {
                sp++;
            }
        } else {
            // skip_to
            char c = 0x7f & *pc;
            if (c == CHAR_SEPARATOR) {
                while (! sepchar[(unsigned char)*sp]) {
                    if (*sp == '\0') {
                        return false;
                    }
                    sp++;
                }
            } else {
                while (c != *sp) {
                    if (*sp == '\0') {
                        return false;
                    }
                    sp++;
                }
            }
        }

        pc++;
    }

    // never reach here
    return true;
}

void
abpvm::print_asm()
{
    int total_inst = 0;
    int total_char = 0;
    int total_skip_to = 0;
    int total_skip_scheme = 0;
    int total_match = 0;

    for (auto &code: m_codes) {
        std::cout << "\"" << code.rule << "\"" << std::endl;

        abpvm_head *head = (abpvm_head*)code.code;
        char *inst = code.code + sizeof(abpvm_head);

        total_inst += head->num_inst;

        for (uint32_t j = 0; j < head->num_inst; j++, inst++) {
            if (IS_OP_CHAR(*inst)) {
                std::cout << "char ";
                total_char++;
                if (*inst == CHAR_HEAD) {
                    std::cout << "head" << std::endl;
                } else if (*inst == CHAR_TAIL) {
                    std::cout << "tail" << std::endl;
                } else if (*inst == CHAR_SEPARATOR) {
                    std::cout << "separator" << std::endl;
                } else {
                    std::cout << *inst << std::endl;
                }
            } else if (IS_OP_MATCH(*inst)) {
                std::cout << "match" << std::endl;
                total_match++;
            } else if (IS_OP_SKIP_SCHEME(*inst)) {
                std::cout << "skip_scheme" << std::endl;
                total_skip_scheme++;
            } else {
                char c = 0x7f & *inst;
                std::cout << "skip_to ";
                total_skip_to++;
                if (c == CHAR_HEAD) {
                    std::cout << "head" << std::endl;
                } else if (c == CHAR_TAIL) {
                    std::cout << "tail" << std::endl;
                } else if (c == CHAR_SEPARATOR) {
                    std::cout << "separator" << std::endl;
                } else {
                    std::cout << c << std::endl;
                }
            }
        }
        std::cout << std::endl;
    }

    std::cout << "#rule = " << m_codes.size()
              << "\n#instruction = " << total_inst
              << "\n#char = " << total_char
              << "\n#skip_to = " << total_skip_to
              << "\nskip_scheme = " << total_skip_scheme
              << "\nmatch = " << total_match
              << "\n" << std::endl;
}

void
abpvm::split(const std::string &str, const std::string &delim,
             std::vector<std::string> &ret)
{
    size_t current = 0, found, delimlen = delim.size();

    while((found = str.find(delim, current)) != std::string::npos) {
        ret.push_back(std::string(str, current, found - current));
        current = found + delimlen;
    }

    ret.push_back(std::string(str, current, str.size() - current));
}

void
abpvm::add_rule(const std::string &rule)
{
    std::vector<std::string> sp;
    std::string url_rule;
    abpvm_code code;
    uint32_t flags = 0;

    // do not add empty rules
    // do not add any comments
    if (rule.size() == 0 || rule.at(0) == '!') {
        return;
    }

    if (rule.find("##") != std::string::npos ||
        rule.find("#@#") != std::string::npos) {
        // TODO: element hide
        return;
    } else {
        // URL filter
        sp.clear();

        split(rule, "$", sp);

        if (sp.size() > 1) {
            std::vector<std::string> opts;

            split(sp[1], ",", opts);

            for (auto &opt: opts) {
                if (opt == "match-case") {
                    flags |= FLAG_MATCH_CASE;
                } else if (opt == "script") {
                    flags |= FLAG_SCRIPT;
                } else if (opt == "~script") {
                    flags |= FLAG_NOT_SCRIPT;
                } else if (opt == "image") {
                    flags |= FLAG_IMAGE;
                } else if (opt == "~image") {
                    flags |= FLAG_NOT_IMAGE;
                } else if (opt == "stylesheet") {
                    flags |= FLAG_STYLESHEET;
                } else if (opt == "~stylesheet") {
                    flags |= FLAG_NOT_STYLESHEET;
                } else if (opt == "object") {
                    flags |= FLAG_OBJECT;
                } else if (opt == "~object") {
                    flags |= FLAG_NOT_OBJECT;
                } else if (opt == "xmlhttprequest") {
                    flags |= FLAG_XMLHTTPREQUEST;
                } else if (opt == "~xmlhttprequest") {
                    flags |= FLAG_NOT_XMLHTTPREQUEST;
                } else if (opt == "object-subrequest") {
                    flags |= FLAG_OBJECT_SUBREQUEST;
                } else if (opt == "~object-subrequest") {
                    flags |= FLAG_NOT_OBJECT_SUBREQUEST;
                } else if (opt == "subdocument") {
                    flags |= FLAG_SUBDOCUMENT;
                } else if (opt == "~subdocument") {
                    flags |= FLAG_NOT_SUBDOCUMENT;
                } else if (opt == "document") {
                    flags |= FLAG_DOCUMENT;
                } else if (opt == "~document") {
                    flags |= FLAG_NOT_DOCUMENT;
                } else if (opt == "elemhide") {
                    flags |= FLAG_ELEMHIDE;
                } else if (opt == "~elemhide") {
                    flags |= FLAG_NOT_ELEMHIDE;
                } else if (opt == "other") {
                    flags |= FLAG_OTHER;
                } else if (opt == "~other") {
                    flags |= FLAG_NOT_OTHER;
                } else if (opt == "third-party") {
                    flags |= FLAG_THIRD_PARTY;
                } else if (opt == "~third-party") {
                    flags |= FLAG_NOT_THIRD_PARTY;
                } else if (opt == "collapse") {
                    flags |= FLAG_COLLAPSE;
                } else if (opt == "~collapse") {
                    flags |= FLAG_NOT_COLLAPSE;
                } else {
                    std::string s = opt.substr(0, 7); // domain=
                    if (s == "domain=") {
                        std::vector<std::string> sp2;
                        s = opt.substr(7);
                        split(s, "|", sp2);

                        for (auto &d: sp2) {
                            if (d.empty())
                                continue;

                            if (d.at(0) == '~') {
                                d.erase(0);
                                std::transform(d.begin(), d.end(),
                                               d.begin(), ::tolower);
                                abpvm_domain domain(d);
                                code.ex_domains.push_back(domain);
                            } else {
                                std::transform(d.begin(), d.end(),
                                               d.begin(), ::tolower);
                                abpvm_domain domain(d);
                                code.domains.push_back(domain);
                            }
                        }

                        flags |= FLAG_DOMAIN;
                    }
                }
            }
        }

        url_rule = sp[0];
        if (url_rule.size() >= 2 &&
            url_rule.at(0) == '@' && url_rule.at(1) == '@') {
            flags |= FLAG_NOT;
        }
    }

    // preprocess rule
    std::string result;

    std::regex re_multistar("\\*\\*+");
    std::regex re_tailstar("\\*$");
    std::regex re_headstar("^\\*");
    std::regex re_starbar("\\*\\|$");
    std::regex re_barstar("^\\|\\*");
    std::regex re_sepbar("\\^\\|$");

    url_rule = std::regex_replace(url_rule, re_multistar, "*");
    url_rule = std::regex_replace(url_rule, re_tailstar, "");
    url_rule = std::regex_replace(url_rule, re_headstar, "");
    url_rule = std::regex_replace(url_rule, re_starbar, "");
    url_rule = std::regex_replace(url_rule, re_barstar, "");
    url_rule = std::regex_replace(url_rule, re_sepbar, "^");

    code.flags = flags;
    code.rule  = url_rule;
    code.code  = get_code(url_rule, flags);

    code.original_rule = rule;

    if (code.code != nullptr)
        m_codes.push_back(code);

    m_need_cu_init = true;
}

char *
abpvm::get_code(const std::string &rule, uint32_t flags)
{
    abpvm_head head;
    char inst[INST_MAX];
    const char *sp = rule.c_str();

    head.num_inst = 0;
    head.flags    = flags;

    if (sp[0] == '@' && sp[1] == '@') {
        sp += 2;
    }

    if (sp[0] == '|') {
        if (sp[1] == '|') {
            inst[0] = CHAR_HEAD;
            inst[1] = OP_SKIP_SCHEME;

            sp += 2;
            head.num_inst += 2;
        } else {
            inst[0] = CHAR_HEAD;

            sp++;
            head.num_inst++;
        }
    }

    while (*sp != '\0') {
        if (head.num_inst >= INST_MAX - 1) {
            // too many instructions
            std::ostringstream oss;
            oss << rule << ":\n"
                << "\ttoo many instructions (exceeded " << INST_MAX << ")";
            throw(abpvm_exception(oss.str()));
        }

        if (sp[0] == '*') {
            inst[head.num_inst] = OP_SKIP_TO;

            if (sp[1] == '^') {
                inst[head.num_inst] |= CHAR_SEPARATOR;
            } else {
                if (urlchar[(unsigned char)sp[1]]) {
                    if (flags & FLAG_MATCH_CASE) {
                        inst[head.num_inst] |= sp[1];
                    } else {
                        inst[head.num_inst] |= TO_LOWER(sp[1]);
                    }
                } else {
                    // invalid character
                    std::ostringstream oss;
                    oss << rule << ":\n"
                        << "\tinvalid character at " << &sp[1] - rule.c_str()
                        << " (" << sp[1] << ")";
                    throw(abpvm_exception(oss.str()));
                }
            }

            sp += 2;
        } else if (sp[0] == '^'){
            inst[head.num_inst] = CHAR_SEPARATOR;
            sp++;
        } else if (sp[0] == '|') {
            if (sp[1] == '\0') {
                inst[head.num_inst] = CHAR_TAIL;
            } else {
                // parse error
                std::ostringstream oss;
                oss << rule << ":\n"
                    << "\tinvalid character at " << &sp[0] - rule.c_str()
                    << " (" << sp[0] << ")";
                throw(abpvm_exception(oss.str()));
            }

            sp++;
        } else {
            if (urlchar[(unsigned char)sp[0]]) {
                inst[head.num_inst] = OP_CHAR;

                if (flags & FLAG_MATCH_CASE) {
                    inst[head.num_inst] = sp[0];
                } else {
                    inst[head.num_inst] = TO_LOWER(sp[0]);
                }
            } else {
                // invalide character
                std::ostringstream oss;
                oss << rule << ":\n"
                    << "\tinvalid character at " << &sp[0] - rule.c_str()
                    << " (" << sp[0] << ")";
                throw(abpvm_exception(oss.str()));
            }

            sp++;
        }

        head.num_inst++;
    }

    inst[head.num_inst] = OP_MATCH;
    head.num_inst++;

    if (head.num_inst > 0) {
        char *code = new char[sizeof(head) + sizeof(inst[0]) * head.num_inst];

        memcpy(code, &head, sizeof(head));
        memcpy(code + sizeof(head), inst, sizeof(inst[0]) * head.num_inst);

        return code;
    } else {
        return nullptr;
    }
}
