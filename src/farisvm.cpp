#include "farisvm.hpp"

#include <algorithm>
#include <iostream>
#include <sstream>
#include <regex>
#include <set>

#define INST_MAX 4096

#define OP_CHAR        0x00
#define OP_SKIP_TO     0x80
#define OP_SKIP_SCHEME 0x83
#define OP_MATCH       0x84

#define CHAR_TAIL      0x7D
#define CHAR_HEAD      0x7E
#define CHAR_SEPARATOR 0x7F

#define VMSTACK_MAX 1024

#define IS_OP_CHAR(INST) (!(0x80 & (INST)))
#define IS_OP_SKIP_SCHEME(INST) ((char)0x83 == (INST))
#define IS_OP_MATCH(INST) ((char)0x84 == (INST))

#define TO_LOWER(CH_) (('A' <= (CH_) && (CH_) <= 'Z') ? (CH_) + ('a' - 'A') : (CH_))
#define UNSIGNED(CH_) (int)(unsigned char)(CH_)

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

farisvm_exception::farisvm_exception(const std::string msg) : m_msg(msg)
{

}

farisvm_exception::~farisvm_exception() throw()
{

}

const char*
farisvm_exception::what() const throw()
{
    return m_msg.c_str();
}

void
farisvm::query_uri::set_uri(const std::string &uri, const std::string &ref)
{
    m_uri = uri;
    m_uri_lower = uri;
    std::transform(m_uri_lower.begin(), m_uri_lower.end(),
                   m_uri_lower.begin(), ::tolower);

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

    m_domain_lower = m_domain;
    std::transform(m_domain_lower.begin(), m_domain_lower.end(),
                   m_domain_lower.begin(), ::tolower);

    // check third-party or not
    colon = ref.find(":");
    if (colon == std::string::npos) {
        m_is_third = false;
        return;
    }

    begin = colon + 1;
    while (begin < ref.size() && ref.at(begin) == '/') {
        begin++;
    }

    if (begin >= ref.size()) {
        m_is_third = false;
        return;
    }

    end = begin + 1;
    while (end < ref.size() && ref.at(end) != '/') {
        end++;
    }

    std::string ref_domain(ref.substr(begin, end - begin));
    std::transform(ref_domain.begin(), ref_domain.end(),
                   ref_domain.begin(), ::tolower);

    if (m_domain_lower == ref_domain) {
        m_is_third = false;
    } else {
        m_is_third = true;
    }
}

farisvm::farisvm()
{

}

farisvm::~farisvm()
{
    spin_rwlock_write lock(m_lock);

    for (auto &p: m_codes) {
        delete p->code;
    }
}

bool
farisvm::check_flag(ptr_farisvm_code code, const query_uri *query)
{
    if (code->flags & FLAG_DOMAIN) {
        const std::string *qd;

        if (code->flags & FLAG_MATCH_CASE) {
            qd = &query->get_domain();
        } else {
            qd = &query->get_domain_lower();
        }

        std::string::const_iterator search_result;
        for (auto &d: code->ex_domains) {
            search_result = (*d.bmh)(qd->begin(), qd->end());
            if (search_result == qd->end()) {
                return false;
            }
        }

        for (auto &d: code->domains) {
            search_result = (*d.bmh)(qd->begin(), qd->end());
            if (search_result != qd->end()) {
                return true;
            }
        }

        return false;
    }

    if (code->flags & FLAG_THIRD_PARTY && ! query->is_third()) {
        return false;
    }

    if (code->flags & FLAG_NOT_THIRD_PARTY && query->is_third()) {
        return false;
    }

    return true;
}

void
farisvm::match_table(std::vector<match_result> *result,
                  const query_uri *query, int size)
{
    int  readnum;
    char h[3];
    
    const char *pc, *sp, *end;

    h[2] = OP_MATCH;

    for (int i = 0; i < size; i++) {
        std::set<ptr_farisvm_code> ret;
        const std::string uri = query[i].get_uri_lower();
        for (int m = 0; m < uri.size(); m++) {
            end = uri.c_str() + uri.size();
            sp = uri.c_str() + m;

            int j;
            char c[2];

            c[0] = *sp;
            c[1] = CHAR_SEPARATOR;

            for (int n = 0; n < 2; n++) {
                j = c[n];

                if (m_table[j].num == 0) {
                    continue;
                }

                h[0] = (char)j;
                h[1] = OP_MATCH;
                if (! vmrun(h, sp, end - sp, readnum)) {
                    continue;
                }

                int k;
                if (IS_OP_CHAR(h[0])) {
                    k = sp[1];
                } else {
                    k = 0;
                }

                for (; k < 256; k++) {
                    if (m_table[j].table[k].codes.empty()) {
                        continue;
                    }

                    h[1] = (char)k;
                    if (! vmrun(h, sp, end - sp, readnum)) {
                        continue;
                    }

                    for (auto &code: m_table[j].table[k].codes) {
                        pc = &code->code[sizeof(farisvm_head)];
                        if (vmrun(pc, sp, end - sp, readnum)) {
                            if (check_flag(code, &query[i])) {
                                ret.insert(code);
                            }
                        }
                    }

                    if (k < 0x7F) {
                        k = CHAR_SEPARATOR - 1;
                    }
                }
            }
        }

        for (auto &code: ret) {
            result[i].push_back(match_result(code->file,
                                             code->original_rule, code->flags));
        }
    }
}

void
farisvm::match_scheme(std::vector<match_result> *result,
                    const query_uri *query, int size)
{
    int  readnum;
    char h[3];
    const char *pc, *sp, *end;

    h[2] = OP_MATCH;

    for (int i = 0; i < size; i++) {
        h[0] = OP_SKIP_SCHEME;
        h[1] = OP_MATCH;

        sp = query[i].get_uri_lower().c_str();
        end = sp + query[i].get_uri_lower().size();

        if (vmrun(h, sp, end - sp, readnum)) {
            sp += readnum;
            for (int j = *sp; j < 256; j++) {
                if (m_table_scheme[j].num == 0) {
                    continue;
                }

                h[0] = (char)j;
                h[1] = OP_MATCH;
                if (! vmrun(h, sp, end - sp, readnum)) {
                    continue;
                }

                int k;
                if (IS_OP_CHAR(h[0])) {
                    k = sp[1];
                } else {
                    k = 0;
                }

                for (; k < 256; k++) {
                    if (m_table_scheme[j].table[k].codes.empty()) {
                        continue;
                    }

                    h[1] = (char)k;
                    if (! vmrun(h, sp, end - sp, readnum)) {
                        continue;
                    }

                    for (auto &code: m_table_scheme[j].table[k].codes) {
                        pc = &code->code[sizeof(farisvm_head) + 2];
                        if (vmrun(pc, sp, end - sp, readnum)) {
                            if (check_flag(code, &query[i])) {
                                result[i].push_back(match_result(code->file, code->original_rule, code->flags));
                            }
                        }
                    }

                    if (k < 0x7F) {
                        k = CHAR_SEPARATOR - 1;
                    }
                }

                if (j < 0x7F) {
                    j = CHAR_SEPARATOR - 1;
                }
            }
        }
    }
}

void
farisvm::match_no_hash(std::vector<match_result> *result,
                     const query_uri *query, int size)
{
    int readnum;

    for (int i = 0; i < size; i++) {
        for (auto &code: m_no_hash) {
            bool ret = false;
            const std::string *uri;

            if (code->flags & FLAG_MATCH_CASE) {
                uri = &query[i].get_uri();
            } else {
                uri = &query[i].get_uri_lower();
            }

            char *pc = code->code + sizeof(farisvm_head);
            bool check_head = false;

            if (*pc == CHAR_HEAD) {
                check_head = true;
                pc++;
            }

            for (int j = 0; j < uri->size(); j++) {
                const char *sp = uri->c_str() + j;

                ret = vmrun(pc, sp, uri->size() - j, readnum);

                if (check_head || ret) {
                    break;
                }
            }

            if (ret) {
                if (check_flag(code, &query[i])) {
                    result[i].push_back(match_result(code->file, code->original_rule, code->flags));
                }
            }
        }
    }
}

void
farisvm::match(std::vector<match_result> *result, const query_uri *query, int size)
{
    // TODO: check input

    spin_rwlock_read lock(m_lock);

    match_scheme(result, query, size);
    match_table(result, query, size);
    match_no_hash(result, query, size);
}

bool
farisvm::vmrun(const char *pc, const char *sp, int splen, int &readnum)
{
    const char *origin = sp;
    const char *end = sp + splen;

    struct {
        const char *pc;
        const char *sp;
    } stack_ptr[VMSTACK_MAX];

    int stack_pos = 0;

    for (;;) {
        if (IS_OP_CHAR(*pc)) {
            if (*pc == CHAR_SEPARATOR) {
                if (! sepchar[(unsigned char)*sp]) {
                    if (stack_pos == 0) {
                        return false;
                    } else {
                        stack_pos--;
                        pc = stack_ptr[stack_pos].pc;
                        sp = stack_ptr[stack_pos].sp;
                        continue;
                    }
                }
            } else {
                if (*pc != *sp && ! (*pc == CHAR_TAIL && sp == end)) {
                    if (stack_pos == 0) {
                        return false;
                    } else {
                        stack_pos--;
                        pc = stack_ptr[stack_pos].pc;
                        sp = stack_ptr[stack_pos].sp;
                        continue;
                    }
                }
            }
            sp++;
        } else if (IS_OP_MATCH(*pc)) {
            readnum = sp - origin;
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
                    if (sp == end) {
                        return false;
                    }
                    sp++;
                }
            } else {
                while (c != *sp) {
                    if (sp == end) {
                        return false;
                    }
                    sp++;
                }
            }
            // push to stack
            if (stack_pos < VMSTACK_MAX) {
                stack_ptr[stack_pos].sp = sp + 1;
                stack_ptr[stack_pos].pc = pc;
                stack_pos++;
            }
        }

        pc++;
    }

    // never reach here
    return true;
}

void
farisvm::print_asm()
{
    int total_inst = 0;
    int total_char = 0;
    int total_skip_to = 0;
    int total_skip_scheme = 0;
    int total_match = 0;

    for (auto &code: m_codes) {
        std::cout << "\"" << code->rule << "\"" << std::endl;

        farisvm_head *head = (farisvm_head*)code->code;
        char *inst = code->code + sizeof(farisvm_head);

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
split(const std::string &str, const std::string &delim,
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
farisvm::add_rule(const std::string &rule, const std::string &file)
{
    std::vector<std::string> sp;
    std::string url_rule;
    ptr_farisvm_code code(new farisvm_code);
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
                                farisvm_domain domain(d);
                                code->ex_domains.push_back(domain);
                            } else {
                                std::transform(d.begin(), d.end(),
                                               d.begin(), ::tolower);
                                farisvm_domain domain(d);
                                code->domains.push_back(domain);
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

    if (url_rule.size() == 0)
        return;

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

    code->flags = flags;
    code->file  = file;
    code->rule  = url_rule;
    code->code  = get_code(url_rule, flags);

    code->original_rule = rule;

    spin_rwlock_write lock(m_lock);
    m_codes.push_back(code);

    farisvm_head *head = (farisvm_head*)code->code;
    char *c = &code->code[sizeof(farisvm_head)];
    unsigned int idx1, idx2;

    if (code->flags & FLAG_MATCH_CASE) {
        m_no_hash.push_back(code);
    } else if (c[0] == CHAR_HEAD) {
        if (IS_OP_SKIP_SCHEME(c[1])) {
            if (head->num_inst < 5) {
                m_no_hash.push_back(code);
            } else {
                idx1 = (unsigned int)c[2] & 0xFF;
                idx2 = (unsigned int)c[3] & 0xFF;
                m_table_scheme[idx1].table[idx2].codes.push_back(code);
                m_table_scheme[idx1].num++;
            }
        } else {
            m_no_hash.push_back(code);
        }
    } else {
        if (head->num_inst < 3) {
            m_no_hash.push_back(code);
        } else {
            idx1 = (unsigned int)c[0] & 0xFF;
            idx2 = (unsigned int)c[1] & 0xFF;
            m_table[idx1].table[idx2].codes.push_back(code);
            m_table[idx1].num++;
        }
    }
}

char *
farisvm::get_code(const std::string &rule, uint32_t flags)
{
    farisvm_head head;
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
            throw(farisvm_exception(oss.str()));
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
                    throw(farisvm_exception(oss.str()));
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
                throw(farisvm_exception(oss.str()));
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
                throw(farisvm_exception(oss.str()));
            }

            sp++;
        }

        head.num_inst++;
    }

    inst[head.num_inst] = OP_MATCH;
    head.num_inst++;

    if (head.num_inst > 1) {
        char *code = new char[sizeof(head) + sizeof(inst[0]) * head.num_inst];

        memcpy(code, &head, sizeof(head));
        memcpy(code + sizeof(head), inst, sizeof(inst[0]) * head.num_inst);

        return code;
    } else {
        // no instructions
        std::ostringstream oss;
        oss << rule << ": no instructions";
        throw(farisvm_exception(oss.str()));
    }

    // never reach here
    return nullptr;
}
