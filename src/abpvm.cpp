#include "abpvm.hpp"

#include <algorithm>
#include <iostream>
#include <sstream>
#include <regex>

#define INST_MAX 4096

#define OP_CHAR        0
#define OP_SKIP_TO     1
#define OP_SKIP_SCHEME 2
#define OP_MATCH       3

#define CHAR_TAIL       0
#define CHAR_HEAD      -1
#define CHAR_SEPARATOR -2

#define TO_LOWER(CH_) (('A' <= CH_ && CH_ <= 'Z') ? CH_ + ('a' - 'A') : CH_)
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
int sepchar[256] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
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

abpvm::abpvm()
{

}

abpvm::~abpvm()
{
    for (auto &p: m_codes) {
        delete p.code;
    }
}

void
abpvm::match(char const * const * uri, int size)
{
    // TODO: handle options
    // TODO: check input

    for (int i = 0; i < size; i++) {
        for (auto &code: m_codes) {
            abpvm_head *head = (abpvm_head*)code.code;
            abpvm_inst *pc = (abpvm_inst*)(code.code + sizeof(*head));
            bool check_head = false;
            bool ret = false;

            if (pc->opcode == OP_CHAR && pc->c == CHAR_HEAD) {
                check_head = true;
                pc++;
            }

            for (int j = 0; j < strlen(uri[i]); j++) {
                const char *sp = uri[i] + j;

                ret = vmrun(head, pc, sp);

                if (ret || check_head) {
                    break;
                }
            }

            // TODO: store result
        }
    }
}

bool
abpvm::vmrun(const abpvm_head *head, const abpvm_inst *pc, const char *sp)
{
    for (;;) {
        switch (pc->opcode) {
        case OP_CHAR:
        {
            if (pc->c == CHAR_SEPARATOR) {
                if (! sepchar[(unsigned char)*sp]) {
                    return false;
                }
            } else {
                if (pc->c != *sp) {
                    return false;
                }
            }
            sp++;
        }
        case OP_SKIP_TO:
        {
            if (pc->c == CHAR_SEPARATOR) {
                while (! sepchar[(unsigned char)*sp]) {
                    if (*sp == '\0') {
                        return false;
                    }
                    sp++;
                }
            } else {
                while (pc->c != *sp) {
                    if (*sp == '\0') {
                        return false;
                    }
                    sp++;
                }
            }
        }
        case OP_SKIP_SCHEME:
        {
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
        }
        case OP_MATCH:
            return true;
        }

        pc++;
    }

    // not reach here
    return true;
}

void
abpvm::print_asm()
{
    for (auto &code: m_codes) {
        std::cout << "\"" << code.rule << "\"" << std::endl;

        abpvm_head *head;
        abpvm_inst *inst;
        char *p = code.code;

        head = (abpvm_head*)p;
        p += sizeof(*head);

        for (uint32_t j = 0; j < head->num_inst; j++) {
            inst = (abpvm_inst*)p;
            p += sizeof(*inst);

            if (inst->opcode == OP_CHAR) {
                std::cout << "char ";
                if (inst->c == CHAR_HEAD) {
                    std::cout << "head" << std::endl;
                } else if (inst->c == CHAR_TAIL) {
                    std::cout << "tail" << std::endl;
                } else if (inst->c == CHAR_SEPARATOR) {
                    std::cout << "separator" << std::endl;
                } else {
                    std::cout << inst->c << std::endl;
                }
            } else if (inst->opcode == OP_MATCH) {
                std::cout << "match" << std::endl;
            } else if (inst->opcode == OP_SKIP_TO) {
                std::cout << "skip_to ";
                if (inst->c == CHAR_HEAD) {
                    std::cout << "head" << std::endl;
                } else if (inst->c == CHAR_TAIL) {
                    std::cout << "tail" << std::endl;
                } else if (inst->c == CHAR_SEPARATOR) {
                    std::cout << "separator" << std::endl;
                } else {
                    std::cout << inst->c << std::endl;
                }
            } else if (inst->opcode == OP_SKIP_SCHEME) {
                std::cout << "skip_scheme" << std::endl;
            }
        }
        std::cout << std::endl;
    }
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

    split(rule, "##", sp);

    if (sp.size() > 1) {
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
                            if (d.at(0) == '~') {
                                d.erase(0);
                                std::transform(d.begin(), d.end(),
                                               d.begin(), ::tolower);
                                code.ex_domains.push_back(d);
                            } else {
                                std::transform(d.begin(), d.end(),
                                               d.begin(), ::tolower);
                                code.domains.push_back(d);
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
}

char *
abpvm::get_code(const std::string &rule, uint32_t flags)
{
    abpvm_head head;
    abpvm_inst inst[INST_MAX];
    const char *sp = rule.c_str();

    head.num_inst = 0;
    head.flags    = flags;

    if (sp[0] == '@' && sp[1] == '@') {
        sp += 2;
    }

    if (sp[0] == '|') {
        if (sp[1] == '|') {
            inst[0].opcode = OP_CHAR;
            inst[0].c = CHAR_HEAD;

            inst[1].opcode = OP_SKIP_SCHEME;
            inst[1].c = 0;

            sp += 2;
            head.num_inst += 2;
        } else {
            inst[0].opcode = OP_CHAR;
            inst[0].c = CHAR_HEAD;

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
            inst[head.num_inst].opcode = OP_SKIP_TO;

            if (sp[1] == '^') {
                inst[head.num_inst].c = CHAR_SEPARATOR;
            } else {
                if (urlchar[(unsigned char)sp[1]]) {
                    if (flags & FLAG_MATCH_CASE) {
                        inst[head.num_inst].c = sp[1];
                    } else {
                        inst[head.num_inst].c = TO_LOWER(sp[1]);
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
            inst[head.num_inst].opcode = OP_CHAR;
            inst[head.num_inst].c = CHAR_SEPARATOR;

            sp++;
        } else if (sp[0] == '|') {
            if (sp[1] == '\0') {
                inst[head.num_inst].opcode = OP_CHAR;
                inst[head.num_inst].c = CHAR_TAIL;
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
                inst[head.num_inst].opcode = OP_CHAR;

                if (flags & FLAG_MATCH_CASE) {
                    inst[head.num_inst].c = sp[0];
                } else {
                    inst[head.num_inst].c = TO_LOWER(sp[0]);
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

    inst[head.num_inst].opcode = OP_MATCH;
    inst[head.num_inst].c      = 0;
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
