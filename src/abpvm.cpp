#include "abpvm.hpp"

//#include <types.h>

#include <iostream>
#include <sstream>

#define INST_MAX 4096

#define OP_CHAR        0
#define OP_SKIP_TO     1
#define OP_SKIP_SCHEME 2
#define OP_MATCH       3

#define CHAR_HEAD      -1
#define CHAR_TAIL      -2
#define CHAR_SEPARATOR -3

#define FLAG_NOT  0x00001
#define FLAG_CASE 0x00002

// characters for URL by RFC 3986
int urlchar[256] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
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
    for (auto p: m_codes) {
        delete p;
    }
}

void
abpvm::print_asm()
{
    int i = 0;
    for (auto p: m_codes) {
        std::cout << m_rules[i] << ":" << std::endl;
        i++;

        abpvm_head *head;
        abpvm_inst *inst;

        head = (abpvm_head*)p;
        p += sizeof(*head);

        for (int j = 0; j < head->num_inst; j++) {
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
abpvm::add_rule(std::string rule, bool is_match_case, const void *p)
{
    abpvm_head head;
    abpvm_inst inst[INST_MAX];
    const char *sp = rule.c_str();

    head.num_inst = 0;
    head.flag     = 0;
    head.p        = p;

    if (is_match_case)
        head.flag |= FLAG_CASE;

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
    } else if (sp[0] == '@' && sp[1] == '@') {
        head.flag |= FLAG_NOT;
        sp += 2;
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
                if (urlchar[sp[1]]) {
                    inst[head.num_inst].c = sp[1];
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
            if (urlchar[sp[0]]) {
                inst[head.num_inst].opcode = OP_CHAR;
                inst[head.num_inst].c = sp[0];
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
        char *codes = new char[sizeof(head) + sizeof(inst[0]) * head.num_inst];

        memcpy(codes, &head, sizeof(head));
        memcpy(codes + sizeof(head), inst, sizeof(inst[0]) * head.num_inst);

        m_codes.push_back(codes);
        m_rules.push_back(rule);
    }
}
