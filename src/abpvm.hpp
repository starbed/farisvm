#ifndef ABPVM_C
#define ABPVM_C

#include <string>
#include <vector>
#include <exception>

class abpvm {
public:
    abpvm();
    virtual ~abpvm();

    void add_rule(std::string rule, bool is_match_case = false,
                  const void *p = NULL);
    void print_asm();

private:
    struct abpvm_head {
        uint32_t flag;
        int  num_inst;
        const void *p; // for storing information of this rule
    };

    struct abpvm_inst {
        uint8_t opcode;
        char    c;
    };

    std::vector<char*> m_codes;
    std::vector<std::string> m_rules;
};

struct abpvm_exception : public std::exception
{
    abpvm_exception(const std::string msg);
    ~abpvm_exception() throw();

    const char* what() const throw();

    std::string m_msg;
};

#endif // ABPVM
