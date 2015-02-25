#ifndef ABPVM_C
#define ABPVM_C

#include <string>
#include <vector>
#include <exception>

#define FLAG_MATCH_CASE             0x00000001
#define FLAG_NOT                   (0x00000001 <<  1)
#define FLAG_SCRIPT                (0x00000001 <<  2)
#define FLAG_NOT_SCRIPT            (0x00000001 <<  3)
#define FLAG_IMAGE                 (0x00000001 <<  4)
#define FLAG_NOT_IMAGE             (0x00000001 <<  5)
#define FLAG_STYLESHEET            (0x00000001 <<  6)
#define FLAG_NOT_STYLESHEET        (0x00000001 <<  7)
#define FLAG_OBJECT                (0x00000001 <<  8)
#define FLAG_NOT_OBJECT            (0x00000001 <<  9)
#define FLAG_XMLHTTPREQUEST        (0x00000001 << 10)
#define FLAG_NOT_XMLHTTPREQUEST    (0x00000001 << 11)
#define FLAG_OBJECT_SUBREQUEST     (0x00000001 << 12)
#define FLAG_NOT_OBJECT_SUBREQUEST (0x00000001 << 13)
#define FLAG_SUBDOCUMENT           (0x00000001 << 14)
#define FLAG_NOT_SUBDOCUMENT       (0x00000001 << 15)
#define FLAG_DOCUMENT              (0x00000001 << 16)
#define FLAG_NOT_DOCUMENT          (0x00000001 << 17)
#define FLAG_ELEMHIDE              (0x00000001 << 18)
#define FLAG_NOT_ELEMHIDE          (0x00000001 << 19)
#define FLAG_OTHER                 (0x00000001 << 20)
#define FLAG_NOT_OTHER             (0x00000001 << 21)
#define FLAG_THIRD_PARTY           (0x00000001 << 22)
#define FLAG_NOT_THIRD_PARTY       (0x00000001 << 23)
#define FLAG_COLLAPSE              (0x00000001 << 24)
#define FLAG_NOT_COLLAPSE          (0x00000001 << 25)

class abpvm {
public:
    abpvm();
    virtual ~abpvm();

    void add_rule(const std::string &rule);
    void print_asm();

private:
    struct abpvm_head {
        uint32_t flags;
        uint32_t num_inst;
    };

    struct abpvm_inst {
        uint8_t opcode;
        char    c;
    };

    struct abpvm_code {
        std::vector<std::string> domains;
        std::vector<std::string> ex_domains;
        std::string rule;
        uint32_t    flags;
        char       *code;
    };

    std::vector<abpvm_code> m_codes;

    char *get_code(const std::string &rule, uint32_t flags);
    void split(const std::string &str, const std::string &delim,
               std::vector<std::string> &ret);
};

struct abpvm_exception : public std::exception
{
    abpvm_exception(const std::string msg);
    ~abpvm_exception() throw();

    const char* what() const throw();

    std::string m_msg;
};

#endif // ABPVM
