#ifndef ABPVM_C
#define ABPVM_C

#include "spin_rwlock.hpp"

#include <string>
#include <vector>
#include <exception>
#include <memory>

#include <boost/algorithm/searching/boyer_moore_horspool.hpp>

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
#define FLAG_DOMAIN                (0x00000001 << 26)

class abpvm_query {
public:
    void set_uri(const std::string &uri, const std::string &ref);
    const std::string &get_uri() const { return m_uri; }
    const std::string &get_uri_lower() const { return m_uri_lower; }
    const std::string &get_domain() const { return m_domain; }
    const std::string &get_domain_lower() const { return m_domain_lower; }
    bool is_third() const { return m_is_third; }

private:
    std::string m_uri;
    std::string m_uri_lower;
    std::string m_domain;
    std::string m_domain_lower;
    bool m_is_third;
};

class abpvm {
public:
    struct match_result {
        std::string file;
        std::string rule;
        uint32_t    flags;

        match_result(const std::string &f, const std::string r, uint32_t flg) : file(f), rule(r), flags(flg) {}
    };

    abpvm();
    virtual ~abpvm();

    void add_rule(const std::string &rule, const std::string &file);
    void print_asm();
    void match(std::vector<match_result> *result, const abpvm_query *query, int size);

private:
    typedef boost::algorithm::boyer_moore_horspool<std::string::iterator> BMH;

    struct abpvm_domain {
        abpvm_domain(std::string d) : name(d), bmh(new BMH(d.begin(), d.end())) { }

        std::string name;
        std::shared_ptr<BMH> bmh;
    };

    struct abpvm_head {
        uint32_t flags;
        uint32_t num_inst;
    };

    struct abpvm_code {
        std::vector<abpvm_domain> domains;
        std::vector<abpvm_domain> ex_domains;
        std::string file;
        std::string original_rule;
        std::string rule;
        uint32_t    flags;
        char       *code;
    };

    spin_rwlock m_lock;

    typedef std::shared_ptr<abpvm_code> ptr_abpvm_code;

    struct abpvm_table1 {
        std::vector<ptr_abpvm_code> codes;
    };

    struct abpvm_table0 {
        int num;
        abpvm_table1 table[256];

        abpvm_table0() : num(0) { }
    };

    std::vector<ptr_abpvm_code> m_codes;
    abpvm_table0 m_table_scheme[256];
    abpvm_table0 m_table[128];
    std::vector<ptr_abpvm_code> m_no_hash; // cannot be hashed

    bool vmrun(const char *pc, const char *sp, int splen, int &readnum);
    char *get_code(const std::string &rule, uint32_t flags);
    bool check_flag(ptr_abpvm_code code, const abpvm_query *query);
    void match_scheme(std::vector<match_result> *result, const abpvm_query *query, int size);
    void match_table(std::vector<match_result> *result, const abpvm_query *query, int size);
    void match_no_hash(std::vector<match_result> *result, const abpvm_query *query, int size);
};

struct abpvm_exception : public std::exception
{
    abpvm_exception(const std::string msg);
    ~abpvm_exception() throw();

    const char* what() const throw();

    std::string m_msg;
};

void split(const std::string &str, const std::string &delim,
           std::vector<std::string> &ret);

#endif // ABPVM
