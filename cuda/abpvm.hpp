#ifndef ABPVM_C
#define ABPVM_C

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
    abpvm_query();
    virtual ~abpvm_query();

    void set_uri(const std::string &uri);
    int  get_len() const { return m_len; }
    const char *get_uri() const { return m_uri; }
    const char *get_uri_lower() const { return m_uri_lower; }
    const std::string &get_domain() const { return m_domain; }
    const std::string &get_domain_lower() const { return m_domain_lower; }

private:
    char *m_uri;
    char *m_uri_lower;
    int   m_len;
    std::string m_domain;
    std::string m_domain_lower;
};

class abpvm {
public:
    struct abpvm_match_result {
        std::string rule;
    };

    struct abpvm_head {
        uint32_t flags;
        uint32_t num_inst;
    };

    abpvm();
    virtual ~abpvm();

    void add_rule(const std::string &rule);
    void print_asm();
    void match(std::vector<std::string> &result, const abpvm_query *query, int size);

private:
    typedef boost::algorithm::boyer_moore_horspool<std::string::iterator> BMH;

    struct abpvm_domain {
        abpvm_domain(std::string d) : name(d), bmh(new BMH(d.begin(), d.end())) { }

        std::string name;
        std::shared_ptr<BMH> bmh;
    };

    struct abpvm_code {
        std::vector<abpvm_domain> domains;
        std::vector<abpvm_domain> ex_domains;
        std::string original_rule;
        std::string rule;
        uint32_t    flags;
        int         code_len;
        int         code_len_align;
        char       *code;
    };

    std::vector<std::shared_ptr<abpvm_code>> m_codes;

    char  *m_d_codes_buf;
    int   *m_d_codes_idx;
    char  *m_d_query;
    char  *m_d_query_lower;
    int   *m_d_scheme_len;
    int   *m_d_result;
    int   *m_result_init;
    bool   m_need_gpu_init;
    int    m_grid_dim;
    int    m_block_dim;
    int    m_code_bytes;

    void get_gpu_prop();
    void init_gpu();
    int  skip_scheme(const char *sp);
    bool vmrun(const char *pc, const char *sp);
    char *get_code(const std::string &rule, uint32_t flags, int &len);
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
