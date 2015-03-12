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

std::regex re_multistar("\\*\\*+");
std::regex re_tailstar("\\*$");
std::regex re_headstar("^\\*");
std::regex re_starbar("\\*\\|$");
std::regex re_barstar("^\\|\\*");
std::regex re_sepbar("\\^\\|$");
std::regex re_scheme("^\\|\\|");
std::regex re_head("^\\|");
std::regex re_star("\\*");
std::regex re_tail("\\|$");
std::regex re_hat("\\^");

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

abpvm::abpvm()
{

}

abpvm::~abpvm()
{

}

void
abpvm::match(std::vector<std::string> &result, const abpvm_query *query, int size)
{
    // TODO: check input

    for (int i = 0; i < size; i++) {
        for (auto &code: m_codes) {
            bool ret = false;

            const std::string &uri(query[i].get_uri());

            if (std::regex_search(uri, *code.re)) {
                ret = true;
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

    url_rule = std::regex_replace(url_rule, re_multistar, "*");
    url_rule = std::regex_replace(url_rule, re_tailstar, "");
    url_rule = std::regex_replace(url_rule, re_headstar, "");
    url_rule = std::regex_replace(url_rule, re_starbar, "");
    url_rule = std::regex_replace(url_rule, re_barstar, "");
    url_rule = std::regex_replace(url_rule, re_sepbar, "^");

    std::cout << rule << std::endl;

    code.flags = flags;
    code.rule  = url_rule;

    try {
        validate_rule(url_rule);
    } catch (abpvm_exception e) {
        return;
    }

    try {
        code.re = get_re(url_rule);
    } catch (...) {
        return;
    }

    code.original_rule = rule;

    m_codes.push_back(code);
}

std::shared_ptr<std::regex>
abpvm::get_re(const std::string &rule)
{
    std::string re_rule = rule;

    re_rule = std::regex_replace(re_rule, re_hat, "(?:[\\x00-\\x24\\x26-\\x2C\\x2F\\x3A-\\x40\\x5B-\\x5E\\x60\\x7B-\\x7F]|$)");
    re_rule = std::regex_replace(re_rule, re_scheme,
                                 "^[\\w\\-]+:\\/+(?!\\/)(?:[^\\/]+\\.)?");
    re_rule = std::regex_replace(re_rule, re_head, "^");  // |foo -> ^foo
    re_rule = std::regex_replace(re_rule, re_star, ".*"); // fo*o -> fo.*o
    re_rule = std::regex_replace(re_rule, re_tail, "$");  // foo| -> foo$

    std::cout << rule << "\n" << re_rule << "\n" << std::endl;

    return std::shared_ptr<std::regex>(new std::regex(re_rule));
}

void
abpvm::validate_rule(const std::string &rule)
{
    const char *sp = rule.c_str();

    if (sp[0] == '@' && sp[1] == '@') {
        sp += 2;
    }

    if (sp[0] == '|') {
        if (sp[1] == '|') {
            sp += 2;
        } else {
            sp++;
        }
    }

    while (*sp != '\0') {
        if (sp[0] == '*') {
            if (sp[1] == '^') {
            } else {
                if (urlchar[(unsigned char)sp[1]]) {
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
            sp++;
        } else if (sp[0] == '|') {
            if (sp[1] == '\0') {
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
    }
}
