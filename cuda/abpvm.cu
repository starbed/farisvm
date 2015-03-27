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

#define MAX_BLOCK_DIM 4096
#define MIN_BLOCK_DIM 32

#define SHM_SIZE 49152

#define MAX_CODE_SIZE (SHM_SIZE / MAX_BLOCK_DIM)

#define MAX_QUERY_LEN (1024 * 32)
#define MAX_QUERY_NUM 100

#define MAX_RESULT 64

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

// Beginning of GPU Architecture definitions
inline int
_ConvertSMVer2Cores(int major, int minor)
{
    // Defines for GPU Architecture types (using the SM version to determine the # of cores per SM
    typedef struct
    {
        int SM; // 0xMm (hexidecimal notation), M = SM Major version, and m = SM minor version
        int Cores;
    } sSMtoCores;

    sSMtoCores nGpuArchCoresPerSM[] =
    {
        { 0x20, 32 }, // Fermi Generation (SM 2.0) GF100 class
        { 0x21, 48 }, // Fermi Generation (SM 2.1) GF10x class
        { 0x30, 192}, // Kepler Generation (SM 3.0) GK10x class
        { 0x32, 192}, // Kepler Generation (SM 3.2) GK10x class
        { 0x35, 192}, // Kepler Generation (SM 3.5) GK11x class
        { 0x37, 192}, // Kepler Generation (SM 3.7) GK21x class
        { 0x50, 128}, // Maxwell Generation (SM 5.0) GM10x class
        { 0x52, 128}, // Maxwell Generation (SM 5.2) GM20x class
        {   -1, -1 }
    };

    int index = 0;

    while (nGpuArchCoresPerSM[index].SM != -1)
    {
        if (nGpuArchCoresPerSM[index].SM == ((major << 4) + minor))
        {
            return nGpuArchCoresPerSM[index].Cores;
        }

        index++;
    }

    // If we don't find the values, we default use the previous one to run properly
    printf("MapSMtoCores for SM %d.%d is undefined.  Default to use %d Cores/SM\n", major, minor, nGpuArchCoresPerSM[index-1].Cores);
    return nGpuArchCoresPerSM[index-1].Cores;
}

__device__
void
gpu_print_asm(char *code, int num_inst)
{
    for (int i = 0; i < num_inst; i++) {
        if (IS_OP_CHAR(*code)) {
            printf("char ");
            if (*code == CHAR_HEAD) {
                printf("head\n");
            } else if (*code == CHAR_TAIL) {
                printf("tail\n");
            } else if (*code == CHAR_SEPARATOR) {
                printf("separator\n");
            } else {
                printf("%c\n", *code);
            }
        } else if (IS_OP_MATCH(*code)) {
            printf("match\n");
            return;
        } else if (IS_OP_SKIP_SCHEME(*code)) {
            printf("skip_scheme\n");
        } else {
            char c = 0x7f & *code;
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

        code++;
    }
}

__device__
bool
gpu_vmrun(char *pc, char *sp, int num_inst)
{
    for (int i = 0; i < num_inst; i++) {
        if (IS_OP_CHAR(*pc)) {
            if (*pc == CHAR_SEPARATOR) {
                if (! d_sepchar[(unsigned char)*sp]) {
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
        } else {
            // skip_to
            char c = 0x7f & *pc;
            if (c == CHAR_SEPARATOR) {
                while (! d_sepchar[(unsigned char)*sp]) {
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
    return false;
}

__global__
void
gpu_match(char *codes, int *codes_idx, int num_codes, int *scheme_len,
          char *query, char *query_lower, int query_num, int *result)
{
    for (int i = 0; i < query_num; i++) {
        int idx = blockIdx.x * blockDim.x + threadIdx.x;
        while (idx < num_codes) {
            char *sp;
            char *pc = &codes[codes_idx[idx]];
            abpvm::abpvm_head *head = (abpvm::abpvm_head*)pc;

            pc += sizeof(*head);

            if (head->flags & FLAG_MATCH_CASE) {
                sp = &query[i * MAX_QUERY_LEN];
            } else {
                sp = &query_lower[i * MAX_QUERY_LEN];
            }

            bool ret;
            bool check_head = false;
            if (*pc == CHAR_HEAD) {
                check_head = true;
                pc++;
                if (IS_OP_SKIP_SCHEME(*pc)) {
                    pc++;
                    sp += scheme_len[i];
                }
            }

            while (*sp != '\0') {
                ret = gpu_vmrun(pc, sp, head->num_inst);

                if (check_head || ret) {
                    break;
                }
                sp++;
            }

            if (ret) {
                for (int j = 0; j < MAX_RESULT; j++) {
                    int n = MAX_RESULT * query_num + j;
                    atomicCAS(&result[n], -1, idx);
                    if (result[n] == idx) {
                        break;
                    }
                }
            }

            idx += gridDim.x * blockDim.x;
        }
    }
};

bool
code_cmp(const char *lhs, const char *rhs)
{
    abpvm::abpvm_head *lhead, *rhead;

    lhead = (abpvm::abpvm_head*)lhs;
    rhead = (abpvm::abpvm_head*)rhs;

    lhs += sizeof(*lhead);
    rhs += sizeof(*rhead);

    int len = lhead->num_inst < rhead->num_inst ? lhead->num_inst : rhead->num_inst;

    int ret = memcmp(lhs, rhs, len);
    if (ret < 0) {
        return true;
    } else if (ret > 0) {
        return false;
    } else {
        return lhead->num_inst < rhead->num_inst;
    }
}

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

abpvm_query::abpvm_query()
{
    m_uri = new char[MAX_QUERY_LEN];
    m_uri_lower = new char[MAX_QUERY_LEN];
    //gpuErrchk(cudaMallocHost((void**)&m_uri, MAX_QUERY_LEN));
    //gpuErrchk(cudaMallocHost((void**)&m_uri_lower, MAX_QUERY_LEN));
}

abpvm_query::~abpvm_query()
{
    delete[] m_uri;
    delete[] m_uri_lower;
    //gpuErrchk(cudaFreeHost(m_uri));
    //gpuErrchk(cudaFreeHost(m_uri_lower));
}

void
abpvm_query::set_uri(const std::string &uri)
{
    int len;
    if (uri.size() + 1 > MAX_QUERY_LEN) {
        len = MAX_QUERY_LEN - 1;
    } else {
        len = uri.size();
    }

    m_len = len + 1;

    memcpy(m_uri, uri.c_str(), len);
    memcpy(m_uri_lower, uri.c_str(), len);

    m_uri[len] = '\0';
    m_uri_lower[len] = '\0';

    std::transform(m_uri_lower, m_uri_lower + len,
                   m_uri_lower, ::tolower);

    size_t colon = uri.find(":");
    if (colon == std::string::npos) {
        m_domain = "";
        return;
    }

    size_t begin = colon + 1;
    while (begin < uri.size() && uri.at(begin) == '/') {
        begin++;
    }

    if (begin >= uri.size()) {
        m_domain = "";
        return;
    }

    size_t end = begin + 1;
    while (end < uri.size() && uri.at(end) != '/') {
        end++;
    }

    m_domain = uri.substr(begin, end - begin);

    m_domain_lower = m_domain;
    std::transform(m_domain_lower.begin(), m_domain_lower.end(),
                   m_domain_lower.begin(), ::tolower);
}

abpvm::abpvm() : m_d_codes_buf(nullptr),
                 m_d_codes_idx(nullptr),
                 m_need_gpu_init(true),
                 m_grid_dim(32),
                 m_block_dim(256),
                 m_code_bytes(0)
{
    gpuErrchk(cudaMemcpyToSymbol(d_urlchar, urlchar, sizeof(urlchar)));
    gpuErrchk(cudaMemcpyToSymbol(d_sepchar, sepchar, sizeof(sepchar)));
    gpuErrchk(cudaMemcpyToSymbol(d_schemechar, schemechar, sizeof(schemechar)));

    gpuErrchk(cudaFuncSetCacheConfig(gpu_match, cudaFuncCachePreferL1));

    gpuErrchk(cudaMalloc((void**)&m_d_query, MAX_QUERY_LEN * MAX_QUERY_NUM));
    gpuErrchk(cudaMalloc((void**)&m_d_query_lower, MAX_QUERY_LEN * MAX_QUERY_NUM));
    gpuErrchk(cudaMalloc((void**)&m_d_scheme_len, MAX_QUERY_NUM * sizeof(m_d_scheme_len[0])));
    gpuErrchk(cudaMalloc((void**)&m_d_result, MAX_QUERY_NUM * MAX_RESULT * sizeof(m_d_result[0])));

    gpuErrchk(cudaMallocHost((void**)&m_result_init, MAX_QUERY_NUM * MAX_RESULT * sizeof(m_result_init[0])));

    memset(m_result_init, -1, MAX_QUERY_NUM * MAX_RESULT * sizeof(m_result_init[0]));

    get_gpu_prop();
}

abpvm::~abpvm()
{
    for (auto &p: m_codes) {
        delete[] p->code;
    }

    if (m_d_codes_buf != nullptr) {
        gpuErrchk(cudaFree(m_d_codes_buf));
    }

    if (m_d_codes_idx != nullptr) {
        gpuErrchk(cudaFree(m_d_codes_idx))
    }

    gpuErrchk(cudaFree(m_d_query));
    gpuErrchk(cudaFree(m_d_query_lower));
    gpuErrchk(cudaFree(m_d_scheme_len));
    gpuErrchk(cudaFree(m_d_result));

    gpuErrchk(cudaFreeHost(m_result_init));
}

void
abpvm::get_gpu_prop()
{
    int deviceCount = 0;
    gpuErrchk(cudaGetDeviceCount(&deviceCount));

    cudaDeviceProp deviceProp;
    cudaGetDeviceProperties(&deviceProp, 0);

    m_grid_dim = _ConvertSMVer2Cores(deviceProp.major, deviceProp.minor) * deviceProp.multiProcessorCount;
}

void
abpvm::init_gpu()
{
    if (m_need_gpu_init) {
        if (m_d_codes_buf != nullptr) {
            gpuErrchk(cudaFree(m_d_codes_buf));
        }

        if (m_d_codes_idx != nullptr) {
            gpuErrchk(cudaFree(m_d_codes_idx));
        }

        std::sort(m_codes.begin(), m_codes.end(),
                  [](const std::shared_ptr<abpvm_code> &lhs,
                     const std::shared_ptr<abpvm_code> &rhs)
                     {
                         abpvm_head *rhead, *lhead;
                         char *rc, *lc;

                         rhead = (abpvm_head*)lhs->code;
                         lhead = (abpvm_head*)rhs->code;

                         rc = lhs->code + sizeof(rhead);
                         lc = lhs->code + sizeof(lhead);

                         int len = (lhead->num_inst < rhead->num_inst) ? lhead->num_inst : rhead->num_inst;
                         return memcmp(lc, rc, len);
                     });

        int num_codes = m_codes.size();

        char *codes = new char[m_code_bytes];
        int  *idx   = new int[m_codes.size()];
        int j = 0;
        int pos = 0;
        for (auto &code: m_codes) {
            idx[j] = pos;
            memcpy(codes + pos, code->code, code->code_len);
            pos += code->code_len_align;
            j++;
        }

        gpuErrchk(cudaMalloc((void**)&m_d_codes_buf, m_code_bytes));
        gpuErrchk(cudaMalloc((void**)&m_d_codes_idx, m_codes.size() * sizeof(int)));
        gpuErrchk(cudaMemcpy(m_d_codes_buf, codes, m_code_bytes,
                             cudaMemcpyHostToDevice));
        gpuErrchk(cudaMemcpy(m_d_codes_idx, idx, m_codes.size() * sizeof(int),
                             cudaMemcpyHostToDevice));

        delete[] codes;

        m_need_gpu_init = false;
    }

    int dim;
    for (dim = MIN_BLOCK_DIM; dim < MAX_BLOCK_DIM; dim += 32) {
        if (m_codes.size() <= m_grid_dim * dim) {
            break;
        }
    }

    m_block_dim = dim;
}

int
abpvm::skip_scheme(const char *sp)
{
    int i = 0;
    while (*sp !=':') {
        if (! schemechar[(unsigned char)*sp]) {
            return false;
        }
        sp++;
        i++;
    }

    sp++;
    i++;

    while (*sp == '/') {
        sp++;
        i++;
    }

    return i;
}

void
abpvm::match(std::vector<std::string> &result, const abpvm_query *query, int size)
{
    // TODO: check input
    init_gpu();

    int  *scheme_len;
    char *q_uri, *q_uri_lower;

    gpuErrchk(cudaMallocHost((void**)&scheme_len, MAX_QUERY_NUM * sizeof(scheme_len[0])));
    gpuErrchk(cudaMallocHost((void**)&q_uri, MAX_QUERY_LEN * MAX_QUERY_NUM));
    gpuErrchk(cudaMallocHost((void**)&q_uri_lower, MAX_QUERY_LEN * MAX_QUERY_NUM));

    int n = 0;

    for (int i = 0; i < size; i += MAX_QUERY_NUM) {
        int query_num = 0;
        for (query_num = 0; i + query_num < size &&
                            query_num < MAX_QUERY_NUM; query_num++) {
            int idx = i + query_num;
            int len = query[idx].get_len();
            const char *uri = query[idx].get_uri();
            const char *uri_lower = query[idx].get_uri_lower();

            scheme_len[query_num] = skip_scheme(uri_lower);

            len = (len < MAX_QUERY_LEN) ? len : MAX_QUERY_LEN;

            memcpy(q_uri + query_num * MAX_QUERY_LEN, uri, len);
            memcpy(q_uri_lower + query_num * MAX_QUERY_LEN, uri_lower, len);

            q_uri[query_num * MAX_QUERY_LEN + MAX_QUERY_LEN - 1] = '\0';
            q_uri_lower[query_num * MAX_QUERY_LEN + MAX_QUERY_LEN - 1] = '\0';

            n++;
        }

        gpuErrchk(cudaMemcpy(m_d_query, q_uri, query_num * MAX_QUERY_LEN,
                             cudaMemcpyHostToDevice));
        gpuErrchk(cudaMemcpy(m_d_query_lower, q_uri_lower, query_num * MAX_QUERY_LEN,
                             cudaMemcpyHostToDevice));
        gpuErrchk(cudaMemcpy(m_d_scheme_len, scheme_len, query_num * sizeof(scheme_len[0]),
                             cudaMemcpyHostToDevice));
        gpuErrchk(cudaMemcpy(m_d_result, m_result_init,
                             MAX_QUERY_NUM * MAX_RESULT * sizeof(m_result_init[0]),
                             cudaMemcpyHostToDevice));

        gpu_match<<<m_grid_dim, m_block_dim>>>(m_d_codes_buf,
                                               m_d_codes_idx,
                                               m_codes.size(),
                                               m_d_scheme_len,
                                               m_d_query,
                                               m_d_query_lower,
                                               query_num,
                                               m_d_result);

        //cudaThreadSynchronize();
    }

    cudaFree(scheme_len);
    cudaFree(q_uri);
    cudaFree(q_uri_lower);
}

bool
abpvm::vmrun(const char *pc, const char *sp)
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
        std::cout << "\"" << code->rule << "\"" << std::endl;

        abpvm_head *head = (abpvm_head*)code->code;
        char *inst = code->code + sizeof(abpvm_head);

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
    std::shared_ptr<abpvm_code> code(new abpvm_code);
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
                                code->ex_domains.push_back(domain);
                            } else {
                                std::transform(d.begin(), d.end(),
                                               d.begin(), ::tolower);
                                abpvm_domain domain(d);
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

    int code_len;
    code->flags = flags;
    code->rule  = url_rule;
    code->code  = get_code(url_rule, flags, code_len);
    code->code_len  = code_len;
    code->original_rule = rule;

    int m = code_len % 4;
    code->code_len_align = code_len + ((m > 0) ? 4 - m : 0);

    if (code->code != nullptr) {
        m_codes.push_back(code);
        m_need_gpu_init = true;
        m_code_bytes += code->code_len_align;
    }
}

char *
abpvm::get_code(const std::string &rule, uint32_t flags, int &len)
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
        } else if (sp[0] == '^') {
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

        len = head.num_inst + sizeof(head);
        return code;
    } else {
        return nullptr;
    }
}
