#include <cstddef>
#include <cstdint>
#include <dlfcn.h>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/ptrace.h>
#include <unordered_map>
#include <vector>

namespace rocprofsys
{
namespace attach
{

int&
get_verbose();
class PTraceSession
{
public:
    explicit PTraceSession(size_t);
    ~PTraceSession();

    bool attach();
    bool detach();
    bool simple_mmap(void*& addr, size_t length);
    bool simple_munmap(void*& addr, size_t length);

    bool write(size_t addr, const std::vector<uint8_t>& data, size_t size);
    bool read(size_t addr, std::vector<uint8_t>& data, size_t size);
    bool swap(size_t addr, const std::vector<uint8_t>& in_data,
              std::vector<uint8_t>& out_data, size_t size);

    size_t get_pid();

    bool call_function(const std::string& library, const std::string& symbol);
    bool call_function(const std::string& library, const std::string& symbol,
                       void* first);
    bool call_function(const std::string& library, const std::string& symbol, void* first,
                       void* second);
    bool call_function(const std::string& library, const std::string& symbol, void* first,
                       void* second, unsigned long long* ret);

    unsigned long long open_library(const std::string& library);
    unsigned long long open_library(const std::string& library, int flag);

    bool stop();
    bool cont();

private:
    bool find_library(void*& addr, int inpid, const std::string& library);
    bool find_symbol(void*& addr, const std::string& library, const std::string& symbol);

    std::unordered_map<std::string, void*> target_library_addrs;
    std::unordered_map<std::string, void*> target_symbol_addrs;

    const size_t pid;
    bool         attached;
};
}  // namespace attach
}  // namespace rocprofsys

class NullBuffer : public std::streambuf
{
public:
    int overflow(int c) override { return c; }
};

inline NullBuffer   null_buffer;
inline std::ostream rocprofsys_null_stream(&null_buffer);

#ifndef ROCPROFSYS_INFO
#    define ROCPROFSYS_INFO                                                              \
        ((rocprofsys::attach::get_verbose() > 1) ? std::cout : rocprofsys_null_stream)
#endif

#ifndef ROCPROFSYS_ERROR
#    define ROCPROFSYS_ERROR std::cerr
#endif
