#include "common/environment.hpp"
#include "common/static_object.hpp"

extern "C"
{
    int rocprofsys_attach(size_t pid, std::vector<char*> env)
        __attribute__((visibility("default")));

    void rocprofsys_detach(size_t pid) __attribute__((visibility("default")));
}