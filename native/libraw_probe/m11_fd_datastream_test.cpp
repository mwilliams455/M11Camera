#include "m11_fd_datastream.h"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <iostream>

#include <fcntl.h>
#include <unistd.h>

static void require(bool condition, const char *message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(2);
    }
}

int main() {
    char path[] = "/tmp/m11-fdstream-XXXXXX";
    int fd = ::mkstemp(path);
    require(fd >= 0, "mkstemp");
    ::unlink(path);

    const char payload[] = "ABCD1234\n-17 2.5 tail";
    const size_t payload_size = sizeof(payload) - 1;
    require(::write(fd, payload, payload_size) == static_cast<ssize_t>(payload_size), "write payload");
    require(::lseek(fd, 0, SEEK_SET) == 0, "rewind source fd");

    m11raw::FdDatastream stream(fd);
    ::close(fd); // stream must own an independent duplicate now.

    require(stream.valid() == 1, "valid after Java/source fd closes");
    require(stream.size() == static_cast<INT64>(payload_size), "size");
    require(stream.tell() == 0, "initial tell");

    char first[5] = {};
    require(stream.read(first, 2, 2) == 2, "fread-style item count");
    require(std::memcmp(first, "ABCD", 4) == 0, "initial bytes");
    require(stream.tell() == 4, "tell after read");

    require(stream.seek(4, SEEK_SET) == 0, "seek set");
    char line[16] = {};
    require(stream.gets(line, sizeof(line)) != nullptr, "gets");
    require(std::strcmp(line, "1234") == 0, "gets removes newline");

    int ivalue = 0;
    require(stream.scanf_one("%d", &ivalue) == 1, "scanf int");
    require(ivalue == -17, "scanf int value");

    float fvalue = 0.0f;
    require(stream.scanf_one("%f", &fvalue) == 1, "scanf float");
    require(std::fabs(fvalue - 2.5f) < 1e-6f, "scanf float value");

    require(stream.seek(-4, SEEK_END) == 0, "seek end");
    char tail[5] = {};
    require(stream.read(tail, 1, 4) == 4, "tail read");
    require(std::memcmp(tail, "tail", 4) == 0, "tail bytes");
    require(stream.eof() == 1, "eof at end");

    require(stream.seek(0, SEEK_SET) == 0, "rewind");
    require(stream.eof() == 0, "not eof after rewind");
    require(stream.seek(-1, SEEK_SET) != 0, "negative absolute seek rejected");

    std::cout << "fd_datastream_conformance=true bytes=" << payload_size << '\n';
    return 0;
}
