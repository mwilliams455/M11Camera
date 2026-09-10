#include <libraw/libraw.h>

#include <fcntl.h>
#include <unistd.h>

#include <cstdlib>
#include <iostream>
#include <string>

#include "m11_open_identify_core.h"

namespace {

[[noreturn]] void fail(const std::string &message) {
    std::cerr << "open_identify_conformance=false reason=" << message << '\n';
    std::exit(1);
}

} // namespace

int main(int argc, char **argv) {
    if (argc != 2) fail("expected synthetic DNG path");

    const int fd = ::open(argv[1], O_RDONLY);
    if (fd < 0) fail("could not open fixture");

    const m11raw::IdentifyResult result = m11raw::identifyFdOnly(fd);
    ::close(fd);

    std::cout << m11raw::serializeIdentifyEvidence(result);

    if (result.open_code != LIBRAW_SUCCESS) fail("LibRaw open_datastream failed");
    if (result.libraw_version != "0.22.1") fail("unexpected LibRaw version");
    if (result.decode_invoked) fail("decode flag unexpectedly true");
    if (result.make != "Xiaomi") fail("unexpected make: " + result.make);
    if (result.raw_width != 16 || result.raw_height != 16)
        fail("unexpected raw dimensions");
    if (result.width == 0 || result.height == 0) fail("visible dimensions missing");
    if (result.raw_count < 1) fail("raw_count missing");
    if (result.colors < 1) fail("colour count missing");
    if (result.filters == 0) fail("CFA filter pattern missing");
    if (result.decoder_name.empty()) fail("decoder name missing");

    std::cout << "open_identify_conformance=true\n";
    return 0;
}
