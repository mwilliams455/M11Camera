#include <libraw/libraw.h>

#include <fcntl.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "m11_fd_datastream.h"
#include "m11_raw_oracle_params.h"

namespace fs = std::filesystem;

namespace {

[[noreturn]] void fail(const std::string &message) {
    std::cerr << "pixel_parity_dump=false reason=" << message << '\n';
    std::exit(1);
}

void writeU16LE(std::ofstream &out, std::uint16_t value) {
    const unsigned char bytes[2] = {
        static_cast<unsigned char>(value & 0xffu),
        static_cast<unsigned char>((value >> 8) & 0xffu)
    };
    out.write(reinterpret_cast<const char *>(bytes), 2);
}

} // namespace

int main(int argc, char **argv) {
    if (argc != 3) fail("usage: m11rawpixeldump input.dng output_dir");

    const fs::path dng_path(argv[1]);
    const fs::path out_dir(argv[2]);
    fs::create_directories(out_dir);

    const int source_fd = ::open(dng_path.c_str(), O_RDONLY);
    if (source_fd < 0) fail("could not open input DNG");

    m11raw::FdDatastream stream(source_fd);
    ::close(source_fd);
    if (!stream.valid()) fail("fd datastream invalid");

    LibRaw raw;
    int rc = raw.open_datastream(&stream);
    if (rc != LIBRAW_SUCCESS) fail("open_datastream: " + std::string(LibRaw::strerror(rc)));

    // Match rawpy.RawPy.raw_image_visible: ensure_unpack() first, then expose
    // the visible Bayer mosaic before dcraw_process modifies the image state.
    rc = raw.unpack();
    if (rc != LIBRAW_SUCCESS) fail("unpack: " + std::string(LibRaw::strerror(rc)));
    if (raw.imgdata.rawdata.raw_image == nullptr) fail("fixture did not unpack to flat Bayer raw_image");

    const unsigned mosaic_width = raw.imgdata.sizes.width;
    const unsigned mosaic_height = raw.imgdata.sizes.height;
    const unsigned raw_width = raw.imgdata.sizes.raw_width;
    const unsigned top_margin = raw.imgdata.sizes.top_margin;
    const unsigned left_margin = raw.imgdata.sizes.left_margin;
    const std::uint16_t *raw_image = raw.imgdata.rawdata.raw_image;

    std::ofstream mosaic(out_dir / "mosaic_u16le.bin", std::ios::binary);
    if (!mosaic) fail("could not create mosaic dump");
    for (unsigned y = 0; y < mosaic_height; ++y) {
        const size_t row = static_cast<size_t>(y + top_margin) * raw_width;
        for (unsigned x = 0; x < mosaic_width; ++x) {
            const size_t index = row + x + left_margin;
            writeU16LE(mosaic, raw_image[index]);
        }
    }
    mosaic.close();

    // rawpy postprocess calls ensure_unpack() before applying Params, so apply
    // the already-proven 0.27.1 field mapping only after the unpack above.
    m11raw::applyRawpy0271OracleParams(raw.imgdata.params, false);
    rc = raw.dcraw_process();
    if (rc != LIBRAW_SUCCESS) fail("dcraw_process: " + std::string(LibRaw::strerror(rc)));

    int mem_error = LIBRAW_SUCCESS;
    libraw_processed_image_t *image = raw.dcraw_make_mem_image(&mem_error);
    if (image == nullptr || mem_error != LIBRAW_SUCCESS)
        fail("dcraw_make_mem_image failed");
    if (image->type != LIBRAW_IMAGE_BITMAP) fail("processed output is not bitmap");
    if (image->bits != 16) fail("processed output is not 16-bit");
    if (image->colors < 1) fail("processed output has no channels");

    const size_t samples = static_cast<size_t>(image->width) * image->height * image->colors;
    if (image->data_size != samples * sizeof(std::uint16_t))
        fail("unexpected processed image byte count");

    std::ofstream ahd(out_dir / "ahd_u16le.bin", std::ios::binary);
    if (!ahd) fail("could not create AHD dump");
    const auto *pixels = reinterpret_cast<const std::uint16_t *>(image->data);
    for (size_t i = 0; i < samples; ++i) writeU16LE(ahd, pixels[i]);
    ahd.close();

    std::ofstream meta(out_dir / "metadata.txt");
    if (!meta) fail("could not create metadata dump");
    meta << "schema=m11camera.raw_pixel_parity.v1\n";
    meta << "producer=direct-libraw\n";
    meta << "librawVersion=" << LibRaw::version() << '\n';
    meta << "mosaicWidth=" << mosaic_width << '\n';
    meta << "mosaicHeight=" << mosaic_height << '\n';
    meta << "outputWidth=" << image->width << '\n';
    meta << "outputHeight=" << image->height << '\n';
    meta << "outputColors=" << image->colors << '\n';
    meta << "outputBits=" << image->bits << '\n';
    meta << "outputBytes=" << image->data_size << '\n';
    meta << "demosaic=AHD\n";
    meta << "decodeInvoked=true\n";
    meta << "m11RendererInvoked=false\n";
    meta.close();

    raw.dcraw_clear_mem(image);
    raw.recycle();

    std::cout << "pixel_parity_dump=true\n";
    return 0;
}
