#include "m11_reference_renderer_core.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
constexpr double kEps = 3e-12;

class Reader {
 public:
  explicit Reader(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open parity fixture: " + path);
    bytes_ = std::vector<unsigned char>(std::istreambuf_iterator<char>(in), {});
  }

  std::array<unsigned char, 8> bytes8() {
    need(8);
    std::array<unsigned char, 8> out{};
    std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(pos_), 8, out.begin());
    pos_ += 8;
    return out;
  }

  std::uint8_t u8() {
    need(1);
    return bytes_[pos_++];
  }

  std::uint16_t u16() {
    need(2);
    const auto v = static_cast<std::uint16_t>(
        (std::uint16_t(bytes_[pos_]) << 8) | bytes_[pos_ + 1]);
    pos_ += 2;
    return v;
  }

  std::uint32_t u32() {
    need(4);
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v = (v << 8) | bytes_[pos_++];
    return v;
  }

  double f64() {
    need(8);
    std::uint64_t bits = 0;
    for (int i = 0; i < 8; ++i) bits = (bits << 8) | bytes_[pos_++];
    double v;
    static_assert(sizeof(v) == sizeof(bits));
    std::memcpy(&v, &bits, sizeof(v));
    return v;
  }

  m11::render::Vec3 vec3() { return {f64(), f64(), f64()}; }
  bool done() const { return pos_ == bytes_.size(); }

 private:
  void need(std::size_t n) const {
    if (pos_ + n > bytes_.size()) throw std::runtime_error("truncated parity fixture");
  }

  std::vector<unsigned char> bytes_;
  std::size_t pos_ = 0;
};

m11::render::Tables syntheticTables() {
  using namespace m11::render;
  Tables t;
  const std::array<int, 9> cc0 = {495, -58, 63, 10, 601, -111, 49, -255, 705};
  const std::array<int, 9> cc1 = {1041, -372, -157, -117, 630, -1, -4, -78, 595};
  for (std::size_t i = 0; i < 9; ++i) {
    t.cc0[i] = cc0[i] / 512.0;
    t.cc1[i] = cc1[i] / 512.0;
  }

  t.tone_x.resize(17);
  for (int i = 0; i < 17; ++i) t.tone_x[i] = i / 16.0;
  for (int contrast = -3; contrast <= 3; ++contrast) {
    auto& curve = t.tone_curves[static_cast<std::size_t>(contrast + 3)];
    curve.resize(17);
    const double exponent = 1.0 - 0.055 * contrast;
    const double scale = 1.0 + 0.025 * contrast;
    for (int i = 0; i < 17; ++i) {
      curve[i] = std::max(0.0, std::min(1.25, std::pow(t.tone_x[i], exponent) * scale));
    }
  }

  t.gamma_x.resize(33);
  t.gamma_y.resize(33);
  for (int i = 0; i < 33; ++i) {
    t.gamma_x[i] = i / 32.0;
    t.gamma_y[i] = std::pow(t.gamma_x[i], 1.0 / 2.15);
  }
  return t;
}

void close(double expected, double actual, const std::string& label, int case_index) {
  if (!(std::abs(expected - actual) <= kEps)) {
    throw std::runtime_error(
        "case " + std::to_string(case_index) + " " + label +
        " expected=" + std::to_string(expected) + " actual=" + std::to_string(actual));
  }
}

void close3(const m11::render::Vec3& expected, const m11::render::Vec3& actual,
            const std::string& label, int case_index) {
  for (int i = 0; i < 3; ++i) {
    close(expected[i], actual[i], label + "[" + std::to_string(i) + "]", case_index);
  }
}
}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc != 2) throw std::runtime_error("usage: m11_reference_renderer_parity_test FIXTURE.bin");
    Reader in(argv[1]);
    const auto magic = in.bytes8();
    const std::array<unsigned char, 8> expected_magic = {'M', '1', '1', 'P', 'A', 'R', '1', 'A'};
    if (magic != expected_magic) throw std::runtime_error("bad parity fixture magic");
    if (in.u32() != 1) throw std::runtime_error("bad parity fixture version");
    const auto count = in.u32();
    if (count != 147) throw std::runtime_error("unexpected case count");

    const auto tables = syntheticTables();
    for (std::uint32_t ci = 0; ci < count; ++ci) {
      const auto mode_id = in.u8();
      const auto flags = in.u8();
      if (in.u16() != 0) throw std::runtime_error("nonzero reserved field");
      if (mode_id > 2) throw std::runtime_error("invalid mode id");

      m11::render::RenderConfig cfg;
      cfg.mode = static_cast<m11::render::Mode>(mode_id);
      cfg.use_cc0 = flags & 1;
      cfg.use_tone = flags & 2;
      cfg.use_cc1 = flags & 4;
      cfg.use_gamma = flags & 8;
      cfg.use_chroma = flags & 16;
      cfg.clamp = flags & 32;

      const auto input = in.vec3();
      const auto expected_cc0 = in.vec3();
      const double expected_y = in.f64();
      const double expected_y2 = in.f64();
      const double expected_scale = in.f64();
      const auto expected_tone = in.vec3();
      const auto expected_cc1 = in.vec3();
      const bool expected_has_ycc = in.u32() != 0;
      const auto expected_ycc_before = in.vec3();
      const auto expected_ycc_after = in.vec3();
      const auto expected_output = in.vec3();

      const auto actual = m11::render::renderPixelTrace(input, tables, cfg);
      close3(expected_cc0, actual.after_cc0, "afterCc0", ci);
      close(expected_y, actual.tone_luma_input, "toneY", ci);
      close(expected_y2, actual.tone_luma_output, "toneY2", ci);
      close(expected_scale, actual.tone_scale, "toneScale", ci);
      close3(expected_tone, actual.after_tone, "afterTone", ci);
      close3(expected_cc1, actual.after_cc1, "afterCc1", ci);
      if (expected_has_ycc != actual.has_ycc) throw std::runtime_error("hasYcc mismatch");
      if (expected_has_ycc) {
        close3(expected_ycc_before, actual.ycc_before, "yccBefore", ci);
        close3(expected_ycc_after, actual.ycc_after, "yccAfter", ci);
      }
      close3(expected_output, actual.output, "output", ci);
    }

    if (!in.done()) throw std::runtime_error("unexpected fixture trailer");
    std::cout << "native_renderer_parity=true cases=147 eps=" << kEps
              << " third_sro_applied=false\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "FAIL: " << e.what() << "\n";
    return 1;
  }
}
