#pragma once

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <stdexcept>
#include <vector>

namespace m11::render {

using Vec3 = std::array<double, 3>;
using Mat3 = std::array<double, 9>;

inline constexpr Mat3 kYccMatrix = {
    77.0 / 256.0, 150.0 / 256.0, 29.0 / 256.0,
    -43.0 / 256.0, -85.0 / 256.0, 128.0 / 256.0,
    128.0 / 256.0, -107.0 / 256.0, -21.0 / 256.0};
inline constexpr Vec3 kToneLuma = {77.0 / 255.0, 149.0 / 255.0, 29.0 / 255.0};

enum class Mode : unsigned char { Natural = 0, Standard = 1, Vivid = 2 };

struct ModeConfig {
  int contrast_state;
  double chroma_scale;
};

inline ModeConfig modeConfig(Mode mode) {
  switch (mode) {
    case Mode::Natural: return {-1, 1.00};
    case Mode::Standard: return {0, 1.15};
    case Mode::Vivid: return {1, 1.30};
  }
  throw std::invalid_argument("invalid M11 mode");
}

struct Tables {
  Mat3 cc0{};
  Mat3 cc1{};
  std::vector<double> tone_x;
  std::array<std::vector<double>, 7> tone_curves;
  std::vector<double> gamma_x;
  std::vector<double> gamma_y;
};

struct RenderConfig {
  Mode mode = Mode::Standard;
  bool use_cc0 = true;
  bool use_tone = true;
  bool use_cc1 = true;
  bool use_gamma = true;
  bool use_chroma = true;
  bool clamp = true;
};

struct StageTrace {
  Vec3 input{};
  Vec3 after_cc0{};
  double tone_luma_input = 0.0;
  double tone_luma_output = 0.0;
  double tone_scale = 1.0;
  Vec3 after_tone{};
  Vec3 after_cc1{};
  bool has_ycc = false;
  Vec3 ycc_before{};
  Vec3 ycc_after{};
  Vec3 output{};
};

inline void requireFinite(const Vec3& v) {
  for (double x : v) {
    if (!std::isfinite(x)) throw std::invalid_argument("non-finite M11 pixel value");
  }
}

inline Vec3 multiply(const Mat3& m, const Vec3& v) {
  return {
      m[0] * v[0] + m[1] * v[1] + m[2] * v[2],
      m[3] * v[0] + m[4] * v[1] + m[5] * v[2],
      m[6] * v[0] + m[7] * v[1] + m[8] * v[2]};
}

inline double dot(const Vec3& a, const Vec3& b) {
  return a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
}

inline Mat3 inverse3(const Mat3& m) {
  const double a=m[0], b=m[1], c=m[2], d=m[3], e=m[4], f=m[5], g=m[6], h=m[7], i=m[8];
  const double A=e*i-f*h, B=-(d*i-f*g), C=d*h-e*g;
  const double D=-(b*i-c*h), E=a*i-c*g, F=-(a*h-b*g);
  const double G=b*f-c*e, H=-(a*f-c*d), I=a*e-b*d;
  const double det = a*A + b*B + c*C;
  if (!std::isfinite(det) || std::abs(det) < 1e-15) throw std::invalid_argument("singular M11 matrix");
  const double s = 1.0 / det;
  return {A*s, D*s, G*s, B*s, E*s, H*s, C*s, F*s, I*s};
}

inline const Mat3& yccInverse() {
  static const Mat3 inverse = inverse3(kYccMatrix);
  return inverse;
}

inline double clamp01(double x) {
  return std::max(0.0, std::min(1.0, x));
}

inline double interpolate(double x, const std::vector<double>& axis, const std::vector<double>& values) {
  if (axis.size() != values.size() || axis.size() < 2) throw std::invalid_argument("invalid M11 interpolation table");
  if (x <= axis.front()) return values.front();
  if (x >= axis.back()) return values.back();
  std::size_t lo = 0;
  std::size_t hi = axis.size() - 1;
  while (hi - lo > 1) {
    const std::size_t mid = (lo + hi) >> 1;
    if (axis[mid] <= x) lo = mid;
    else hi = mid;
  }
  const double span = axis[hi] - axis[lo];
  if (!(span > 0.0)) throw std::invalid_argument("M11 interpolation axis not strictly increasing");
  const double f = (x - axis[lo]) / span;
  return values[lo] * (1.0 - f) + values[hi] * f;
}

inline void validateTables(const Tables& t) {
  if (t.tone_x.size() < 2 || t.gamma_x.size() < 2 || t.gamma_x.size() != t.gamma_y.size()) {
    throw std::invalid_argument("invalid M11 table dimensions");
  }
  for (const auto& curve : t.tone_curves) {
    if (curve.size() != t.tone_x.size()) throw std::invalid_argument("M11 tone curve size mismatch");
  }
}

inline StageTrace renderPixelTrace(const Vec3& rgb, const Tables& tables, const RenderConfig& cfg) {
  validateTables(tables);
  requireFinite(rgb);
  StageTrace tr{};
  tr.input = rgb;
  Vec3 out = rgb;

  if (cfg.use_cc0) out = multiply(tables.cc0, out);
  tr.after_cc0 = out;

  const ModeConfig mc = modeConfig(cfg.mode);
  const int curve_index = mc.contrast_state + 3;
  tr.tone_luma_input = dot(out, kToneLuma);
  tr.tone_luma_output = tr.tone_luma_input;
  tr.tone_scale = 1.0;
  if (cfg.use_tone) {
    const double lookup = clamp01(tr.tone_luma_input);
    tr.tone_luma_output = interpolate(lookup, tables.tone_x, tables.tone_curves.at(static_cast<std::size_t>(curve_index)));
    if (tr.tone_luma_input > 1e-10) {
      tr.tone_scale = tr.tone_luma_output / std::max(tr.tone_luma_input, 1e-10);
      for (double& x : out) x *= tr.tone_scale;
    }
  }
  tr.after_tone = out;

  if (cfg.use_cc1) out = multiply(tables.cc1, out);
  tr.after_cc1 = out;

  tr.has_ycc = cfg.use_gamma || cfg.use_chroma;
  if (tr.has_ycc) {
    Vec3 ycc = multiply(kYccMatrix, out);
    tr.ycc_before = ycc;
    if (cfg.use_gamma) ycc[0] = interpolate(clamp01(ycc[0]), tables.gamma_x, tables.gamma_y);
    if (cfg.use_chroma) {
      ycc[1] *= mc.chroma_scale;
      ycc[2] *= mc.chroma_scale;
    }
    tr.ycc_after = ycc;
    out = multiply(yccInverse(), ycc);
  }

  if (cfg.clamp) for (double& x : out) x = clamp01(x);
  requireFinite(out);
  tr.output = out;
  return tr;
}

inline Vec3 renderPixel(const Vec3& rgb, const Tables& tables, const RenderConfig& cfg) {
  return renderPixelTrace(rgb, tables, cfg).output;
}

}  // namespace m11::render
