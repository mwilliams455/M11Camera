#pragma once

#include "m11_reference_renderer_core.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <stdexcept>

namespace m11::source {
using m11::render::Mat3;
using m11::render::Vec3;

inline constexpr Vec3 kD50Xyz = {0.9642, 1.0, 0.8249};
inline constexpr Mat3 kM11ColorMatrixA = {
    0.57568359375, -0.13330078125, -0.01611328125,
    -0.607421875, 1.5380859375, 0.435791015625,
    -0.098388671875, 0.194580078125, 0.85546875};
inline constexpr Mat3 kBradford = {
    0.8951, 0.2664, -0.1614,
    -0.7502, 1.7135, 0.0367,
    0.0389, -0.0685, 1.0296};

struct SourceResult {
  Mat3 camera_to_xyz_d50{};
  double interpolation_factor = 0.0;
  Vec3 reference_neutral{};
};

inline Mat3 multiply3x3(const Mat3& a, const Mat3& b) {
  Mat3 out{};
  for (int r = 0; r < 3; ++r) {
    for (int c = 0; c < 3; ++c) {
      out[r * 3 + c] = a[r * 3] * b[c] + a[r * 3 + 1] * b[3 + c] + a[r * 3 + 2] * b[6 + c];
    }
  }
  return out;
}

inline Mat3 lerp(const Mat3& a, const Mat3& b, double f) {
  Mat3 out{};
  for (int i = 0; i < 9; ++i) out[i] = a[i] * (1.0 - f) + b[i] * f;
  return out;
}

inline double illuminantKelvin(int value) {
  switch (value) {
    case 1: return 6504; case 2: return 4230; case 3: return 2856; case 4: return 5500;
    case 9: return 5500; case 10: return 6500; case 11: return 7500; case 12: return 6430;
    case 13: return 5000; case 14: return 4230; case 15: return 3450; case 17: return 2856;
    case 18: return 4874; case 19: return 6774; case 20: return 5503; case 21: return 6504;
    case 22: return 7504; case 23: return 5003; case 24: return 3200;
    default: throw std::invalid_argument("unsupported DNG reference illuminant");
  }
}

inline Vec3 cieXyFromXyz(const Vec3& xyz) {
  const double total = xyz[0] + xyz[1] + xyz[2];
  if (total <= 1e-9) return {0.3127, 0.3290, 0.0};
  return {xyz[0] / total, xyz[1] / total, 0.0};
}

inline double mccamyCct(double x, double y) {
  double denom = y - 0.1858;
  if (std::abs(denom) < 1e-9) denom = denom < 0 ? -1e-9 : 1e-9;
  const double n = (x - 0.332) / denom;
  return -449.0 * n * n * n + 3525.0 * n * n - 6823.3 * n + 5520.33;
}

inline Mat3 normalizeForwardMatrix(const Mat3& fm) {
  const Vec3 xyz = m11::render::multiply(fm, {1.0, 1.0, 1.0});
  Mat3 out = fm;
  for (int row = 0; row < 3; ++row) {
    if (!std::isfinite(xyz[row]) || std::abs(xyz[row]) < 1e-12) throw std::invalid_argument("forward matrix cannot be normalized");
    const double scale = kD50Xyz[row] / xyz[row];
    for (int col = 0; col < 3; ++col) out[row * 3 + col] *= scale;
  }
  return out;
}

inline double findInterpolationFactor(int illum1, int illum2, const Mat3& cal1, const Mat3& cal2,
                                      const Mat3& cm1, const Mat3& cm2, const Vec3& neutral) {
  const double t1 = illuminantKelvin(illum1), t2 = illuminantKelvin(illum2);
  const Mat3 xyz_to_cam1 = multiply3x3(cal1, cm1), xyz_to_cam2 = multiply3x3(cal2, cm2);
  const double lower = std::min(t1, t2), upper = std::max(t1, t2);
  double factor = 0.5, old_factor = factor;
  for (int iteration = 0; iteration < 30; ++iteration) {
    const Mat3 xyz_to_cam = lerp(xyz_to_cam1, xyz_to_cam2, factor);
    const Vec3 neutral_xyz = m11::render::multiply(m11::render::inverse3(xyz_to_cam), neutral);
    const Vec3 xy = cieXyFromXyz(neutral_xyz);
    const double temperature = mccamyCct(xy[0], xy[1]);
    double next;
    if (temperature <= lower) next = 1.0;
    else if (temperature >= upper) next = 0.0;
    else next = (1.0 / temperature - 1.0 / upper) / (1.0 / lower - 1.0 / upper);
    if (lower == t1) next = 1.0 - next;
    factor = 0.5 * (next + old_factor);
    const double diff = std::abs(old_factor - factor);
    old_factor = factor;
    if (diff <= 1e-4) break;
  }
  return factor;
}

inline SourceResult buildDualIlluminantTransform(int illum1, int illum2, const Mat3& cal1, const Mat3& cal2,
                                                 const Mat3& cm1, const Mat3& cm2, const Mat3& fm1,
                                                 const Mat3& fm2, const Vec3& neutral) {
  const double factor = findInterpolationFactor(illum1, illum2, cal1, cal2, cm1, cm2, neutral);
  const Mat3 cal = lerp(cal1, cal2, factor);
  const Mat3 inv_cal = m11::render::inverse3(cal);
  Vec3 ref_neutral = m11::render::multiply(inv_cal, neutral);
  double max_neutral = -1e300;
  for (double& v : ref_neutral) {
    v = std::max(v, 1e-6);
    max_neutral = std::max(max_neutral, v);
  }
  Mat3 wb = {max_neutral / ref_neutral[0], 0, 0,
             0, max_neutral / ref_neutral[1], 0,
             0, 0, max_neutral / ref_neutral[2]};
  const Mat3 fm = lerp(normalizeForwardMatrix(fm1), normalizeForwardMatrix(fm2), factor);
  return {multiply3x3(multiply3x3(fm, wb), inv_cal), factor, ref_neutral};
}

inline Vec3 xyToXyz(double x, double y) { return {x / y, 1.0, (1.0 - x - y) / y}; }

inline Mat3 bradfordMap(double x1, double y1, double x2, double y2) {
  const Vec3 w1 = m11::render::multiply(kBradford, xyToXyz(x1, y1));
  const Vec3 w2 = m11::render::multiply(kBradford, xyToXyz(x2, y2));
  Mat3 diagonal{};
  for (int k = 0; k < 3; ++k) {
    const double r = w1[k] > 0.0 ? w2[k] / w1[k] : 10.0;
    diagonal[k * 3 + k] = std::max(0.1, std::min(10.0, r));
  }
  return multiply3x3(multiply3x3(m11::render::inverse3(kBradford), diagonal), kBradford);
}

inline Mat3 xyzD50ToM11AReferenceWb() {
  constexpr double d50_x = 0.34567, d50_y = 0.35850, a_x = 0.44757, a_y = 0.40745;
  Mat3 pcs_to_camera = multiply3x3(kM11ColorMatrixA, bradfordMap(d50_x, d50_y, a_x, a_y));
  const Vec3 saturation_probe = m11::render::multiply(pcs_to_camera, xyToXyz(d50_x, d50_y));
  const double scale = std::max({saturation_probe[0], saturation_probe[1], saturation_probe[2]});
  for (double& v : pcs_to_camera) v /= scale;
  const Mat3 camera_to_pcs = m11::render::inverse3(pcs_to_camera);
  Vec3 camera_white = m11::render::multiply(kM11ColorMatrixA, xyToXyz(a_x, a_y));
  const double white_max = std::max({camera_white[0], camera_white[1], camera_white[2]});
  Mat3 white{};
  for (int k = 0; k < 3; ++k) {
    white[k * 3 + k] = std::max(0.001, std::min(1.0, camera_white[k] / white_max));
  }
  return m11::render::inverse3(multiply3x3(camera_to_pcs, white));
}

inline Mat3 cameraToM11Reference(const SourceResult& source) {
  return multiply3x3(xyzD50ToM11AReferenceWb(), source.camera_to_xyz_d50);
}

}  // namespace m11::source
