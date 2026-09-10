#include "m11_source_pipeline_core.h"

#include <cmath>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
void near(double expected, double actual, double eps, const char* label) {
  if (std::abs(expected - actual) > eps) {
    throw std::runtime_error(std::string(label) + " mismatch");
  }
}

void near9(const m11::render::Mat3& expected, const m11::render::Mat3& actual,
           double eps, const char* label) {
  for (int i = 0; i < 9; ++i) near(expected[i], actual[i], eps, label);
}
}  // namespace

int main() {
  try {
    using namespace m11;
    const render::Mat3 cm1 = {
        .8359375, -.171875, -.1328125,
        -.46875, 1.3984375, .046875,
        -.0859375, .3359375, .40625};
    const render::Mat3 cm2 = {
        1.28125, -.484375, -.2265625,
        -.5859375, 1.59375, .140625,
        -.046875, .1796875, .703125};
    const render::Mat3 cal = {
        1.03125, 0, 0,
        0, 1, 0,
        0, 0, 1.015625};
    const render::Mat3 fm = {
        .6328125, .109375, .21875,
        .21875, .7578125, .0234375,
        -.0390625, -.453125, 1.3203125};

    // Existing Java SOURCECAL2A regression fixture.
    const render::Vec3 old_neutral = {.32421875, 1.0, .62109375};
    const auto old = source::buildDualIlluminantTransform(
        21, 17, cal, cal, cm1, cm2, fm, fm, old_neutral);
    near(.00006103515625, old.interpolation_factor, 0.0, "old factor");
    const render::Mat3 old_expected = {
        1.9584339, .10974634, .3533970,
        .6746988, .7578125, .03773585,
        -.12001274, -.45136034, 2.1175075};
    near9(old_expected, old.camera_to_xyz_d50, 1e-6, "old sourcecal2a");

    // Provisional reference-basis reconstruction must stay replaceable and must
    // continue to match the recorded genuine-M11 regression matrix.
    const auto basis = source::xyzD50ToM11AReferenceWb();
    const render::Mat3 recorded_basis = {
        1.31879337, -.14831682, -.14939568,
        -.51395518, 1.34347843, .18430135,
        -.27544169, .50342179, .92362240};
    near9(recorded_basis, basis, 1e-8, "M11 basis");

    // Metadata-only fixture from the current real Xiaomi 15 Ultra DNG used for
    // RENDER1A. No user image bytes are stored in this test.
    const render::Vec3 current_neutral = {557.0 / 1024.0, 1.0, 440.0 / 1024.0};
    const auto current = source::buildDualIlluminantTransform(
        21, 17, cal, cal, cm1, cm2, fm, fm, current_neutral);
    near(0.44814293727680954, current.interpolation_factor, 1e-12, "current factor");
    const render::Mat3 current_xyz = {
        1.16732502517844, .10974634146341, .51081933481153,
        .40215439856373, .7578125, .05454545454545,
        -.07153362013482, -.45136037735849, 3.06076102915952};
    near9(current_xyz, current.camera_to_xyz_d50, 1e-12, "current cameraToXYZ");

    const render::Mat3 current_m11 = {
        1.49050105530601, .09976769856798, .20831066628829,
        -.07285072197443, .87851372237539, .37484478772108,
        -.18514674263673, -.06561594705348, 2.71374589104543};
    near9(current_m11, source::cameraToM11Reference(current), 2e-12, "current cameraToM11");

    std::cout << "native_source_pipeline_parity=true current_fixture_factor="
              << current.interpolation_factor
              << " reference_basis_status=strong_inference third_sro_applied=false\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "FAIL: " << e.what() << "\n";
    return 1;
  }
}
