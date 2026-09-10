cmake_minimum_required(VERSION 3.22)
project(m11_apk1a_native LANGUAGES C CXX)

if(NOT DEFINED M11_LIBRAW_PATH OR M11_LIBRAW_PATH STREQUAL "" OR NOT EXISTS "${M11_LIBRAW_PATH}/libraw/libraw.h")
    message(FATAL_ERROR "M11_LIBRAW_PATH must point to pinned LibRaw 0.22.1 source")
endif()
if(NOT DEFINED M11_LIBRAW_CMAKE_PATH OR M11_LIBRAW_CMAKE_PATH STREQUAL "" OR NOT EXISTS "${M11_LIBRAW_CMAKE_PATH}/CMakeLists.txt")
    message(FATAL_ERROR "M11_LIBRAW_CMAKE_PATH must point to the pinned LibRaw-cmake wrapper")
endif()

set(LIBRAW_PATH "${M11_LIBRAW_PATH}" CACHE STRING "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(ENABLE_OPENMP OFF CACHE BOOL "" FORCE)
set(ENABLE_LCMS OFF CACHE BOOL "" FORCE)
set(ENABLE_JASPER OFF CACHE BOOL "" FORCE)
set(ENABLE_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ENABLE_RAWSPEED OFF CACHE BOOL "" FORCE)
set(ENABLE_DCRAW_DEBUG OFF CACHE BOOL "" FORCE)
set(ENABLE_X3FTOOLS OFF CACHE BOOL "" FORCE)
set(ENABLE_6BY9RPI OFF CACHE BOOL "" FORCE)
set(LIBRAW_INSTALL OFF CACHE BOOL "" FORCE)
set(LIBRAW_UNINSTALL_TARGET OFF CACHE BOOL "" FORCE)

add_subdirectory("${M11_LIBRAW_CMAKE_PATH}" "${CMAKE_BINARY_DIR}/libraw")
find_library(M11_Z_LIB z REQUIRED)
find_library(M11_JNIGRAPHICS_LIB jnigraphics REQUIRED)

# The original identify, synthetic parity, REALRAW probe and REALRAW1C export
# paths retain their existing boundaries.  RENDER1A is a new explicitly gated
# translation unit: it may unpack/AHD only after the same narrow real-Xiaomi
# decoder identity gate and may invoke the frozen M11 renderer only with tables
# already accepted by the Java canonical-asset loader.
add_library(m11rawjni SHARED
    m11_raw_jni.cpp
    m11_raw_selftest_jni.cpp
    m11_realraw_probe_jni.cpp
    m11_realraw_export_jni.cpp
    m11_render_jni.cpp
)
target_compile_features(m11rawjni PRIVATE cxx_std_17)
target_compile_options(m11rawjni PRIVATE -fvisibility=hidden)
target_include_directories(m11rawjni PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/../../../../native/libraw_probe"
    "${CMAKE_CURRENT_LIST_DIR}/../../../../native/m11_renderer"
)
target_link_libraries(m11rawjni PRIVATE
    libraw::libraw
    ${M11_Z_LIB}
    ${M11_JNIGRAPHICS_LIB}
)
