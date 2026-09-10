#include <jni.h>

#include <exception>
#include <string>

#include "m11_open_identify_core.h"

namespace {

jstring toJavaString(JNIEnv *env, const std::string &value) {
    return env->NewStringUTF(value.c_str());
}

} // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_m11_diagnostic_M11NativeRawBridge_nativeIdentifyFd(
        JNIEnv *env, jclass /*clazz*/, jint fd) {
    try {
        m11raw::IdentifyResult result = m11raw::identifyFdOnly(static_cast<int>(fd));
        std::string evidence = "nativeAvailable=true\n" + m11raw::serializeIdentifyEvidence(result);
        return toJavaString(env, evidence);
    } catch (const std::exception &e) {
        std::string failure =
                "schema=m11camera.libraw_identify.v1\n"
                "nativeAvailable=true\n"
                "nativeException=" + std::string(e.what()) + "\n"
                "decodeInvoked=false\n";
        return toJavaString(env, failure);
    } catch (...) {
        return toJavaString(env,
                "schema=m11camera.libraw_identify.v1\n"
                "nativeAvailable=true\n"
                "nativeException=unknown\n"
                "decodeInvoked=false\n");
    }
}
