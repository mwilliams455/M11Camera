plugins {
    id("com.android.application")
}

val m11LibRawPath = System.getenv("M11_LIBRAW_PATH")
    ?: rootProject.file("work/LibRaw").absolutePath
val m11LibRawCmakePath = System.getenv("M11_LIBRAW_CMAKE_PATH")
    ?: rootProject.file("work/LibRaw-cmake").absolutePath

android {
    namespace = "com.m11.diagnostic"
    compileSdk = 36
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "com.m11.diagnostic"
        minSdk = 26
        targetSdk = 36
        versionCode = 2
        versionName = "0.1.1-apk1a-realraw1a"

        testInstrumentationRunner = "android.test.InstrumentationTestRunner"

        ndk {
            abiFilters += listOf("arm64-v8a")
        }

        externalNativeBuild {
            cmake {
                arguments += listOf(
                    "-DM11_LIBRAW_PATH=$m11LibRawPath",
                    "-DM11_LIBRAW_CMAKE_PATH=$m11LibRawCmakePath",
                    "-DANDROID_STL=c++_static"
                )
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}
