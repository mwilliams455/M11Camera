plugins {
    id("com.android.application")
}

android {
    namespace = "com.m11.diagnostic"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.m11.diagnostic"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0-apk1a-shell"

        testInstrumentationRunner = "android.test.InstrumentationTestRunner"
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
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}
