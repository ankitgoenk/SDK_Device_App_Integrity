plugins {
    id("integrity.android.library.published")
}

android {
    namespace = "io.integrity.nativecore"

    defaultConfig {
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
        externalNativeBuild {
            cmake {
                // The token the library identifies itself by. A .so from another build of
                // the SDK reports a different one, which is what makes a swapped library
                // detectable without a digest baseline (that arrives in phase 4).
                //
                // Passed as a cache variable rather than by overriding CMAKE_CXX_FLAGS,
                // which AGP also populates. c++_static because the boundary catches C++
                // exceptions; ANDROID_STL=none cannot support that.
                arguments += listOf(
                    "-DINTEGRITY_TOKEN=${IntegrityBuild.VERSION}",
                    "-DANDROID_STL=c++_static"
                )
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    ndkVersion = IntegrityBuild.NDK_VERSION
}

dependencies {
    api(project(":integrity-core"))

    testImplementation(libs.junit)
    testImplementation(libs.truth)
    testImplementation(libs.kotlinx.coroutines.test)

    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.junit)
    androidTestImplementation(libs.androidx.test.runner)
}
