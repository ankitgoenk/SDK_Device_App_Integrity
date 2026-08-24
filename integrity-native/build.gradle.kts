plugins {
    id("integrity.android.library")
}

android {
    namespace = "io.integrity.nativecore"

    defaultConfig {
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
        externalNativeBuild {
            cmake {
                // Hide everything, strip everything: no greppable Java_io_integrity_* symbols.
                cppFlags += listOf("-std=c++17", "-fvisibility=hidden", "-ffunction-sections", "-fdata-sections")
                arguments += listOf("-DANDROID_STL=c++_static")
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
}

dependencies {
    api(project(":integrity-core"))
}
