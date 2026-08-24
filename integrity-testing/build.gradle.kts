plugins {
    id("integrity.android.library")
}

android {
    namespace = "io.integrity.testing"
}

dependencies {
    api(project(":integrity-core"))
    implementation(libs.kotlinx.coroutines.core)
}
