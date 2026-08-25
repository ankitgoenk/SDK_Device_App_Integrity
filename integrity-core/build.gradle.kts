plugins {
    id("integrity.android.library.published")
}

android {
    namespace = "io.integrity.core"
}

dependencies {
    // api, not implementation: consumers import Signal, SignalId and the rest from here
    // and must keep seeing them. Same package, so nothing downstream changes.
    api(project(":integrity-model"))
    api(libs.androidx.annotation)
    api(libs.kotlinx.coroutines.core)

    testImplementation(libs.junit)
    testImplementation(libs.truth)
    testImplementation(libs.kotlinx.coroutines.test)
}
