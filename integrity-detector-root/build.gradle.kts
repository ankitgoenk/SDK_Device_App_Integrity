plugins {
    id("integrity.android.library.published")
}

android {
    namespace = "io.integrity.detector.root"
}

dependencies {
    api(project(":integrity-core"))

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.truth)
    testImplementation(project(":integrity-testing"))

    androidTestImplementation(libs.androidx.test.core)
    // The clean-image baseline covers hook detectors too: the false positive that made
    // this necessary was in HOOK_UNEXPECTED_MODULE, and a root-only baseline could not see it.
    androidTestImplementation(project(":integrity-detector-hooking"))
    androidTestImplementation(libs.androidx.test.junit)
    androidTestImplementation(libs.androidx.test.runner)
}
