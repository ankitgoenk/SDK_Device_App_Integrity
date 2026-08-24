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
    androidTestImplementation(libs.androidx.test.junit)
    androidTestImplementation(libs.androidx.test.runner)
}
