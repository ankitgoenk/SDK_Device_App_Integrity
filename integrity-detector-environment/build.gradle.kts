plugins {
    id("integrity.android.library.published")
}

android {
    namespace = "io.integrity.detector.environment"
}

dependencies {
    api(project(":integrity-core"))

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.truth)
    testImplementation(project(":integrity-testing"))
}
