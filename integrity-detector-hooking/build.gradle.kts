plugins {
    id("integrity.android.library")
}

android {
    namespace = "io.integrity.detector.hooking"
}

dependencies {
    api(project(":integrity-core"))

    testImplementation(libs.junit)
    testImplementation(libs.truth)
    testImplementation(project(":integrity-testing"))
}
