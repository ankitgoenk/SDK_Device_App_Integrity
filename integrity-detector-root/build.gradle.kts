plugins {
    id("integrity.android.library")
}

android {
    namespace = "io.integrity.detector.root"
}

dependencies {
    api(project(":integrity-core"))

    testImplementation(libs.junit)
    testImplementation(libs.truth)
    testImplementation(project(":integrity-testing"))
}
