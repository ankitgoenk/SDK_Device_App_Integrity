plugins {
    id("integrity.android.library")
}

android {
    namespace = "io.integrity.core"
}

dependencies {
    api(libs.androidx.annotation)
    api(libs.kotlinx.coroutines.core)

    testImplementation(libs.junit)
    testImplementation(libs.truth)
    testImplementation(libs.kotlinx.coroutines.test)
}
