plugins {
    id("integrity.android.application")
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "io.integrity.sample"

    buildFeatures {
        compose = true
    }
}

dependencies {
    implementation(project(":integrity-core"))
    implementation(project(":integrity-detector-root"))
    implementation(project(":integrity-detector-hooking"))
    implementation(project(":integrity-detector-app"))
    implementation(project(":integrity-detector-environment"))
    implementation(project(":integrity-detector-emulator"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.kotlinx.coroutines.android)

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    debugImplementation(libs.compose.ui.tooling)
    implementation(libs.compose.ui.tooling.preview)

    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.junit)
    androidTestImplementation(libs.androidx.test.runner)
}
