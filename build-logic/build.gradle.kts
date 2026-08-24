plugins {
    `kotlin-dsl`
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    // Needed on the classpath so the precompiled script plugins can apply them.
    implementation(libs.android.gradlePlugin)
    implementation(libs.kotlin.gradlePlugin)
}
