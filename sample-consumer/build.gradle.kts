import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("com.android.application") version "8.9.1"
    id("org.jetbrains.kotlin.android") version "2.1.20"
}

// Must match IntegrityBuild.VERSION in build-logic.
val sdkVersion = "0.1.0-alpha01"

android {
    namespace = "io.integrity.consumer"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.integrity.consumer"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        release {
            // Minification on purpose: this is what proves the AAR's consumer ProGuard
            // rules actually keep what the SDK needs. Without it the release build is
            // not testing anything the debug build does not.
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}

tasks.withType<KotlinCompile>().configureEach {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    // Real AAR coordinates, resolved from ../build/local-maven — never project(...).
    implementation("io.integrity.sdk:integrity-core:$sdkVersion")
    implementation("io.integrity.sdk:integrity-detector-environment:$sdkVersion")
    implementation("io.integrity.sdk:integrity-detector-root:$sdkVersion")
    implementation("io.integrity.sdk:integrity-native:$sdkVersion")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.1")

    androidTestImplementation("androidx.test:core:1.6.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
