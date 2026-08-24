import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    compileSdk = IntegrityBuild.COMPILE_SDK

    defaultConfig {
        minSdk = IntegrityBuild.MIN_SDK
        targetSdk = IntegrityBuild.TARGET_SDK
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = IntegrityBuild.TEST_RUNNER
    }

    compileOptions {
        sourceCompatibility = IntegrityBuild.JAVA_VERSION
        targetCompatibility = IntegrityBuild.JAVA_VERSION
    }

    buildTypes {
        release {
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
