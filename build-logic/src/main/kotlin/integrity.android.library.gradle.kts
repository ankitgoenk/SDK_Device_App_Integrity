import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    compileSdk = IntegrityBuild.COMPILE_SDK

    defaultConfig {
        minSdk = IntegrityBuild.MIN_SDK
        testInstrumentationRunner = IntegrityBuild.TEST_RUNNER
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = IntegrityBuild.JAVA_VERSION
        targetCompatibility = IntegrityBuild.JAVA_VERSION
    }

    buildTypes {
        release {
            isMinifyEnabled = false // consumers minify; the AAR ships consumer rules
        }
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            isReturnDefaultValues = true
        }
    }

    lint {
        warningsAsErrors = true
        abortOnError = true
        checkDependencies = true
    }
}

kotlin {
    // Public API of an SDK must be deliberate: explicit visibility and return types.
    explicitApi()
}

tasks.withType<KotlinCompile>().configureEach {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        allWarningsAsErrors.set(true)
        freeCompilerArgs.add("-Xjvm-default=all")
    }
}
