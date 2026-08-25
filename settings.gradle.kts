pluginManagement {
    includeBuild("build-logic")
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "device-app-integrity"

// --- SDK ---------------------------------------------------------------
include(":integrity-model")
include(":integrity-core")
include(":integrity-detector-root")
include(":integrity-detector-hooking")
include(":integrity-detector-app")
include(":integrity-detector-environment")
include(":integrity-detector-emulator")
include(":integrity-testing")

// --- Tooling -----------------------------------------------------------
include(":integrity-baseline-plugin")

// --- Samples -----------------------------------------------------------
include(":sample-app")
include(":sample-backend")

// The native module needs the NDK, which is not required to build anything else.
// Phase 3 turns this on (and adds the NDK to CI). See docs/PLAN.md.
if (providers.gradleProperty("integrity.enableNative").orNull.toBoolean()) {
    include(":integrity-native")
}
