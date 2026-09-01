// Test fixture, not shipped. Builds the positive control for ROOT_PROP_SPOOF's
// Build-versus-property check: an Xposed module that rewrites android.os.Build
// fields for one scoped app while leaving the backing properties untouched —
// exactly what Play Integrity Fork does to GMS.
plugins {
    id("integrity.android.application")
}

android {
    namespace = "io.integrity.fixture.buildspoof"
    defaultConfig { applicationId = "io.integrity.fixture.buildspoof" }
}

dependencies {
    // compileOnly is load-bearing: packaging these classes makes the framework refuse the
    // module outright. Verified by the failure this fixture was written to avoid.
    compileOnly(project(":tools:xposed-api-stubs"))
}
