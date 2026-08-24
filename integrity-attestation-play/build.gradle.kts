plugins {
    id("integrity.android.library")
}

android {
    namespace = "io.integrity.attestation.play"
}

dependencies {
    api(project(":integrity-core"))
    // Phase 7 adds com.google.android.play:integrity. Kept out of the scaffold so the
    // module builds and so hosts without Play Services are never forced to carry it.
}
