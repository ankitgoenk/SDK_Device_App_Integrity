plugins {
    id("integrity.kotlin.jvm")
}

dependencies {
    // The same scorer the client ran. ADR-0006: the backend recomputes rather than
    // trusting clientAdvisory, and recomputing with a second implementation would only
    // move the trust problem into a diff between two codebases.
    implementation(project(":integrity-model"))

    testImplementation(libs.junit)
    testImplementation(libs.truth)
}
