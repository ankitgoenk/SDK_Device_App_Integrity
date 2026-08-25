/**
 * The evidence model and the scoring policy, with no Android in them.
 *
 * Split out of `integrity-core` so the backend can re-score a report with *the same code*
 * the client used. The alternative — a second implementation on the server — is two things
 * that must agree, which for a security decision is a way of eventually discovering that
 * they do not.
 *
 * The package stays `io.integrity.core` deliberately: nothing a consumer imports changes.
 */
plugins {
    id("integrity.kotlin.jvm.published")
}

dependencies {
    testImplementation(libs.junit)
    testImplementation(libs.truth)
}
