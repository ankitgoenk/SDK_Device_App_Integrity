plugins {
    `java-gradle-plugin`
    id("integrity.kotlin.jvm")
}

gradlePlugin {
    plugins {
        create("integrityBaseline") {
            id = "io.integrity.sdk.baseline"
            implementationClass = "io.integrity.baseline.IntegrityBaselinePlugin"
            displayName = "Integrity baseline plugin"
            description = "Bakes dex/native digests, signing pins and the obfuscated string vault into the build."
        }
    }
}

dependencies {
    testImplementation(libs.junit)
    testImplementation(libs.truth)
}
