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

// TestKit's injected plugin classpath is the main *runtime* classpath, which by design
// excludes `compileOnly`. AGP is compileOnly here — we never ship it — so without this the
// plugin cannot even be decorated inside a TestKit build.
//
// It has to be AGP's full runtime closure, not `compileClasspath`: the compile artifacts alone
// leave AGP unable to apply its own `version-check` plugin, which needs classes from sibling
// artifacts. A dedicated resolvable configuration is the way to ask for the whole thing.
val agpForTestKit: Configuration by configurations.creating

tasks.named<org.gradle.plugin.devel.tasks.PluginUnderTestMetadata>("pluginUnderTestMetadata") {
    pluginClasspath.from(agpForTestKit)
}

dependencies {
    // compileOnly: AGP is provided by the consuming build, never shipped by us.
    compileOnly(libs.android.gradlePlugin)
    agpForTestKit(libs.android.gradlePlugin)

    // TestKit runs the plugin inside a real Android build; gradleTestKit() supplies the runner.
    testImplementation(gradleTestKit())
    testImplementation(libs.junit)
    testImplementation(libs.truth)
}
