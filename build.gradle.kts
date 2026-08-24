plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.detekt)
    alias(libs.plugins.ktlint)
    alias(libs.plugins.bcv)
}

// The public API surface is contract. A change to api/*.api must be deliberate and reviewed.
apiValidation {
    ignoredProjects += listOf(
        "sample-app",
        "sample-backend",
        "integrity-baseline-plugin",
        "integrity-testing"
    )
}

allprojects {
    apply(plugin = rootProject.libs.plugins.detekt.get().pluginId)
    apply(plugin = rootProject.libs.plugins.ktlint.get().pluginId)

    detekt {
        config.setFrom(rootProject.files("config/detekt/detekt.yml"))
        buildUponDefaultConfig = true
        parallel = true
    }

    ktlint {
        version.set("1.5.0")
        android.set(true)
        filter {
            exclude { it.file.path.contains("${layout.buildDirectory.get()}") }
        }
    }
}

tasks.register("qualityCheck") {
    group = "verification"
    description = "Runs the static-analysis gates that CI enforces."
    dependsOn(subprojects.map { "${it.path}:detekt" })
    dependsOn(subprojects.map { "${it.path}:ktlintCheck" })
}
