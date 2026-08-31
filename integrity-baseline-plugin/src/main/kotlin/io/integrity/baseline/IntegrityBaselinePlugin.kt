package io.integrity.baseline

import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.variant.ApplicationAndroidComponentsExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property

/**
 * Build-time baseline generation (phase 4).
 *
 * Registers one [IntegrityBaselineTask] per variant, wired to that variant's packaged APK
 * through AGP's public artifact API, so no human maintains a digest by hand: an R8
 * configuration change that shifts the dex layout updates the baseline automatically.
 *
 * ### The baseline is a build output, not an embedded asset
 *
 * The obvious design — bake the digests into the APK so the app can check itself — cannot be
 * built, and not for want of API. **A digest of the APK cannot live inside that APK.** Digesting
 * only `classes*.dex` and injecting the result as an asset would dodge the circularity, since
 * assets are packaged after dexing, but AGP 8.9 exposes no stable public API for pre-packaging
 * dex outputs.
 *
 * That constraint turns out to point the same way the architecture already does. A baseline
 * shipped alongside the code an attacker rewrote is worth nothing — they regenerate it. So the
 * client measures its own dex at runtime and *reports what it found*, and only a party holding
 * this file independently can say the report is wrong. ADR-0006's division of labour and
 * ADR-0007's asymmetry, reached by arithmetic rather than preference.
 *
 * Publish `integrity-baseline.json` with the release; the backend compares against it.
 */
public class IntegrityBaselinePlugin : Plugin<Project> {

    override fun apply(target: Project) {
        val extension = target.extensions.create(EXTENSION_NAME, IntegrityBaselineExtension::class.java)

        target.plugins.withId(ANDROID_APPLICATION) {
            val components = target.extensions.getByType(ApplicationAndroidComponentsExtension::class.java)
            components.onVariants { variant ->
                val task = target.tasks.register(
                    "generate${variant.name.replaceFirstChar { it.uppercase() }}IntegrityBaseline",
                    IntegrityBaselineTask::class.java
                ) { t ->
                    t.group = "integrity"
                    t.description = "Generates the build-time integrity baseline for ${variant.name}."
                    t.packageName.set(extension.packageName.orElse(variant.applicationId))
                    t.baselineFile.set(
                        target.layout.buildDirectory.file("outputs/integrity/${variant.name}/integrity-baseline.json")
                    )
                }
                // The APK is the input, so this necessarily runs after packaging. Wiring the
                // artifact rather than a path is what makes the dependency real to Gradle:
                // a path would let the task run before the thing it measures exists.
                val apk = variant.artifacts.get(SingleArtifact.APK).map { dir ->
                    val apks = dir.asFile
                        .listFiles { f -> f.name.endsWith(APK_SUFFIX) }
                        .orEmpty()
                        .sortedBy { it.name }
                    check(apks.isNotEmpty()) { "no APK produced for ${variant.name}" }
                    target.layout.projectDirectory.file(apks.first().absolutePath)
                }
                task.configure { t -> t.archive.set(apk) }
            }
        }
    }

    private companion object {
        const val EXTENSION_NAME = "integrityBaseline"
        const val ANDROID_APPLICATION = "com.android.application"
        const val APK_SUFFIX = ".apk"
    }
}

public abstract class IntegrityBaselineExtension {
    /** SHA-256 of the signing certificate(s); several are allowed for key rotation. */
    public abstract val expectedSigningCertSha256: ListProperty<String>

    /** Overrides the variant's applicationId when the two legitimately differ. */
    public abstract val packageName: Property<String>

    public abstract val verifyDexDigests: Property<Boolean>

    public abstract val obfuscateStrings: Property<Boolean>

    init {
        verifyDexDigests.convention(true)
        obfuscateStrings.convention(true)
    }
}
