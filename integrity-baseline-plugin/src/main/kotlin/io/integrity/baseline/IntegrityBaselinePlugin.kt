package io.integrity.baseline

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property

/**
 * Build-time baseline generation.
 *
 * Phase 4 implements this. It runs after packaging and writes, into the native string
 * vault: the digest of every `classes*.dex` in the produced artifact, digests of the SDK's
 * own native libraries, the expected package name, and the signing-certificate pins.
 *
 * The point is that no human maintains a digest by hand: an R8 configuration change that
 * shifts the dex layout updates the baseline automatically, so APP_DEX_DIGEST_MISMATCH
 * never fires on our own release.
 */
public class IntegrityBaselinePlugin : Plugin<Project> {

    override fun apply(target: Project) {
        val extension = target.extensions.create(
            EXTENSION_NAME,
            IntegrityBaselineExtension::class.java
        )

        target.tasks.register(TASK_NAME) { task ->
            task.group = "integrity"
            task.description = "Generates the build-time integrity baseline (phase 4)."
            task.doLast {
                task.logger.lifecycle(
                    "integrity-baseline: not implemented yet (phase 4). " +
                        "verifyDexDigests=${extension.verifyDexDigests.get()}, " +
                        "obfuscateStrings=${extension.obfuscateStrings.get()}"
                )
            }
        }
    }

    private companion object {
        const val EXTENSION_NAME = "integrityBaseline"
        const val TASK_NAME = "generateIntegrityBaseline"
    }
}

public abstract class IntegrityBaselineExtension {
    /** SHA-256 of the signing certificate(s); several are allowed for key rotation. */
    public abstract val expectedSigningCertSha256: ListProperty<String>

    public abstract val verifyDexDigests: Property<Boolean>

    public abstract val obfuscateStrings: Property<Boolean>

    init {
        verifyDexDigests.convention(true)
        obfuscateStrings.convention(true)
    }
}
