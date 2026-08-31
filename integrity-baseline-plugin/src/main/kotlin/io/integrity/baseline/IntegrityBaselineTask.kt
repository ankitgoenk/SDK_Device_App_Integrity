package io.integrity.baseline

import org.gradle.api.DefaultTask
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction

/** Writes the build-time baseline for one variant. See [BaselineComputer] for what it is for. */
public abstract class IntegrityBaselineTask : DefaultTask() {

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    public abstract val archive: RegularFileProperty

    @get:Input
    public abstract val packageName: Property<String>

    @get:OutputFile
    public abstract val baselineFile: RegularFileProperty

    @TaskAction
    public fun generate() {
        val input = archive.get().asFile
        val baseline = BaselineComputer.compute(input, packageName.get())

        // Checked before anything is written. An empty baseline is worse than no baseline:
        // it is a file that looks like a comparison and can never disagree with anything, and
        // a failed build that left one behind would be believed by the next step.
        check(baseline.dex.isNotEmpty()) {
            "no classes*.dex found in ${input.name}; the baseline would be vacuous"
        }

        val out = baselineFile.get().asFile
        out.parentFile?.mkdirs()
        out.writeText(baseline.toJson())
        logger.lifecycle(
            "integrity-baseline: ${baseline.dex.size} dex, ${baseline.nativeLibs.size} native lib(s) -> ${out.name}"
        )
    }
}
