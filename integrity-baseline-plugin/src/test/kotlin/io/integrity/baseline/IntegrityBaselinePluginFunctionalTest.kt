package io.integrity.baseline

import com.google.common.truth.Truth.assertThat
import java.io.File
import java.util.Properties
import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.TaskOutcome
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Runs the plugin inside a real Android build.
 *
 * The unit tests cover the digesting, which is the part that can compute a wrong answer. This
 * covers the part that can silently compute *no* answer: whether `plugins.withId` fires, whether
 * the variant extension is obtainable, whether a task is registered per variant, and whether
 * AGP's `SingleArtifact.APK` provider actually yields an APK by the time the task runs.
 *
 * None of that was exercised before this test existed. `integrity-baseline-plugin` is a project
 * in this build rather than an included build, so nothing in the repository can apply it — the
 * wiring compiled and had never run, which is the precise shape of defect the rest of this
 * project spends its time catching.
 */
class IntegrityBaselinePluginFunctionalTest {

    @get:Rule
    val projectDir = TemporaryFolder()

    private lateinit var androidSdk: String

    /**
     * A real Android build needs a real SDK.
     *
     * **In CI this fails rather than skips.** Every CI job that runs this has
     * `android-actions/setup-android`, so a missing SDK there is a broken workflow, not an
     * environment fact — and a skip would leave the job green while proving nothing about the
     * wiring, which is the whole reason this test exists. Locally, where an SDK is a
     * reasonable thing to lack, it skips and says why.
     *
     * The decision is [SdkRequirement], extracted so it can be tested without environment
     * gymnastics. A guard whose own behaviour is unobservable is the thing being guarded
     * against.
     */
    @Before
    fun requireAndroidSdk() {
        val sdk = resolveSdk()
        when (SdkRequirement.of(sdk, isCi = System.getenv("CI") != null)) {
            SdkRequirement.OK -> androidSdk = sdk!!
            SdkRequirement.FAIL_CI -> fail(
                "no Android SDK on a CI runner: this test cannot verify the AGP wiring, and " +
                    "skipping would leave the job green having proved nothing. Check that " +
                    "android-actions/setup-android runs before ./gradlew test."
            )
            SdkRequirement.SKIP_LOCAL -> {
                println("SKIPPED: no Android SDK locally (ANDROID_HOME or local.properties sdk.dir)")
                assumeTrue(false)
            }
        }
    }

    private fun resolveSdk(): String? {
        val fromEnv = System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT")
        val fromLocalProperties = File(rootOfThisBuild(), "local.properties")
            .takeIf { it.exists() }
            ?.let { Properties().apply { it.inputStream().use(::load) }.getProperty("sdk.dir") }
        return (fromEnv ?: fromLocalProperties)?.takeIf { File(it, "platforms").isDirectory }
    }

    /** Walks up to the directory holding `settings.gradle.kts`, so this works from any CWD. */
    private fun rootOfThisBuild(): File {
        var dir: File? = File(".").absoluteFile
        while (dir != null && !File(dir, "settings.gradle.kts").exists()) dir = dir.parentFile
        return dir ?: File(".").absoluteFile
    }

    private fun write(path: String, content: String) {
        val file = File(projectDir.root, path)
        file.parentFile.mkdirs()
        file.writeText(content.trimIndent())
    }

    private fun givenAnAndroidApp() {
        write(
            "settings.gradle.kts",
            """
            pluginManagement {
                repositories { google(); mavenCentral(); gradlePluginPortal() }
            }
            dependencyResolutionManagement {
                repositories { google(); mavenCentral() }
            }
            rootProject.name = "baseline-fixture"
        """
        )

        write(
            "build.gradle.kts",
            """
            plugins {
                id("com.android.application")
                id("io.integrity.sdk.baseline")
            }

            android {
                namespace = "io.integrity.fixture"
                compileSdk = $COMPILE_SDK
                defaultConfig {
                    applicationId = "io.integrity.fixture"
                    minSdk = $MIN_SDK
                }
            }
        """
        )

        // At least one class, or there is no dex to digest and the task's own guard fires —
        // which would make this test pass for the wrong reason.
        write(
            "src/main/java/io/integrity/fixture/Fixture.java",
            """
            package io.integrity.fixture;
            public final class Fixture {
                public static int value() { return 42; }
            }
        """
        )

        // Namespace lives in the build file, so the manifest need only exist.
        write(
            "src/main/AndroidManifest.xml",
            """
            <?xml version="1.0" encoding="utf-8"?>
            <manifest />
        """
        )

        write("local.properties", "sdk.dir=$androidSdk")
        write("gradle.properties", "org.gradle.jvmargs=-Xmx2g\nandroid.useAndroidX=true")
    }

    private fun run(vararg args: String) = GradleRunner.create()
        .withProjectDir(projectDir.root)
        .withPluginClasspath()
        .withArguments(*args, "--stacktrace")
        .forwardOutput()
        .build()

    @Test
    fun `registers a task per variant and writes a baseline from the real APK`() {
        givenAnAndroidApp()

        val result = run("generateDebugIntegrityBaseline")

        assertThat(result.task(":generateDebugIntegrityBaseline")?.outcome).isEqualTo(TaskOutcome.SUCCESS)

        val baseline = File(projectDir.root, "build/outputs/integrity/debug/integrity-baseline.json")
        assertThat(baseline.exists()).isTrue()

        val json = baseline.readText()
        // The fixture's own class must be in a dex the task actually digested. An assertion
        // that the file merely exists would pass on an empty baseline.
        assertThat(json).contains("classes.dex")
        assertThat(json).contains("\"packageName\":\"io.integrity.fixture\"")
        val parsed = Regex("\"(classes[0-9]*\\.dex)\":\"([0-9a-f]{64})\"").findAll(json).toList()
        assertThat(parsed).isNotEmpty()
    }

    @Test
    fun `the release variant gets its own task`() {
        // onVariants runs per variant; a plugin that registered one task for the project would
        // pass the test above and silently baseline only debug.
        givenAnAndroidApp()

        val result = run("tasks", "--group", "integrity")

        assertThat(result.output).contains("generateDebugIntegrityBaseline")
        assertThat(result.output).contains("generateReleaseIntegrityBaseline")
    }

    @Test
    fun `a project without the android plugin gets no task and does not fail`() {
        // The `plugins.withId` guard: applying this to a plain JVM project must be inert
        // rather than throwing on a missing AndroidComponentsExtension.
        write("settings.gradle.kts", """rootProject.name = "plain"""")
        write(
            "build.gradle.kts",
            """
            plugins {
                id("io.integrity.sdk.baseline")
            }
        """
        )

        val result = run("tasks", "--group", "integrity")

        assertThat(result.output).doesNotContain("IntegrityBaseline")
    }

    private companion object {
        const val COMPILE_SDK = 35
        const val MIN_SDK = 24
    }
}
