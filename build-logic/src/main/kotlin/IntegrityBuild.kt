/**
 * Single source of truth for build-wide constants used by the convention plugins.
 *
 * Dependency versions live in `gradle/libs.versions.toml`; only values the Android/Kotlin
 * DSL needs at configuration time live here, because a version catalog is not accessible
 * from precompiled script plugins.
 */
object IntegrityBuild {
    const val COMPILE_SDK = 35
    const val TARGET_SDK = 35

    /** API 24. Below this, ART/native special-casing costs more than the reach is worth. */
    const val MIN_SDK = 24

    const val NAMESPACE_PREFIX = "io.integrity"
    const val TEST_RUNNER = "androidx.test.runner.AndroidJUnitRunner"

    val JAVA_VERSION = org.gradle.api.JavaVersion.VERSION_17
}
