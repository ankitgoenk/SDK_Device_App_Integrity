/**
 * A pure-JVM library that is also published as a Maven artifact.
 *
 * Exists so `integrity-model` can be consumed by both the Android SDK and a plain JVM
 * backend. An android-library publishes an AAR, which a JVM module cannot consume — which
 * is exactly why the scoring code had to leave `integrity-core` before a backend could
 * re-score with the same implementation rather than a second one that drifts.
 */
plugins {
    id("integrity.kotlin.jvm")
    `maven-publish`
}

group = IntegrityBuild.GROUP
version = IntegrityBuild.VERSION

java {
    withSourcesJar()
}

publishing {
    publications {
        create<MavenPublication>("release") {
            from(components["java"])
            groupId = IntegrityBuild.GROUP
            artifactId = project.name
            version = IntegrityBuild.VERSION
        }
    }
    repositories {
        maven {
            name = "localRepo"
            url = uri(rootProject.layout.buildDirectory.dir("local-maven"))
        }
    }
}
