/**
 * An android library that is also published as a Maven artifact.
 *
 * Publishing to a local repository is what lets sample-consumer depend on a real AAR
 * rather than on project(...). That distinction matters: a project dependency exercises
 * neither AAR packaging, nor consumer ProGuard rules, nor manifest merging of the
 * ADR-0004 <queries> fragment — exactly the machinery a real integrator hits first.
 */
plugins {
    id("integrity.android.library")
    `maven-publish`
}

group = IntegrityBuild.GROUP
version = IntegrityBuild.VERSION

android {
    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
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
}
