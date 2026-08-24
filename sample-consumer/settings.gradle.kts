// A deliberately SEPARATE Gradle build.
//
// If sample-consumer were a subproject of the root build, Gradle would substitute the
// published coordinates with project dependencies and the whole point would be lost. As
// its own build, it can only resolve io.integrity.sdk:* from the local Maven repository
// the root build publishes into — i.e. from real AARs.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven {
            name = "sdkLocalRepo"
            url = uri("../build/local-maven")
        }
        google()
        mavenCentral()
    }
}

rootProject.name = "sample-consumer"
