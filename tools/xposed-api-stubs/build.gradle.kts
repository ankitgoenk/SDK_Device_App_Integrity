// compileOnly stubs for the legacy Xposed API.
//
// These must NEVER be packaged into a module APK: the framework injects the real classes at
// runtime and refuses to load any module that ships its own copy ("The Xposed API classes are
// compiled into the module's APK"). Consumers depend on this with `compileOnly`.
plugins {
    kotlin("jvm")
}
