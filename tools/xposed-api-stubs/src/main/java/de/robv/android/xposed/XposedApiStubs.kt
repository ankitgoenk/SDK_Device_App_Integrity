@file:Suppress("unused", "UNUSED_PARAMETER")

package de.robv.android.xposed

import de.robv.android.xposed.callbacks.XC_LoadPackage

/**
 * Minimal stubs for the legacy Xposed API.
 *
 * The real classes are injected by the framework at runtime; these exist only so the fixture
 * compiles without a dependency on a jar that has not been published since jcenter closed.
 * Anything here that is actually called at runtime resolves to the framework's implementation.
 */
interface IXposedHookLoadPackage {
    fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam)
}

object XposedBridge {
    @JvmStatic fun log(message: String) { /* replaced at runtime */ }
}
