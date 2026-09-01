@file:Suppress("unused", "ClassName")

package de.robv.android.xposed.callbacks

class XC_LoadPackage {
    class LoadPackageParam {
        @JvmField var packageName: String = ""

        @JvmField var classLoader: ClassLoader? = null
    }
}
