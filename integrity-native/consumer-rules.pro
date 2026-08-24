# JNI methods are registered dynamically in JNI_OnLoad, but the loader class itself
# must keep its name so System.loadLibrary can find its companion.
-keep class io.integrity.nativecore.NativeBridge { *; }
