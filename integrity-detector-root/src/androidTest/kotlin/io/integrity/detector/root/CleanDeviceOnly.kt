package io.integrity.detector.root

/**
 * Marks a test that is only meaningful on a clean device image.
 *
 * CI runs the normal instrumented suite on `google_apis`, which is a userdebug image: it
 * ships `su` and reports `test-keys`, so the root detectors legitimately fire there. Tests
 * carrying this annotation run separately, on `google_apis_playstore`, and are excluded
 * from the normal suite by runner filtering.
 */
@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION)
annotation class CleanDeviceOnly
