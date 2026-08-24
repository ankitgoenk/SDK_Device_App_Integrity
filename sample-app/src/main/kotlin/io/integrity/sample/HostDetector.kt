package io.integrity.sample

import io.integrity.core.Category
import io.integrity.core.Depth
import io.integrity.core.DetectionContext
import io.integrity.core.Detector
import io.integrity.core.Signal

/**
 * Shows a host registering its own detector alongside the SDK's, which is a supported
 * extension point: business-specific checks get scored by the same policy.
 *
 * It finds nothing, which is itself a documented result — a detector that ran and
 * concluded "no evidence" is not the same as one that could not run, and only the latter
 * returns [io.integrity.core.Confidence.INCONCLUSIVE].
 */
class HostDetector : Detector {
    override val id: String = "sample.host"
    override val category: Category = Category.META
    override val minDepth: Depth = Depth.QUICK

    override suspend fun detect(context: DetectionContext): List<Signal> = emptyList()
}
