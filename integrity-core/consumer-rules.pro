# Signal ids and enum names appear in reports and are compared as strings.
-keepclassmembers enum io.integrity.core.** { *; }
# Do not add a blanket -keep for io.integrity.** — it defeats the SDK's own obfuscation.
