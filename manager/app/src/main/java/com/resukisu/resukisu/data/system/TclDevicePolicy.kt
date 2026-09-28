package com.resukisu.resukisu.data.system

import android.os.Build
import android.system.Os
import java.util.concurrent.TimeUnit

/**
 * Safety policy for the TCL T653T01 laboratory target.
 *
 * Every profile is deliberately exact and fail closed. V643 was validated on
 * device; V637 and V655/V665/V667 are experimental profiles with independent
 * firmware/kernel checks in GhostLock. The manager only needs to keep these
 * exact targets in volatile-only mode and must never infer a nearby version.
 */
object TclDevicePolicy {
    const val PLATFORM = "T653T01"
    const val PRODUCT_DEVICE = "G08"

    private data class ExactProfile(
        val firmware: String,
        val softwareVersion: String,
        val kernelRelease: String,
    )

    private val exactProfiles = listOf(
        ExactProfile("V637", "V8-T653T01-LF1V637", "5.15.180-android14-11"),
        ExactProfile("V643", "V8-T653T01-LF1V643", "5.15.180-android14-11"),
        ExactProfile("V655", "V8-T653T01-LF1V655", "5.15.192-android14-11"),
        ExactProfile("V665", "V8-T653T01-LF1V665", "5.15.192-android14-11"),
        ExactProfile("V667", "V8-T653T01-LF1V667", "5.15.192-android14-11"),
    )

    private val softwareVersionId: String by lazy {
        runCatching {
            val process = ProcessBuilder(
                "/system/bin/getprop",
                "ro.software.version_id",
            ).redirectErrorStream(true).start()
            val value = process.inputStream.bufferedReader().use { it.readLine().orEmpty().trim() }
            if (!process.waitFor(1, TimeUnit.SECONDS) || process.exitValue() != 0) "" else value
        }.getOrDefault("")
    }

    val isExactVolatileTarget: Boolean
        get() {
            if (!Build.MANUFACTURER.equals("TCL", ignoreCase = true) ||
                !Build.DEVICE.equals(PRODUCT_DEVICE, ignoreCase = true) ||
                Build.VERSION.SDK_INT != 34
            ) {
                return false
            }
            val display = Build.DISPLAY.orEmpty()
            val kernel = Os.uname().release
            return exactProfiles.any { profile ->
                val exactSoftwareVersion = softwareVersionId.equals(
                    profile.softwareVersion,
                    ignoreCase = true,
                ) || (
                    softwareVersionId.isBlank() &&
                        display.contains(PLATFORM, ignoreCase = true) &&
                        display.contains(profile.firmware, ignoreCase = true)
                    )
                exactSoftwareVersion && kernel == profile.kernelRelease
            }
        }
}
