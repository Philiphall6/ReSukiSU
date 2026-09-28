package com.resukisu.resukisu.data.system

import android.os.Build
import android.system.Os
import java.util.concurrent.TimeUnit

/**
 * Safety policy for the TCL T653T01 laboratory target.
 *
 * This profile is deliberately exact and fail closed. It only identifies the
 * V643 build that was validated offline and on-device. The manager must never
 * turn a nearby TCL firmware version into an assumed-compatible target.
 */
object TclDevicePolicy {
    const val PLATFORM = "T653T01"
    const val FIRMWARE = "V643"
    const val SOFTWARE_VERSION = "V8-T653T01-LF1V643"
    const val PRODUCT_DEVICE = "G08"
    const val KERNEL_RELEASE = "5.15.180-android14-11"

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
            val display = Build.DISPLAY.orEmpty()
            val exactSoftwareVersion = softwareVersionId.equals(
                SOFTWARE_VERSION,
                ignoreCase = true,
            ) || (
                display.contains(PLATFORM, ignoreCase = true) &&
                    display.contains(FIRMWARE, ignoreCase = true)
                )
            return Build.MANUFACTURER.equals("TCL", ignoreCase = true) &&
                Build.DEVICE.equals(PRODUCT_DEVICE, ignoreCase = true) &&
                exactSoftwareVersion &&
                Build.VERSION.SDK_INT == 34 &&
                Os.uname().release == KERNEL_RELEASE
        }
}
