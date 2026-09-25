package com.resukisu.resukisu.data.system

import android.os.Build
import android.system.Os

/**
 * Safety policy for the TCL C855 laboratory target.
 *
 * This profile is deliberately exact and fail closed. It only identifies the
 * V643 build that was validated offline and on-device. The manager must never
 * turn a nearby TCL firmware version into an assumed-compatible target.
 */
object TclDevicePolicy {
    const val PLATFORM = "T653T01"
    const val FIRMWARE = "V643"
    const val KERNEL_RELEASE = "5.15.180-android14-11"

    val isExactVolatileTarget: Boolean
        get() {
            val display = Build.DISPLAY.orEmpty()
            return Build.MANUFACTURER.equals("TCL", ignoreCase = true) &&
                display.contains(PLATFORM, ignoreCase = true) &&
                display.contains(FIRMWARE, ignoreCase = true) &&
                Build.VERSION.SDK_INT == 34 &&
                Os.uname().release == KERNEL_RELEASE
        }
}
