# ReSukiSU TCL T653T01 v1.0

First device-specific release of the ReSukiSU manager/LKM pair validated on a
TCL T653T01 firmware V643 (hardware validation performed on a C855).

## Exact supported target

- Platform: TCL T653T01 (hardware validation performed on C855)
- Firmware: V643
- Android: 14
- Kernel: `5.15.180-android14-11`
- Android userspace: 32-bit (`armeabi-v7a`) on an arm64 kernel

Do not use the LKM on another firmware, kernel or television model. Similar
version numbers are not proof of binary compatibility.

## Included

- TV-friendly manager APK, package `com.philiphall6.resukisu.tcl`
- exact V643 kernel module, full and stripped variants
- matching armv7 and arm64 `ksud` binaries
- build identity, module metadata, hashes and static validation reports

GhostLock is deliberately not included. This release starts at the ReSukiSU
late-load boundary and is not a self-contained exploit.

## Validated on the real TV

- dedicated APK certificate/LKM identity handshake
- 32-bit manager to arm64-kernel driver communication
- root grant and revoke for an ordinary Android application
- `su -c id` returning UID 0 in the `u:r:ksu:s0` domain
- D-pad navigation through the Superuser list
- D-pad center/enter toggling the per-application Superuser switch
- SELinux Enforcing retained
- Verified Boot green, vbmeta locked and dm-verity enforcing retained

## Safety and limitations

- Volatile session only; reboot clears the loaded module and grants.
- No bootloader unlock, boot/vbmeta patch, partition write or firmware flash.
- Do not use the manager's generic kernel installation/update button on this
  device.
- The manager and module do not make GhostLock or another loader safe or
  reliable. Loader compatibility must be established separately.
- Keep physical recovery access available. A wrong LKM or wrong kernel target
  can panic or hang the TV.

## Integrity

Verify the downloaded assets against `SHA256SUMS.txt` before use. The release
APK certificate SHA-256 is:

`d3058af8ca0fa6e486ff10362ef941fbf96cf7f593548f048a338e6a63ea5ea1`

Source and reproducible build details are in `TCL_T653T01_V643.md`.
