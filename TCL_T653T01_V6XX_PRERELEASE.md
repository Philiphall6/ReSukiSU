# ReSukiSU TCL T653T01 v1.1.0-pre4

> [!CAUTION]
> V637, V655, V665 and V667 have not been root-tested on matching real
> hardware. The associated GhostLock profiles may panic or reboot the TV,
> interrupt networking/ADB, or require a physical power cycle. V643 is the
> only hardware-validated profile.

This manager recognizes these exact Android 14 volatile-only targets:

- V637 and V643 with `5.15.180-android14-11`;
- V655, V665 and V667 with `5.15.192-android14-11`.

There is no generic V6xx match. Firmware and kernel must form one of the exact
pairs above. On those targets, boot-image and AnyKernel installation routes
remain disabled; the manager only controls a temporary, late-loaded driver.

The 5.15.192 driver candidate is separate from the V643 module. Its target
KMI/BTF, vermagic and 163 imported symbol CRCs were checked offline, but its
live loading and GhostLock handoff have not yet been validated on a V65x TV.

Use this companion only with the matching GhostLock TCL T653T01 pre-release.
No boot image, VBMeta, firmware or partition is modified by the volatile path.
