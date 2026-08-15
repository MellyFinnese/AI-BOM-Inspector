# AppArmor profile for aibom sandbox (minimal)
# This profile is intentionally conservative and may need tuning per-host.
profile aibom-sandbox flags=(attach_disconnected) {
  network none,
  file,
  deny @{HOME}/** w,
  /usr/bin/python3 ixr,
  /app/** r,
  /workspace/** r,
  /proc/** r,
  capability,
  deny /** wklx,
}
