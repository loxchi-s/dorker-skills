---
name: sandbox-monitor
description: Monitors sandbox health, resource use, policy violations and execution lifecycle. Use when operating or debugging isolated Dorker jobs.
---
# Sandbox Monitor
Track CPU, RSS, disk, process count, network bytes, wall time, queue wait, exit code and policy denials.
1. Associate process trees with run IDs.
2. Enforce hard limits outside untrusted processes.
3. Detect limit breaches and orphan processes.
4. Terminate full process tree on violation or cancellation.
5. Store bounded diagnostics without secrets. Monitoring alone is not enforcement.
