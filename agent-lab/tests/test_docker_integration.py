from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dorker_agent.container_sandbox import ContainerOutputLimitError, ContainerSandboxConfig, DockerCLIContainerRuntime, Mount
from dorker_agent.execution import ExecutionDeadlineExceeded

IMAGE = os.environ.get("DORKER_TEST_IMAGE")
RUNTIME = DockerCLIContainerRuntime()


@unittest.skipUnless(IMAGE, "real Docker integration runs only when DORKER_TEST_IMAGE is set")
class DockerDaemonIntegrationTests(unittest.TestCase):
    def test_isolation_identity_and_resource_limits(self):
        probe = r"""
import os
from pathlib import Path
assert os.getuid() == 10000
assert os.getgid() == 10000
status = Path("/proc/self/status").read_text()
assert "NoNewPrivs:\t1" in status
cap_eff = next(line for line in status.splitlines() if line.startswith("CapEff:"))
assert int(cap_eff.split()[1], 16) == 0
try:
    Path("/rootfs-write-probe").write_text("blocked")
except OSError:
    pass
else:
    raise AssertionError("root filesystem unexpectedly writable")
Path("/tmp/dorker-tmpfs-probe").write_text("writable")
assert Path("/tmp/dorker-tmpfs-probe").read_text() == "writable"
routes = Path("/proc/net/route").read_text().splitlines()[1:]
assert not any(line.split()[1] == "00000000" for line in routes), routes
cg = Path("/sys/fs/cgroup")
if (cg / "memory.max").exists():
    assert int((cg / "memory.max").read_text()) <= 128 * 1024 * 1024
if (cg / "pids.max").exists():
    assert int((cg / "pids.max").read_text()) <= 16
if (cg / "cpu.max").exists():
    quota, period = map(int, (cg / "cpu.max").read_text().split())
    assert quota > 0 and quota / period <= 0.5
print("docker-isolation-probe: PASS")
"""
        config = ContainerSandboxConfig(
            image=IMAGE, command=("python", "-I", "-c", probe),
            memory_bytes=128 * 1024 * 1024, cpu_limit=0.5, pids_limit=16,
            tmpfs_bytes=8 * 1024 * 1024, max_output_bytes=4096,
        )
        result = RUNTIME.run_container(config, timeout_seconds=15, control=None)
        self.assertIn(b"docker-isolation-probe: PASS", result.stdout)

    def test_read_only_host_mount_and_no_docker_socket(self):
        with __import__("tempfile").TemporaryDirectory() as host_dir:
            fixture = Path(host_dir) / "fixture.txt"
            fixture.write_text("host-data")
            fixture.chmod(0o644)
            Path(host_dir).chmod(0o755)
            probe = r"""
from pathlib import Path
assert Path("/input/fixture.txt").read_text() == "host-data"
try:
    Path("/input/attack.txt").write_text("must-not-reach-host")
except OSError:
    pass
else:
    raise AssertionError("read-only host mount accepted a write")
assert not Path("/var/run/docker.sock").exists()
assert not Path("/run/docker.sock").exists()
print("mount-boundary-probe: PASS")
"""
            config = ContainerSandboxConfig(
                image=IMAGE, command=("python", "-I", "-c", probe),
                allowed_mount_roots=(host_dir,),
                mounts=(Mount(host_dir, "/input", read_only=True),),
                allow_host_mounts=True,
                max_output_bytes=4096,
            )
            result = RUNTIME.run_container(config, timeout_seconds=15, control=None)
            self.assertIn(b"mount-boundary-probe: PASS", result.stdout)
            self.assertFalse((Path(host_dir) / "attack.txt").exists())

    def test_bounded_artifact_transfer_over_stdin(self):
        config = ContainerSandboxConfig(
            image=IMAGE, command=("python", "-I", "-c",
                "import sys; data=sys.stdin.buffer.read(); "
                "assert data == b'artifact' + bytes([0]) + b'payload'; print(len(data))"),
            input_payload=b"artifact" + bytes([0]) + b"payload", max_input_bytes=64,
            max_output_bytes=1024,
        )
        result = RUNTIME.run_container(config, timeout_seconds=10, control=None)
        self.assertIn(b"16", result.stdout)

    def test_timeout_stops_long_running_container(self):
        config = ContainerSandboxConfig(
            image=IMAGE, command=("python", "-I", "-c", "import time; time.sleep(30)"),
            max_output_bytes=1024,
        )
        with self.assertRaises(ExecutionDeadlineExceeded):
            RUNTIME.run_container(config, timeout_seconds=0.5, control=None)

    def test_output_limit_stops_noisy_container(self):
        config = ContainerSandboxConfig(
            image=IMAGE,
            command=("python", "-I", "-c", "import sys; sys.stdout.write('x' * 1000000); sys.stdout.flush()"),
            max_output_bytes=1024,
        )
        with self.assertRaises(ContainerOutputLimitError):
            RUNTIME.run_container(config, timeout_seconds=10, control=None)


if __name__ == "__main__":
    unittest.main()
