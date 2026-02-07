"""DNS privacy protections — recommend and apply secure DNS configuration."""

from __future__ import annotations

import platform
import subprocess

from dont_track_me.core.base import ProtectionResult

RECOMMENDED_DNS = {
    "quad9": {"primary": "9.9.9.9", "secondary": "149.112.112.112", "name": "Quad9"},
    "cloudflare": {"primary": "1.1.1.1", "secondary": "1.0.0.1", "name": "Cloudflare"},
    "mullvad": {
        "primary": "194.242.2.2",
        "secondary": "194.242.2.3",
        "name": "Mullvad",
    },
}


def _get_active_network_service() -> str | None:
    """Get the primary active network service on macOS."""
    try:
        result = subprocess.run(
            ["networksetup", "-listallnetworkservices"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines()[1:]:  # skip header
                line = line.strip()
                if line and not line.startswith("*"):
                    return line
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


async def protect_dns(
    dry_run: bool = True,
    provider: str = "quad9",
    **kwargs,
) -> ProtectionResult:
    """Configure privacy-respecting DNS."""
    actions_available: list[str] = []
    actions_taken: list[str] = []

    dns_config = RECOMMENDED_DNS.get(provider, RECOMMENDED_DNS["quad9"])
    system = platform.system()

    if system == "Darwin":
        service = _get_active_network_service()
        if service:
            action = (
                f"Set DNS for '{service}' to {dns_config['name']} "
                f"({dns_config['primary']}, {dns_config['secondary']})"
            )
            actions_available.append(action)

            if not dry_run:
                try:
                    subprocess.run(
                        [
                            "networksetup",
                            "-setdnsservers",
                            service,
                            dns_config["primary"],
                            dns_config["secondary"],
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    actions_taken.append(action)
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                    actions_taken.append(f"Failed: {e}")
        else:
            actions_available.append("Could not detect active network service")

    elif system == "Linux":
        action = (
            f"Write {dns_config['name']} DNS servers to /etc/resolv.conf "
            f"({dns_config['primary']}, {dns_config['secondary']})"
        )
        actions_available.append(action)

        if not dry_run:
            try:
                with open("/etc/resolv.conf", "w") as f:
                    f.write(f"# Set by dont-track-me — {dns_config['name']}\n")
                    f.write(f"nameserver {dns_config['primary']}\n")
                    f.write(f"nameserver {dns_config['secondary']}\n")
                actions_taken.append(action)
            except PermissionError:
                actions_taken.append(
                    "Failed: need root privileges to modify /etc/resolv.conf"
                )

    else:
        actions_available.append(
            f"Manual: set your DNS to {dns_config['primary']} and {dns_config['secondary']} ({dns_config['name']})"
        )

    # Always recommend DoH
    actions_available.append(
        "Enable DNS-over-HTTPS in your browser: "
        "Firefox (Settings > Privacy > DNS over HTTPS), "
        "Chrome (Settings > Security > Use secure DNS)"
    )

    return ProtectionResult(
        module_name="dns",
        dry_run=dry_run,
        actions_taken=actions_taken,
        actions_available=actions_available,
    )
