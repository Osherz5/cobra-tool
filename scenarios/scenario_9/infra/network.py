import pulumi_gcp as gcp


def create_network(ssh_cidr: str):
    """Create the VPC network and firewall rule for scenario 9.

    Args:
        ssh_cidr: CIDR block to allow SSH and HTTP access from.

    Returns:
        Tuple of (network, firewall) GCP resources.
    """
    network = gcp.compute.Network("cobra-scenario-9-network",
        name="cobra-scenario-9-network",
        auto_create_subnetworks=True,
    )

    firewall = gcp.compute.Firewall("cobra-scenario-9-firewall",
        name="cobra-scenario-9-allow-ssh-http",
        network=network.self_link,
        allows=[
            gcp.compute.FirewallAllowArgs(
                protocol="tcp",
                ports=["22", "8080"],
            ),
        ],
        source_ranges=[ssh_cidr],
        target_tags=["cobra-scenario-9"],
    )

    return network, firewall
