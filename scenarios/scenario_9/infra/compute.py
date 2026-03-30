import pulumi
import pulumi_gcp as gcp


def create_sa_role_binding(name, service_account, role):
    """Bind an IAM role to a service account at the GCP project level.

    Uses ``gcp.projects.IAMMember`` which is additive — it will not
    remove other members that already hold the same role.

    Args:
        name: Pulumi resource name for the binding.
        service_account: The ``gcp.serviceaccount.Account`` to grant the role to.
        role: The IAM role string (e.g. ``roles/compute.editor``).

    Returns:
        The created ``gcp.projects.IAMMember`` resource.
    """
    gcp_config = pulumi.Config("gcp")
    project = gcp_config.require("project")

    return gcp.projects.IAMMember(name,
        project=project,
        role=role,
        member=service_account.email.apply(lambda email: f"serviceAccount:{email}"),
    )


def create_instance(
    name: str,
    machine_type: str,
    zone: str,
    ubuntu_image: str,
    network: gcp.compute.Network,
    service_account: gcp.serviceaccount.Account,
    ssh_user: str,
    ssh_public_key: str,
    startup_script,
    default_labels: dict,
):
    """Create a GCP Compute Engine instance for scenario 9.

    Args:
        name: Instance name (used as both the Pulumi resource name and GCE name).
        machine_type: GCE machine type (e.g. ``e2-medium``).
        zone: GCP zone for the instance.
        ubuntu_image: Full image path for the boot disk.
        network: The VPC network to attach the instance to.
        service_account: The service account to attach to the instance.
        ssh_user: SSH username to configure on the instance.
        ssh_public_key: SSH public key content for the user.
        startup_script: Startup script content (string or ``pulumi.Output[str]``).
        default_labels: Labels to apply to the instance.

    Returns:
        The created ``gcp.compute.Instance`` resource.
    """
    return gcp.compute.Instance(name,
        name=name,
        machine_type=machine_type,
        zone=zone,
        boot_disk=gcp.compute.InstanceBootDiskArgs(
            initialize_params=gcp.compute.InstanceBootDiskInitializeParamsArgs(
                image=ubuntu_image,
                size=20,
                type="pd-standard",
            ),
        ),
        network_interfaces=[
            gcp.compute.InstanceNetworkInterfaceArgs(
                network=network.id,
                access_configs=[
                    gcp.compute.InstanceNetworkInterfaceAccessConfigArgs(),
                ],
            ),
        ],
        service_account=gcp.compute.InstanceServiceAccountArgs(
            email=service_account.email,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        ),
        tags=["cobra-scenario-9"],
        metadata={
            "enable-oslogin": "FALSE",
            "ssh-keys": f"{ssh_user}:{ssh_public_key}",
        },
        metadata_startup_script=startup_script,
        labels={
            **default_labels,
        },
    )
