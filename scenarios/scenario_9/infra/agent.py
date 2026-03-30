import pulumi
import pulumi_gcp as gcp

from utils import read_startup_script

AGENT_INSTALL_PLACEHOLDER = "# __AGENT_INSTALL_BLOCK__"


def _build_agent_block(args):
    """Build the shell commands that download and install the Cortex XDR agent."""
    bucket_name, object_name = args
    return (
        f'echo "=== Downloading Cortex XDR agent from GCS ==="\n'
        f'gsutil cp gs://{bucket_name}/{object_name} /home/cobra/agent_installer.tar.gz\n'
        f'echo "Extracting agent..."\n'
        f'mkdir -p /home/cobra/agent\n'
        f'tar -xzf /home/cobra/agent_installer.tar.gz -C /home/cobra/agent\n'
        f'chown -R cobra:cobra /home/cobra/agent\n'
        f'mkdir -p /etc/panw\n'
        f'cp /home/cobra/agent/cortex.conf /etc/panw/ 2>/dev/null || true\n'
        f'chmod +x /home/cobra/agent/cortex-*.sh\n'
        f'/home/cobra/agent/cortex-*.sh\n'
        f'echo "=== Cortex XDR agent installation completed ==="'
    )


def _create_agent_bucket(default_labels):
    """Create the GCS bucket to host the Cortex XDR agent installer.

    Args:
        default_labels: Labels to apply to the bucket.

    Returns:
        The created ``gcp.storage.Bucket`` resource.
    """
    return gcp.storage.Bucket("cobra-scenario-9-agent-bucket",
        location="US",
        force_destroy=True,
        uniform_bucket_level_access=True,
        labels={**default_labels},
    )


def _upload_agent_installer(agent_bucket, agent_installer_path):
    """Upload the agent installer archive to the GCS bucket.

    Args:
        agent_bucket: The GCS bucket to upload to.
        agent_installer_path: Local path to the agent installer tar.gz.

    Returns:
        The created ``gcp.storage.BucketObject`` resource.
    """
    return gcp.storage.BucketObject("agent-installer-obj",
        bucket=agent_bucket.name,
        name="agent_installer.tar.gz",
        source=pulumi.FileAsset(agent_installer_path),
    )


def _grant_sa_bucket_access(name, agent_bucket, service_account):
    """Grant a service account read access to the agent bucket.

    Args:
        name: Pulumi resource name for the IAM member binding.
        agent_bucket: The GCS bucket to grant access to.
        service_account: The service account to grant access.
    """
    gcp.storage.BucketIAMMember(name,
        bucket=agent_bucket.name,
        role="roles/storage.objectViewer",
        member=service_account.email.apply(lambda email: f"serviceAccount:{email}"),
    )


def _patch_startup_script(template, agent_bucket, agent_object):
    """Replace the agent placeholder in a startup script template.

    Args:
        template: The raw startup script string containing the placeholder.
        agent_bucket: The GCS bucket holding the agent installer.
        agent_object: The GCS bucket object for the agent installer.

    Returns:
        A ``pulumi.Output[str]`` with the placeholder replaced by agent
        download/install commands.
    """
    agent_block = pulumi.Output.all(
        agent_bucket.name, agent_object.name,
    ).apply(_build_agent_block)

    return agent_block.apply(
        lambda block: template.replace(AGENT_INSTALL_PLACEHOLDER, block)
    )


def prepare_startup_script(
    include_agent: bool,
    config: pulumi.Config,
    service_account: gcp.serviceaccount.Account,
    default_labels: dict,
):
    """Prepare the startup script for the primary instance.

    When ``include_agent`` is True, a GCS bucket is created to host the agent
    installer archive and the startup script template is patched to download,
    extract, and run it.  The compute instance's service account is granted
    read access to the bucket.

    Args:
        include_agent: Whether to include the Cortex XDR agent.
        config: Pulumi config object (used to read ``agentInstallerPath``).
        service_account: The GCP service account attached to the compute instance.
        default_labels: Labels to apply to created GCP resources.

    Returns:
        Tuple of ``(startup_script, agent_exports, agent_bucket, agent_object)``
        where ``startup_script`` is either a plain string or a
        ``pulumi.Output[str]``, ``agent_exports`` is a dict of values to export
        via ``pulumi.export()``, and ``agent_bucket``/``agent_object`` are the
        GCS resources (or ``None`` when agent is not included).
    """
    startup_script_template = read_startup_script()
    agent_exports: dict = {}
    agent_bucket = None
    agent_object = None

    if include_agent:
        agent_installer_path = config.require("agentInstallerPath")

        agent_bucket = _create_agent_bucket(default_labels)
        agent_object = _upload_agent_installer(agent_bucket, agent_installer_path)
        _grant_sa_bucket_access("agent-bucket-reader", agent_bucket, service_account)

        startup_script = _patch_startup_script(
            startup_script_template, agent_bucket, agent_object,
        )

        agent_exports["Agent Bucket"] = agent_bucket.name
        agent_exports["Agent Included"] = True
    else:
        startup_script = startup_script_template.replace(
            AGENT_INSTALL_PLACEHOLDER, "# Agent not included",
        )
        agent_exports["Agent Included"] = False

    return startup_script, agent_exports, agent_bucket, agent_object


def prepare_startup_script_2(
    include_agent: bool,
    service_account: gcp.serviceaccount.Account,
    agent_bucket=None,
    agent_object=None,
):
    """Prepare the startup script for the second instance.

    Reads ``startup_script_2.sh`` and optionally patches in the agent
    installation block.  When agent is included, the second service account
    is granted read access to the existing agent bucket (created by
    ``prepare_startup_script``).

    Args:
        include_agent: Whether to include the Cortex XDR agent.
        service_account: The service account attached to the second instance.
        agent_bucket: The GCS bucket holding the agent installer (required
            when ``include_agent`` is True).
        agent_object: The GCS bucket object for the agent installer (required
            when ``include_agent`` is True).

    Returns:
        The prepared startup script as a string or ``pulumi.Output[str]``.
    """
    startup_script_template = read_startup_script("startup_script_2.sh")

    if include_agent:
        _grant_sa_bucket_access("agent-bucket-reader-2", agent_bucket, service_account)

        return _patch_startup_script(
            startup_script_template, agent_bucket, agent_object,
        )
    else:
        return startup_script_template.replace(
            AGENT_INSTALL_PLACEHOLDER, "# Agent not included",
        )
