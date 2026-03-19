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


def prepare_startup_script(
    include_agent: bool,
    config: pulumi.Config,
    service_account: gcp.serviceaccount.Account,
    default_labels: dict,
):
    """Prepare the startup script, optionally including Cortex XDR agent installation.

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
        Tuple of (startup_script, agent_exports) where ``startup_script`` is
        either a plain string or a ``pulumi.Output[str]``, and ``agent_exports``
        is a dict of values to export via ``pulumi.export()``.
    """
    startup_script_template = read_startup_script()
    agent_exports: dict = {}

    if include_agent:
        agent_installer_path = config.require("agentInstallerPath")

        # Create a GCS bucket to host the agent installer
        agent_bucket = gcp.storage.Bucket("cobra-scenario-9-agent-bucket",
            location="US",
            force_destroy=True,
            uniform_bucket_level_access=True,
            labels={**default_labels},
        )

        # Upload the agent installer archive to the bucket
        agent_object = gcp.storage.BucketObject("agent-installer-obj",
            bucket=agent_bucket.name,
            name="agent_installer.tar.gz",
            source=pulumi.FileAsset(agent_installer_path),
        )

        # Grant the compute instance's service account read access to the agent bucket
        gcp.storage.BucketIAMMember("agent-bucket-reader",
            bucket=agent_bucket.name,
            role="roles/storage.objectViewer",
            member=service_account.email.apply(lambda email: f"serviceAccount:{email}"),
        )

        # Build the agent installation shell block that will replace the
        # placeholder in the startup script template.
        agent_block = pulumi.Output.all(
            agent_bucket.name, agent_object.name,
        ).apply(_build_agent_block)

        # Replace the placeholder with the agent block
        startup_script = agent_block.apply(
            lambda block: startup_script_template.replace(AGENT_INSTALL_PLACEHOLDER, block)
        )

        agent_exports["Agent Bucket"] = agent_bucket.name
        agent_exports["Agent Included"] = True
    else:
        # No agent — remove the placeholder from the startup script
        startup_script = startup_script_template.replace(
            AGENT_INSTALL_PLACEHOLDER, "# Agent not included",
        )
        agent_exports["Agent Included"] = False

    return startup_script, agent_exports
