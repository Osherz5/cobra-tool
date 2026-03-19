import os
import re
import subprocess
import json
import time
from time import sleep
from termcolor import colored
from core.helpers import loading_animation, generate_ssh_key

PULUMI_STACK_NAME = "cobra-scenario-9"
PULUMI_OUTPUT_JSON_PATH = "./core/cobra-scenario-9-output.json"
SSH_KEY_PATH = "./scenario_9_id_rsa"

CYTOOL_STATUS_CMD = "/opt/traps/bin/cytool status"
AGENT_CHECK_INTERVAL = 60  # seconds between agent status checks
MAX_AGENT_WAIT_TIME = 60 * 10  # 10 minutes max wait


class ScenarioExecution:
    def __init__(self):
        self.instance_name = None
        self.instance_public_ip = None
        self.instance_id = None
        self.instance_zone = None
        self.service_account_email = None
        self.ssh_user = None
        self.web_app_url = None
        self.agent_included = False

    def read_pulumi_config(self):
        """Read Pulumi stack outputs from the JSON file."""
        with open(PULUMI_OUTPUT_JSON_PATH, "r") as file:
            data = json.load(file)

        self.instance_name = data["Instance Name"]
        self.instance_public_ip = data["Instance Public IP"]
        self.instance_id = data["Instance ID"]
        self.instance_zone = data["Instance Zone"]
        self.service_account_email = data["Service Account Email"]
        self.ssh_user = data["SSH User"]
        self.web_app_url = data["Web App URL"]
        self.agent_included = data.get("Agent Included", False)

    def init_infra(self):
        """Generate SSH keys and deploy Pulumi infrastructure."""
        if not os.path.exists(SSH_KEY_PATH):
            generate_ssh_key(SSH_KEY_PATH)
        else:
            print(colored(f"SSH key already exists at '{SSH_KEY_PATH}', reusing.", color="yellow"))

        if os.path.exists(PULUMI_OUTPUT_JSON_PATH):
            os.remove(PULUMI_OUTPUT_JSON_PATH)
            print("File '{}' found and deleted.".format(PULUMI_OUTPUT_JSON_PATH))
        else:
            print("File '{}' not found.".format(PULUMI_OUTPUT_JSON_PATH))

        subprocess.call(
            f"cd ./scenarios/scenario_9/infra/ && pulumi up -s {PULUMI_STACK_NAME} -y",
            shell=True,
        )
        subprocess.call(
            f"cd ./scenarios/scenario_9/infra/ && pulumi stack -s {PULUMI_STACK_NAME} output --json >> ../../../{PULUMI_OUTPUT_JSON_PATH}",
            shell=True,
        )

    def wait_for_instance_running(self):
        """Poll GCP compute instance status until it reaches RUNNING state."""
        print(colored("Waiting for instance to reach RUNNING status...", color="yellow"))
        max_attempts = 30
        for attempt in range(1, max_attempts + 1):
            try:
                result = subprocess.run(
                    f"gcloud compute instances describe {self.instance_name} --zone={self.instance_zone} --format='value(status)'",
                    shell=True, capture_output=True, text=True,
                )
                status = result.stdout.strip()
                if status == "RUNNING":
                    print(colored(f"Instance '{self.instance_name}' is RUNNING.", color="green"))
                    return True
                print(colored(f"  Attempt {attempt}/{max_attempts} - Current status: {status}", color="yellow"))
            except Exception as e:
                print(colored(f"  Attempt {attempt}/{max_attempts} - Error checking status: {e}", color="yellow"))
            sleep(10)
        print(colored(f"Instance did not reach RUNNING status after {max_attempts} attempts.", color="red"))
        return False

    def check_agent_connected(self):
        """Check if the Cortex XDR agent EDR is enabled on the remote instance via SSH."""
        cmdline = (
            f"ssh -o StrictHostKeyChecking=no -i {SSH_KEY_PATH} "
            f"{self.ssh_user}@{self.instance_public_ip} 'sudo {CYTOOL_STATUS_CMD}'"
        )
        try:
            result = subprocess.run(cmdline, shell=True, capture_output=True, text=True)
            output = result.stdout
            edr_match = re.search(r"\nEDR\s+\w+\s+(\w+)\s+", output)
            if edr_match:
                return edr_match.group(1) == "Enabled"
        except Exception as e:
            print(colored(f"  Agent check error: {e}", color="yellow"))
        return False

    def wait_for_agent(self):
        """Wait for the Cortex XDR agent EDR to become enabled on the instance."""
        print(colored("Waiting for Cortex XDR agent EDR to be enabled...", color="yellow"))
        time_waited = 0

        while True:
            if self.check_agent_connected():
                print(colored("Cortex XDR agent EDR enabled!", color="green"))
                return True

            if time_waited >= MAX_AGENT_WAIT_TIME:
                print(colored(
                    "Agent EDR did not start within the timeout period. "
                    "The scenario will continue, but the agent may not be active.",
                    color="red",
                ))
                return False

            print(colored(
                f"  Agent not ready yet, retrying in {AGENT_CHECK_INTERVAL}s "
                f"(waited {time_waited}s / {MAX_AGENT_WAIT_TIME}s)...",
                color="yellow",
            ))
            time.sleep(AGENT_CHECK_INTERVAL)
            time_waited += AGENT_CHECK_INTERVAL

    def scenario_9_execute(self, manual):
        """Deploy infrastructure and optionally run the attack simulation.

        When ``--manual`` is passed, only the infrastructure is deployed.
        The attack simulation can then be triggered separately via the
        ``post-launch`` action.
        """
        print("-" * 30)
        print(colored(
            "Executing Scenario 9 : GCP Cloud Detection and Response - Attack Simulation on GCP Environment",
            color="red",
        ))
        loading_animation()
        print("-" * 30)

        print(colored(
            "Please make sure that this scenario's Pulumi.yaml is properly configured for your specific environment.",
            "yellow",
        ))

        input("Press enter to continue...")

        print(colored("Rolling out Infra", color="red"))
        loading_animation()
        print("-" * 30)

        self.init_infra()

        print("-" * 30)
        print(colored("Infrastructure deployed successfully", color="green"))
        loading_animation()

        if manual:
            print(colored(
                "Using manual mode - use 'post-launch' to start the attack simulation",
                "yellow",
            ))
        else:
            self.post_execution()

    def post_execution(self):
        """Run the attack simulation against the already-deployed infrastructure."""
        print(colored("Starting attack simulation...", "cyan"))
        self.read_pulumi_config()

        print("-" * 30)
        print(colored(f"Instance Name: {self.instance_name}", color="cyan"))
        print(colored(f"Instance Public IP: {self.instance_public_ip}", color="cyan"))
        print(colored(f"Instance ID: {self.instance_id}", color="cyan"))
        print(colored(f"Instance Zone: {self.instance_zone}", color="cyan"))
        print(colored(f"Service Account: {self.service_account_email}", color="cyan"))
        print(colored(f"Web App URL: {self.web_app_url}", color="cyan"))
        print(colored(f"Agent Included: {self.agent_included}", color="cyan"))
        print("-" * 30)

        self.wait_for_instance_running()

        # If agent is included, wait for it to become active
        if self.agent_included:
            print("-" * 30)
            print(colored("Cortex XDR agent was included — waiting for agent to initialize...", color="yellow"))
            # Give the startup script time to download and install the agent
            print(colored("Waiting 60s for startup script to complete agent installation...", color="yellow"))
            time.sleep(60)
            self.wait_for_agent()
        else:
            print(colored("Agent not included in this deployment.", color="yellow"))

        print("-" * 30)
        print(colored("GCP Compute Instance is ready for attack simulation", color="green"))
        print(colored(
            f"SSH Command: ssh -o 'StrictHostKeyChecking accept-new' -i {SSH_KEY_PATH} {self.ssh_user}@{self.instance_public_ip}",
            color="green",
        ))
        print(colored(f"Web App: {self.web_app_url}<target>", color="green"))
        print(colored(f"Example: curl \"{self.web_app_url}8.8.8.8\"", color="green"))
        print("-" * 30)

    def scenario_9_destroy(self):
        """Destroy the Pulumi infrastructure for scenario 9."""
        print(colored("Destroying infrastructure...", "yellow"))
        subprocess.call(
            f"cd ./scenarios/scenario_9/infra && pulumi destroy -s {PULUMI_STACK_NAME} --yes",
            shell=True,
        )
