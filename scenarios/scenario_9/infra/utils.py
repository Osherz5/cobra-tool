import os
import ssl
import sys
import urllib.request


def _create_ssl_context():
    """Create an SSL context with proper certificate verification."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def fetch_public_ip():
    """Fetch the public IP of the machine running this script."""
    urls = [
        "https://api.ipify.org",
        "http://api.ipify.org",
    ]
    last_error = None
    for url in urls:
        try:
            ctx = _create_ssl_context() if url.startswith("https") else None
            response = urllib.request.urlopen(url, context=ctx, timeout=10)
            ip = response.read().decode("utf-8").strip()
            if not ip:
                raise Exception("Could not fetch IP, got empty response.")
            return ip
        except Exception as e:
            last_error = e
    raise Exception(f"Error fetching public IP: {last_error}")


def read_public_key(pub_key_path):
    """Read the SSH public key from the specified file path."""
    try:
        with open(pub_key_path, "r") as f:
            public_key = f.read().strip()
        return public_key
    except FileNotFoundError:
        print(f"Error: Public key file not found at {pub_key_path}", file=sys.stderr)
        print(f"Please ensure the path '{pub_key_path}' is correct relative to where you run 'pulumi up'.",
              file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading public key: {e}", file=sys.stderr)
        sys.exit(1)


def read_startup_script(script_filename="startup_script.sh"):
    """Read the startup script from a file in the same directory as this module."""
    script_path = os.path.join(os.path.dirname(__file__), script_filename)
    try:
        with open(script_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: Startup script not found at {script_path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading startup script: {e}", file=sys.stderr)
        sys.exit(1)
