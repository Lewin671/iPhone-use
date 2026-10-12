"""Private shared credentials and reproducible, authenticated WDA builds."""
import fcntl
import hashlib
import os
from pathlib import Path
import plistlib
import re
import secrets
import stat
import subprocess
import tempfile

TOKEN_FILE = "control-token"
AUTH_PROTOCOL = "bearer-v1"
PATCH = Path(__file__).resolve().parents[1] / "tooling/wda-auth.patch"


def control_token(directory, create=True):
    directory = Path(directory).resolve()
    if any((ancestor / ".git").exists() for ancestor in (directory, *directory.parents)):
        raise ValueError("Device credentials must stay outside Git checkouts.")
    path = directory / TOKEN_FILE
    lock_fd = os.open(directory / ".auth.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            if not create:
                raise ValueError("Device authentication is not configured; run setup first.")
            token = secrets.token_hex(32)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(token + "\n")
            return token
        with os.fdopen(fd) as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError("Device credential must be an owner-only regular file.")
            token = stream.read(128).strip()
        if not re.fullmatch(r"[0-9a-f]{64}", token):
            raise ValueError("Invalid device credential; preserve it and inspect setup.")
        return token
    finally:
        os.close(lock_fd)


def patch_digest():
    return hashlib.sha256(PATCH.read_bytes()).hexdigest()


def verify_source(source):
    """Accept exactly the bundled changes, including new headers; no unrelated edits."""
    result = subprocess.run(["git", "-C", str(source), "diff", "--binary", "--full-index", "HEAD"],
                            capture_output=True, check=True)
    if result.stdout != PATCH.read_bytes():
        raise ValueError("WDA must have exactly the bundled authentication patch; fetch the managed source.")


def apply_patch(source):
    subprocess.run(["git", "-C", str(source), "apply", "--check", str(PATCH)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "-C", str(source), "apply", str(PATCH)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # A new header is included in the deterministic diff without staging its contents.
    subprocess.run(["git", "-C", str(source), "add", "--intent-to-add",
                    "WebDriverAgentLib/Routing/FBUseAuthentication.h"], check=True)
    verify_source(source)


def authenticated_xctestrun(state_dir, device_port):
    """Inject the credential into a private run file, never source, build flags or argv."""
    state_dir = Path(state_dir)
    candidates = list((state_dir / "derived_data/Build/Products").glob("*.xctestrun"))
    if len(candidates) != 1:
        raise ValueError("Expected one built WDA xctestrun; rebuild in a clean private derived-data directory.")
    source = candidates[0]
    document = plistlib.loads(source.read_bytes())
    def expand(value):
        if isinstance(value, str):
            return value.replace("__TESTROOT__", str(source.parent))
        if isinstance(value, dict):
            return {key: expand(item) for key, item in value.items()}
        if isinstance(value, list):
            return [expand(item) for item in value]
        return value
    document = expand(document)
    if isinstance(document.get("TestConfigurations"), list):
        targets = [target for config in document["TestConfigurations"]
                   for target in config.get("TestTargets", [])]
    else:
        targets = [value for key, value in document.items()
                   if key != "__xctestrun_metadata__" and isinstance(value, dict)]
    runners = [target for target in targets if "WebDriverAgentRunner" in str(target.get("TestBundlePath", ""))]
    if len(runners) != 1:
        raise ValueError("Expected exactly one WebDriverAgentRunner test target.")
    env = runners[0].setdefault("EnvironmentVariables", {})
    if not isinstance(env, dict):
        raise ValueError("Invalid test environment in the built run file.")
    env.update(IPHONE_USE_DEVICE_TOKEN=control_token(state_dir), USE_PORT=str(device_port),
               VERBOSE_LOGGING="0", MJPEG_SERVER_PORT="9100")
    # Clearing an inherited bind override keeps USB and the paired tunnel usable.
    env.pop("USE_IP", None)
    destination = state_dir / "runtime/authenticated.xctestrun"
    fd, temporary = tempfile.mkstemp(prefix=".run-", dir=destination.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            plistlib.dump(document, stream)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return destination
