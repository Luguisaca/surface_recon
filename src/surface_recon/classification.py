from pathlib import Path
import ipaddress
import re
from urllib.parse import urlparse

from .model import ClassificationState, Target


def classify_target(target: Target) -> Target:
    value = target.value.strip()

    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        target.target_type = "url"
        target.classification_state = ClassificationState.RESOLVED
        return target

    try:
        ipaddress.ip_address(value)
        target.target_type = "host"
        target.classification_state = ClassificationState.RESOLVED
        return target
    except ValueError:
        pass

    try:
        ipaddress.ip_network(value, strict=False)
        target.target_type = "network"
        target.classification_state = ClassificationState.RESOLVED
        return target
    except ValueError:
        pass

    if re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?[.])+[A-Za-z]{2,63}", value):
        target.target_type = "host"
        target.classification_state = ClassificationState.RESOLVED
        return target

    path = Path(value)
    if value.startswith(("./", "../", ".\\", "..\\")) or path.is_absolute() or path.exists():
        if path.exists() and path.is_dir() and (path / ".git").exists():
            target.target_type = "repository"
        elif path.exists() and path.is_dir():
            target.target_type = "directory"
        elif path.suffix.lower() in {".exe", ".dll", ".bin", ".so", ".elf"}:
            target.target_type = "binary"
        else:
            target.target_type = "path"
        target.classification_state = ClassificationState.RESOLVED
        return target

    # Preserve every submitted value as an auditable target. Unknown syntax is
    # characterized as opaque rather than rejected; deeper capabilities can be
    # selected later from evidence without changing authorization scope.
    target.target_type = "opaque"
    target.classification_state = ClassificationState.RESOLVED
    return target
