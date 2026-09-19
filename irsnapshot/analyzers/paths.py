"""Host-independent, lexical interpretation of captured Windows paths."""

from dataclasses import dataclass
import ntpath
import re
from typing import Literal

from irsnapshot.models import PathContext


@dataclass(frozen=True)
class PathAssessment:
    category: Literal["temp", "appdata", "profile", "other", "unknown"]
    normalized_path: str | None
    confidence: Literal["known_root", "conventional_pattern", "unresolved"]
    basis: str


@dataclass(frozen=True)
class _RootMatch:
    root: str
    category: Literal["temp", "appdata", "profile", "other"]
    confidence: Literal["known_root", "conventional_pattern"]
    basis: str


_VARIABLE = re.compile(r"%([^%]+)%")
_DRIVE_ABSOLUTE = re.compile(r"^[A-Za-z]:\\")
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
_EXPANSION_DEPTH_LIMIT = 32
_EXPANSION_SIZE_LIMIT = 32_768
_SUBSTITUTION_LIMIT = 256


class _ExpansionFailure(Exception):
    """Expected ambiguity while resolving captured environment values."""


def _unknown(reason: str) -> PathAssessment:
    return PathAssessment(
        category="unknown",
        normalized_path=None,
        confidence="unresolved",
        basis=reason,
    )


def _environment_value(
    name: str, context: PathContext, owner_sid: str | None
) -> tuple[str | None, str | None]:
    named = [item for item in context.environment if item.name.casefold() == name.casefold()]
    global_values = [item.value for item in named if item.owner_sid is None]
    owner_values: list[str] = []
    if owner_sid is not None:
        owner_values = [
            item.value
            for item in named
            if item.owner_sid is not None
            and item.owner_sid.casefold() == owner_sid.casefold()
        ]
    applicable = owner_values or global_values
    if not applicable:
        return None, f"Missing captured environment value for %{name}%; expansion is unresolved."

    distinct: dict[str, str] = {}
    for value in applicable:
        key = value.replace("/", "\\").casefold()
        distinct.setdefault(key, value)
    if len(distinct) != 1:
        return None, f"Conflicting captured environment values for %{name}%; expansion is unresolved."
    return next(iter(distinct.values())), None


def _expand_variables(
    path: str, context: PathContext, owner_sid: str | None
) -> tuple[str | None, str | None]:
    cache: dict[str, str] = {}
    active: set[str] = set()
    substitutions = 0

    def expand_text(text: str) -> str:
        nonlocal substitutions
        if len(text) > _EXPANSION_SIZE_LIMIT:
            raise _ExpansionFailure(
                "Environment variable expansion exceeded its bounded size and is unresolved."
            )

        pieces: list[str] = []
        output_size = 0

        def append(piece: str) -> None:
            nonlocal output_size
            output_size += len(piece)
            if output_size > _EXPANSION_SIZE_LIMIT:
                raise _ExpansionFailure(
                    "Environment variable expansion exceeded its bounded size and is unresolved."
                )
            pieces.append(piece)

        position = 0
        for match in _VARIABLE.finditer(text):
            append(text[position : match.start()])
            substitutions += 1
            if substitutions > _SUBSTITUTION_LIMIT:
                raise _ExpansionFailure(
                    "Environment variable expansion exceeded its bounded substitution "
                    "limit and is unresolved."
                )
            append(resolve(match.group(1)))
            position = match.end()
        append(text[position:])
        expanded = "".join(pieces)
        if "%" in expanded:
            raise _ExpansionFailure(
                "Unresolved percent-delimited environment variable syntax."
            )
        return expanded

    def resolve(name: str) -> str:
        key = name.casefold()
        if key in cache:
            return cache[key]
        if key in active:
            raise _ExpansionFailure(
                "Cyclic captured environment variable expansion is unresolved."
            )
        if len(active) >= _EXPANSION_DEPTH_LIMIT:
            raise _ExpansionFailure(
                "Environment variable expansion exceeded its bounded nesting limit "
                "and is unresolved."
            )
        value, issue = _environment_value(name, context, owner_sid)
        if issue:
            raise _ExpansionFailure(issue)
        assert value is not None
        active.add(key)
        try:
            resolved = expand_text(value)
        finally:
            active.remove(key)
        cache[key] = resolved
        return resolved

    try:
        return expand_text(path), None
    except _ExpansionFailure as exc:
        return None, str(exc)


def _strip_paired_quotes(path: str) -> tuple[str | None, str | None]:
    if path.startswith('"') or path.endswith('"'):
        if len(path) < 2 or not (path.startswith('"') and path.endswith('"')):
            return None, "Malformed surrounding quote in path."
        path = path[1:-1]
    if '"' in path:
        return None, "Malformed quote inside path."
    if not path:
        return None, "Empty path is unresolved."
    return path, None


def _validate_absolute_windows_path(path: str) -> str | None:
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        return "Path contains a control character."
    if '"' in path:
        return "Malformed quote inside path."

    windows_path = path.replace("/", "\\")
    folded = windows_path.casefold()
    if folded.startswith(("\\\\?\\", "\\\\.\\", "\\??\\", "\\\\??\\")):
        return "Windows device namespace paths are unresolved."

    colon_positions = [
        index for index, character in enumerate(windows_path) if character == ":"
    ]
    if colon_positions and not (
        colon_positions == [1] and _DRIVE_PREFIX.match(windows_path)
    ):
        return "Path contains an unsupported colon or alternate data stream."

    drive_absolute = bool(_DRIVE_ABSOLUTE.match(windows_path))
    if windows_path.startswith("\\\\"):
        unc_components = windows_path[2:].split("\\")
        if len(unc_components) < 2 or not unc_components[0] or not unc_components[1]:
            return "Incomplete UNC path; both server and share are required."
    elif drive_absolute:
        pass
    elif _DRIVE_PREFIX.match(windows_path):
        return "Drive-relative path is unresolved without a captured working directory."
    elif windows_path.startswith("\\"):
        return "Root-relative path is unresolved without a captured drive."
    else:
        return "Relative path is unresolved without a captured working directory."

    if any(character in windows_path for character in '<>|*?'):
        return "Path contains malformed Windows path characters."

    for component in windows_path.split("\\"):
        if component in ("", ".", ".."):
            continue
        if component.endswith((" ", ".")):
            return "A path component has an ambiguous trailing space or dot."
    return None


def _normalize_absolute(path: str) -> tuple[str | None, str | None]:
    issue = _validate_absolute_windows_path(path)
    if issue:
        return None, issue
    windows_path = path.replace("/", "\\")
    return ntpath.normcase(ntpath.normpath(windows_path)), None


def _contains(root: str, path: str) -> bool:
    return path == root or path.startswith(root.rstrip("\\") + "\\")


def _root_matches(context: PathContext, path: str) -> list[_RootMatch]:
    matches: list[_RootMatch] = []
    for known in context.known_paths:
        root, issue = _normalize_absolute(known.path)
        if issue or root is None:
            continue
        if _contains(root, path):
            category: Literal["temp", "appdata", "profile", "other"] = {
                "temp": "temp",
                "appdata": "appdata",
                "local_appdata": "appdata",
                "profile": "profile",
                "startup": "other",
                "common_startup": "other",
                "windows": "other",
            }[known.kind]
            matches.append(
                _RootMatch(
                    root=root,
                    category=category,
                    confidence="known_root",
                    basis=(
                        f"The normalized path is within a captured {known.kind} root; "
                        "this is a lexical location hint, not an ACL or trust decision."
                    ),
                )
            )

        conventional: tuple[tuple[str, Literal["temp", "appdata"]], ...] = ()
        source = ""
        if known.kind == "profile":
            conventional = (
                (ntpath.join(root, "appdata", "local", "temp"), "temp"),
                (ntpath.join(root, "appdata", "local"), "appdata"),
                (ntpath.join(root, "appdata", "roaming"), "appdata"),
                (ntpath.join(root, "appdata", "locallow"), "appdata"),
            )
            source = "profile"
        elif known.kind == "windows":
            conventional = ((ntpath.join(root, "temp"), "temp"),)
            source = "Windows"
        for conventional_root, category in conventional:
            if _contains(conventional_root, path):
                matches.append(
                    _RootMatch(
                        root=conventional_root,
                        category=category,
                        confidence="conventional_pattern",
                        basis=(
                            f"The normalized path follows a conventional {category} "
                            f"location under a captured {source} root; this is a lexical "
                            "hint, not an ACL or trust decision."
                        ),
                    )
                )
    return matches


def classify_path(
    path: str, context: PathContext, owner_sid: str | None = None
) -> PathAssessment:
    """Classify a path using captured endpoint roots and Windows lexical rules."""
    context = PathContext.model_validate(context)
    unquoted, issue = _strip_paired_quotes(path)
    if issue:
        return _unknown(issue)
    assert unquoted is not None

    expanded, issue = _expand_variables(unquoted, context, owner_sid)
    if issue:
        return _unknown(issue)
    assert expanded is not None

    normalized, issue = _normalize_absolute(expanded)
    if issue:
        return _unknown(issue)
    assert normalized is not None

    matches = _root_matches(context, normalized)
    if matches:
        longest = max(len(item.root) for item in matches)
        contenders = [item for item in matches if len(item.root) == longest]
        temp_contenders = [item for item in contenders if item.category == "temp"]
        if temp_contenders:
            contenders = temp_contenders
        else:
            categories = sorted({item.category for item in contenders})
            if len(categories) > 1:
                return PathAssessment(
                    category="unknown",
                    normalized_path=normalized,
                    confidence="unresolved",
                    basis=(
                        "Conflicting captured root categories apply at the same "
                        f"specificity ({', '.join(categories)}); the lexical "
                        "classification is unresolved."
                    ),
                )
        selected = min(
            contenders,
            key=lambda item: (
                item.confidence != "known_root",
                item.basis.casefold(),
            ),
        )
        return PathAssessment(
            category=selected.category,
            normalized_path=normalized,
            confidence=selected.confidence,
            basis=selected.basis,
        )
    return PathAssessment(
        category="other",
        normalized_path=normalized,
        confidence="conventional_pattern",
        basis=(
            "No recognized captured root contains the normalized path; this confidence "
            "label only denotes a lexical fallback, and no ACL or trust conclusion is "
            "available."
        ),
    )
