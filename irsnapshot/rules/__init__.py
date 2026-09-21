"""The explicit, versioned offline rule catalog."""
from irsnapshot.rules.process_rules import PROCESS_RULES
from irsnapshot.rules.persistence_rules import PERSISTENCE_RULES

DEFAULT_RULES = PROCESS_RULES + PERSISTENCE_RULES

__all__ = ['DEFAULT_RULES']
