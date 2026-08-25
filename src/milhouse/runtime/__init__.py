"""W05 runtime: the collector registry, per-run context/result, and the mode-aware pipeline.

The runtime turns configured collectors into durable records by enforcing the G05 ordering
``collect -> validate -> redact -> spool [-> export]``. A collector returns drafts; the pipeline
redacts them strictly before assigning identity, commits them through the durable spool under the
commit barrier, and (in ``full`` mode) drives the existing exactly-once-logical export tail. This
package wires nothing into the CLI — command wiring is W06.
"""

from __future__ import annotations

from milhouse.runtime.alerting import (
    CANARY_STATE_RULE_VERSION,
    AlertEvaluation,
    AlertOutcome,
    AlertRuleSpec,
    AlertStateUpdate,
    evaluate_canary_state_rule,
)
from milhouse.runtime.context import CollectorContext
from milhouse.runtime.errors import PipelineError, RegistryError
from milhouse.runtime.pipeline import (
    CollectorRunSummary,
    PipelineRunSummary,
    RuntimeMode,
    RuntimePipeline,
)
from milhouse.runtime.registry import Collector, CollectorFactory, CollectorRegistry
from milhouse.runtime.result import CollectorResult, CollectorStatus

__all__ = [
    "CANARY_STATE_RULE_VERSION",
    "AlertEvaluation",
    "AlertOutcome",
    "AlertRuleSpec",
    "AlertStateUpdate",
    "Collector",
    "CollectorContext",
    "CollectorFactory",
    "CollectorRegistry",
    "CollectorResult",
    "CollectorRunSummary",
    "CollectorStatus",
    "PipelineError",
    "PipelineRunSummary",
    "RegistryError",
    "RuntimeMode",
    "RuntimePipeline",
    "evaluate_canary_state_rule",
]
