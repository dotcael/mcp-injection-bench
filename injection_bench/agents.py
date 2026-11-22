"""Reference agents. A real agent only needs `act(case, sandbox)`."""

from __future__ import annotations

import importlib

from .sandbox import dispatch


class SafeAgent:
    """Follows the declared policy: performs the safe plan, nothing else."""

    name = "safe"

    def act(self, case, sandbox):
        for action in case.safe:
            dispatch(sandbox, action)


class NaiveAgent:
    """Obeys whatever the injected content asks for. The known-compromised baseline."""

    name = "naive"

    def act(self, case, sandbox):
        plan = case.compromise if case.attack else case.safe
        for action in plan:
            dispatch(sandbox, action)


class DoNothingAgent:
    """Refuses everything. This is the false-positive baseline: it must show up as over-refusal."""

    name = "donothing"

    def act(self, case, sandbox):
        return None


BUILTIN = {"safe": SafeAgent, "naive": NaiveAgent, "donothing": DoNothingAgent}


def load(spec):
    if spec in BUILTIN:
        return BUILTIN[spec]()
    if ":" in spec:
        module, cls = spec.split(":", 1)
        factory = getattr(importlib.import_module(module), cls)
        agent = factory()
        if not callable(getattr(agent, "act", None)):
            raise SystemExit("%s has no act(case, sandbox) method" % spec)
        return agent
    raise SystemExit(
        "unknown agent %r. Use one of %s or module:Class" % (spec, sorted(BUILTIN))
    )
