from dataclasses import dataclass
from enum import Enum

class State(Enum):
    OK = 0
    WARN = 1
    CRIT = 2
    UNKNOWN = 3

@dataclass
class Result:
    state: State
    summary: str
    details: str | None = None

class Service:
    pass

class Metric:
    def __init__(self, name: str, value: int | float):
        self.name = name
        self.value = value

class AgentSection:
    def __init__(self, *args, **kwargs):
        pass

class CheckPlugin:
    def __init__(self, *args, **kwargs):
        pass
