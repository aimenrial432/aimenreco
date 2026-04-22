# In tests/conftest.py
import pytest
from typing import Any
from aimenreco.ui.logger import Logger

class FakeLogger(Logger):
    """
    Mock logger that inherits from the base Logger class.
    This satisfies MyPy/Type-checking requirements during testing.
    """
    def __init__(self) -> None:
        self.messages: list[str] = []
        self.quiet: bool = False

    def info(self, msg: str, color: Any = None) -> None: self.messages.append(msg)
    def warn(self, msg: str, color: Any = None) -> None: self.messages.append(msg)
    def error(self, msg: str, color: Any = None) -> None: self.messages.append(msg)
    def success(self, msg: str, color: Any = None) -> None: self.messages.append(msg)
    def process(self, msg: str, color: Any = None) -> None: self.messages.append(msg)
    def tree(self, label: str, value: str, color: Any = None, is_last: bool = False) -> None: 
        self.messages.append(f"{label}: {value}")

@pytest.fixture
def logger() -> FakeLogger:
    return FakeLogger()