#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional

class AimenrecoException(Exception):
    """
    Base exception class for all framework-specific errors.
    
    Acts as the root of the Aimenreco exception hierarchy to allow 
    global catching of tool-specific failures.
    """
    def __init__(self, message: str = "An unexpected error occurred in Aimenreco") -> None:
        self.message: str = message
        super().__init__(self.message)


class UserAbortException(AimenrecoException):
    """
    Custom exception to handle user-initiated interrupts (SIGINT/Ctrl+C).
    
    Used to propagate the abort signal from deep core modules up to 
    the CLI orchestrator for a graceful shutdown and cleanup.
    """
    def __init__(self, message: str = "Operation cancelled by the user") -> None:
        super().__init__(message)


class NetworkError(AimenrecoException):
    """
    Raised when a critical connectivity or protocol-level issue occurs.
    
    Args:
        message (str): Description of the network failure.
        status_code (Optional[int]): The HTTP status code if applicable.
    """
    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        self.status_code: Optional[int] = status_code
        super().__init__(message)


class WordlistError(AimenrecoException):
    """
    Raised when the wordlist is missing, inaccessible, or incorrectly formatted.
    """
    def __init__(self, message: str = "Critical error accessing the wordlist resource") -> None:
        super().__init__(message)