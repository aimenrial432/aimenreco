#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class AimenrecoException(Exception):
    """Base exception for all Aimenreco errors."""
    pass

class UserAbortException(AimenrecoException):
    """Custom exception to handle Ctrl+C (SIGINT) gracefully across all modules."""
    pass

class NetworkError(AimenrecoException):
    """Raised when a critical connectivity issue occurs."""
    pass