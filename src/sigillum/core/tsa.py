# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""RFC 3161 timestamping client.

Wraps the TSA request/response cycle so signers can stay agnostic about which
TSA is used. The actual embedding of the token in the signature structure is
handled by endesive, which accepts a callable returning the TSA token bytes.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TSAConfig:
    url: str
    username: str | None = None
    password: str | None = None


class TSAClient:
    def __init__(self, config: TSAConfig):
        self.config = config

    def stamp(self, data_digest: bytes, hash_algo: str = "sha256") -> bytes:
        """Send an RFC 3161 TimeStampReq and return the TimeStampToken bytes."""
        raise NotImplementedError("TSA request/response not yet implemented")
