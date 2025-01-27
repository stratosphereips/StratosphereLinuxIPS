# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from collections import defaultdict
from typing import (
    Dict,
    Tuple,
    Optional,
)


class TrieNode:
    def __init__(self):
        self.children = defaultdict(TrieNode)
        self.is_end_of_word = False
        self.domain_info = (
            None  # store associated domain information if needed
        )


class Trie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, domain: str, domain_info: str):
        """Insert a domain into the trie (using domain parts not chars)."""
        node = self.root
        parts = domain.split(".")[::-1]  # reverse to handle subdomains
        for part in parts:
            node = node.children[part]
        node.is_end_of_word = True
        node.domain_info = domain_info

    def search(self, domain: str) -> Tuple[bool, Optional[Dict[str, str]]]:
        """
        Check if a domain or its subdomain exists in the trie
         (using domain parts instead of characters).
        Returns a tuple (found, domain_info).
        """
        node = self.root
        # reverse domain to handle subdomains
        parts = domain.split(".")[::-1]
        for part in parts:
            if part not in node.children:
                return False, None

            node = node.children[part]
            if node.is_end_of_word:
                return True, node.domain_info
        return False, None
