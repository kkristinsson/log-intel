from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from log_intel.syslogb.app import config

TokenKind = Literal["LPAREN", "RPAREN", "AND", "OR", "NOT", "TERM", "EOF"]


@dataclass(frozen=True)
class Token:
    kind: TokenKind
    value: str = ""


_KEYWORDS = {"AND", "OR", "NOT"}


def _tokenize(query: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    n = len(query)

    while i < n:
        ch = query[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "(":
            tokens.append(Token("LPAREN"))
            i += 1
            continue
        if ch == ")":
            tokens.append(Token("RPAREN"))
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            i += 1
            start = i
            while i < n and query[i] != quote:
                if query[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                i += 1
            if i >= n:
                raise ValueError("Unclosed quote in search query")
            tokens.append(Token("TERM", query[start:i]))
            i += 1
            continue

        j = i
        while j < n and not query[j].isspace() and query[j] not in "()":
            j += 1
        word = query[i:j]
        upper = word.upper()
        if upper in _KEYWORDS:
            tokens.append(Token(upper, upper))  # type: ignore[arg-type]
        else:
            tokens.append(Token("TERM", word))
        i = j

    tokens.append(Token("EOF"))
    return tokens


@dataclass
class TermNode:
    value: str


@dataclass
class NotNode:
    child: QueryNode


@dataclass
class AndNode:
    children: list[QueryNode]


@dataclass
class OrNode:
    children: list[QueryNode]


QueryNode = TermNode | NotNode | AndNode | OrNode


class QueryParser:
    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.pos = 0

    def parse(self) -> QueryNode:
        node = self._parse_or()
        if self._peek().kind != "EOF":
            tok = self._peek()
            raise ValueError(f"Unexpected token near '{tok.value or tok.kind}'")
        return node

    def _peek(self) -> Token:
        return self.tokens[self.pos]

    def _advance(self) -> Token:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def _match(self, kind: TokenKind) -> bool:
        if self._peek().kind == kind:
            self._advance()
            return True
        return False

    def _parse_or(self) -> QueryNode:
        nodes = [self._parse_and()]
        while self._match("OR"):
            nodes.append(self._parse_and())
        if len(nodes) == 1:
            return nodes[0]
        return OrNode(nodes)

    def _parse_and(self) -> QueryNode:
        nodes = [self._parse_not()]
        while True:
            if self._match("AND"):
                nodes.append(self._parse_not())
            elif self._implies_and():
                nodes.append(self._parse_not())
            else:
                break
        if len(nodes) == 1:
            return nodes[0]
        return AndNode(nodes)

    def _implies_and(self) -> bool:
        kind = self._peek().kind
        return kind in ("TERM", "LPAREN", "NOT")

    def _parse_not(self) -> QueryNode:
        if self._match("NOT"):
            return NotNode(self._parse_not())
        return self._parse_primary()

    def _parse_primary(self) -> QueryNode:
        if self._match("LPAREN"):
            node = self._parse_or()
            if not self._match("RPAREN"):
                raise ValueError("Missing closing parenthesis")
            return node
        tok = self._peek()
        if tok.kind != "TERM":
            raise ValueError(f"Expected search term, got '{tok.kind}'")
        self._advance()
        return TermNode(tok.value)


def parse_query(query: str) -> QueryNode:
    q = query.strip()
    if not q:
        raise ValueError("query required")
    return QueryParser(_tokenize(q)).parse()


def _term_in_line(term: str, line: str) -> bool:
    if config.SEARCH_CASE_SENSITIVE:
        return term in line
    return term.lower() in line.lower()


def line_matches(node: QueryNode, line: str) -> bool:
    if isinstance(node, TermNode):
        return _term_in_line(node.value, line)
    if isinstance(node, NotNode):
        return not line_matches(node.child, line)
    if isinstance(node, AndNode):
        return all(line_matches(child, line) for child in node.children)
    if isinstance(node, OrNode):
        return any(line_matches(child, line) for child in node.children)
    raise TypeError(f"Unknown node type: {type(node)!r}")


def collect_terms(node: QueryNode) -> list[str]:
    if isinstance(node, TermNode):
        return [node.value] if node.value else []
    if isinstance(node, NotNode):
        return collect_terms(node.child)
    if isinstance(node, AndNode):
        out: list[str] = []
        for child in node.children:
            out.extend(collect_terms(child))
        return out
    if isinstance(node, OrNode):
        out = []
        for child in node.children:
            out.extend(collect_terms(child))
        return out
    return []


def compile_text_query(query: str) -> tuple[QueryNode, list[str]]:
    ast = parse_query(query)
    terms = collect_terms(ast)
    # Preserve order, drop duplicates (case-sensitive key for display)
    seen: set[str] = set()
    unique: list[str] = []
    for t in terms:
        key = t if config.SEARCH_CASE_SENSITIVE else t.lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(t)
    return ast, unique
