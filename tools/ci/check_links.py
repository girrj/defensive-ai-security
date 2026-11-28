#!/usr/bin/env python3
"""Check repository-relative Markdown links (Markdown 상대 링크 검사)."""

from html.parser import HTMLParser
from pathlib import Path
import posixpath
import subprocess
import sys
import unicodedata
from urllib.parse import unquote, urlsplit

from markdown_it import MarkdownIt


MARKDOWN_SUFFIXES = {".md", ".markdown"}
MARKDOWN = MarkdownIt("commonmark").enable(["table", "strikethrough"])


class HtmlLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.anchors = set()
        self.links = []

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if fields.get("id"):
            self.anchors.add(fields["id"])
        if tag == "a" and fields.get("name"):
            self.anchors.add(fields["name"])
        destination = fields.get({"a": "href", "img": "src"}.get(tag))
        if destination:
            self.links.append(destination)


def heading_anchor(title, used):
    slug = "".join(
        "-" if char == " " else char
        for char in title.strip().lower()
        if char in " _-" or unicodedata.category(char)[0] in "LMN"
    )
    anchor = slug
    suffix = 1
    while anchor in used:
        anchor = f"{slug}-{suffix}"
        suffix += 1
    used.add(anchor)


def read_markdown(path):
    tokens = MARKDOWN.parse(path.read_text(encoding="utf-8-sig"))
    headings, custom_anchors, links = set(), set(), []
    line = 1
    for index, token in enumerate(tokens):
        if token.map:
            line = token.map[0] + 1
        if token.type == "heading_open":
            children = tokens[index + 1].children or []
            title = "".join(
                item.content if item.type != "image" else item.attrGet("alt") or item.content
                for item in children
                if item.type in {"text", "code_inline", "image"}
            )
            heading_anchor(title, headings)

        for item in token.children or [token]:
            if item.type in {"link_open", "image"}:
                attribute = "href" if item.type == "link_open" else "src"
                links.append((line, item.attrGet(attribute) or ""))
            if item.type in {"html_block", "html_inline"}:
                parser = HtmlLinks()
                parser.feed(item.content)
                parser.close()
                custom_anchors.update(parser.anchors)
                links.extend((line, destination) for destination in parser.links)
    return headings | custom_anchors, links


def link_problem(source, location, files, directories, documents):
    path = unquote(location.path)
    target = source
    if path:
        target = posixpath.normpath(
            path.lstrip("/") if path.startswith("/") else
            posixpath.join(posixpath.dirname(source), path)
        )
        if target not in files and target not in directories:
            return "missing repository path"
        if path.endswith("/") and target not in directories:
            return "expected a directory"

    fragment = unquote(location.fragment)
    if fragment and target in directories:
        readme = posixpath.join(target, "README.md")
        target = posixpath.normpath(readme)
        if target not in documents:
            return "directory has no Markdown README for the anchor"
    if fragment and target in documents and fragment not in documents[target][0]:
        return "missing Markdown anchor"
    return None


def main():
    root = Path(subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], text=True
    ).rstrip("\n"))
    names = subprocess.check_output([
        "git", "-C", str(root), "ls-files", "-z",
        "--cached", "--others", "--exclude-standard",
    ])
    files = {
        name for name in names.decode("utf-8").split("\0")
        if name and ((root / name).is_file() or (root / name).is_symlink())
    }
    directories = {".", *(parent.as_posix() for name in files for parent in Path(name).parents)}
    documents = {
        name: read_markdown(root / name)
        for name in sorted(files)
        if Path(name).suffix.lower() in MARKDOWN_SUFFIXES and not (root / name).is_symlink()
    }

    checked = failed = 0
    for source, (_, links) in documents.items():
        for line, url in links:
            location = urlsplit(url)
            if location.scheme or location.netloc or url.startswith("//"):
                continue
            checked += 1
            problem = link_problem(source, location, files, directories, documents)
            if problem:
                print(f"{source}:{line}: {problem}: {url!r}", file=sys.stderr)
                failed += 1

    print(f"Checked {checked} relative links in {len(documents)} Markdown files, {failed} broken.")
    return int(failed > 0)


if __name__ == "__main__":
    sys.exit(main())
