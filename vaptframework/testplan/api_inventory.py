"""API endpoint inventory + test-spec generation for the dynamic round.

Two sources of truth:
  * ``extract_from_source`` — static AST parse of a FastAPI ``routes`` directory. Works
    offline (we have the source) and records each endpoint's method, full path, auth
    requirement, and path params.
  * ``load_from_openapi`` — parse a running app's ``/openapi.json`` (most accurate; use at
    runtime against the authorized staging target).

``build_api_tests`` turns an inventory into concrete ``api_tests`` specs the ``api`` scanner
runs, prioritizing checks that are *runnable without pre-seeded object IDs*:
  * **unauth** — every non-public endpoint must reject anonymous access (needs only a target),
  * **BFLA** — a low-privilege identity must be denied privileged endpoints (needs only a
    ``user`` token),
  * **BOLA** — templates for endpoints with a path ID (need a victim object id filled in).
"""
from __future__ import annotations

import ast
import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Optional

API_V1_PREFIX_DEFAULT = "/api/v1"

# FastAPI dependency name -> normalized auth level
AUTH_BY_DEP = {
    "_admin": "admin",
    "get_current_user": "authenticated",
    "_owner": "owner",
    "_staff": "staff",
    "_provider": "provider",
    "_brand_owner": "brand_owner",
    "get_optional_user": "optional",
}
# Which auth levels are "privileged" (a plain user must be denied) -> BFLA candidates
PRIVILEGED = {"admin", "owner", "staff", "provider", "brand_owner"}
_METHODS = {"get", "post", "put", "patch", "delete"}
_PATH_PARAM = re.compile(r"\{([^}:]+)(?::[^}]+)?\}")


@dataclass
class Endpoint:
    method: str
    path: str
    auth: str = "public"
    path_params: list[str] = field(default_factory=list)
    source: str = ""
    tags: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _router_prefixes(tree: ast.Module) -> dict[str, str]:
    """Map router variable name -> its APIRouter(prefix=...) value."""
    prefixes: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            call = node.value
            fn = call.func
            is_router = (isinstance(fn, ast.Name) and fn.id == "APIRouter") or (
                isinstance(fn, ast.Attribute) and fn.attr == "APIRouter")
            if not is_router:
                continue
            prefix = ""
            for kw in call.keywords:
                if kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
                    prefix = kw.value.value or ""
            for target in node.targets:
                if isinstance(target, ast.Name):
                    prefixes[target.id] = prefix
    return prefixes


def _dep_names_from_call(call: ast.Call) -> list[str]:
    names = []
    for arg in call.args:
        if isinstance(arg, ast.Name):
            names.append(arg.id)
    return names


def _auth_from_function(func: ast.AST, decorator: ast.Call) -> str:
    found = set()
    # 1) decorator dependencies=[Depends(x), ...]
    for kw in decorator.keywords:
        if kw.arg == "dependencies" and isinstance(kw.value, (ast.List, ast.Tuple)):
            for el in kw.value.elts:
                if isinstance(el, ast.Call) and getattr(el.func, "id", "") == "Depends":
                    found.update(_dep_names_from_call(el))
    # 2) function parameter defaults: param = Depends(dep)
    args = getattr(func, "args", None)
    if args is not None:
        for default in list(args.defaults) + list(args.kw_defaults or []):
            if isinstance(default, ast.Call) and getattr(default.func, "id", "") == "Depends":
                found.update(_dep_names_from_call(default))
    levels = {AUTH_BY_DEP[n] for n in found if n in AUTH_BY_DEP}
    for level in ("admin", "owner", "brand_owner", "provider", "staff", "authenticated", "optional"):
        if level in levels:
            return level
    return "public"


def extract_from_source(routes_dir: str, api_prefix: str = API_V1_PREFIX_DEFAULT) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    if not os.path.isdir(routes_dir):
        return endpoints
    for fn in sorted(os.listdir(routes_dir)):
        if not fn.endswith(".py") or fn == "__init__.py":
            continue
        fpath = os.path.join(routes_dir, fn)
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                tree = ast.parse(fh.read(), filename=fpath)
        except SyntaxError:
            continue
        prefixes = _router_prefixes(tree)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)):
                    continue
                method = dec.func.attr.lower()
                router_var = getattr(dec.func.value, "id", None)
                if method not in _METHODS or router_var not in prefixes:
                    continue
                if not dec.args or not isinstance(dec.args[0], ast.Constant):
                    continue
                route_path = dec.args[0].value or ""
                full = api_prefix + prefixes[router_var] + route_path
                full = re.sub(r"/+", "/", full)
                if full.endswith("/") and len(full) > 1:
                    full = full.rstrip("/")
                endpoints.append(Endpoint(
                    method=method.upper(),
                    path=full,
                    auth=_auth_from_function(node, dec),
                    path_params=_PATH_PARAM.findall(route_path),
                    source=f"{fn}:{node.name}",
                ))
    return endpoints


def load_from_openapi(spec: dict, api_prefix: str = "") -> list[Endpoint]:
    """Parse a FastAPI /openapi.json document into endpoints."""
    endpoints: list[Endpoint] = []
    for path, methods in (spec.get("paths") or {}).items():
        for method, op in methods.items():
            if method.lower() not in _METHODS:
                continue
            auth = "authenticated" if op.get("security") else "public"
            endpoints.append(Endpoint(
                method=method.upper(),
                path=api_prefix + path,
                auth=auth,
                path_params=_PATH_PARAM.findall(path),
                tags=",".join(op.get("tags", []) or []),
                source="openapi",
            ))
    return endpoints


def build_api_tests(endpoints: list[Endpoint], base_url: str = "${TARGET}") -> list[dict]:
    """Generate api_tests specs. GET/HEAD only by default (non-destructive)."""
    specs: list[dict] = []
    n = 0
    for ep in endpoints:
        if ep.method not in ("GET", "HEAD"):
            continue  # mutating verbs need destructive authorization; keep prep read-only
        protected = ep.auth not in ("public", "optional")
        if not protected:
            continue
        url = base_url + ep.path
        # unauth check (runnable with only a target)
        n += 1
        specs.append({
            "name": f"unauth {ep.method} {ep.path}",
            "url": url, "method": ep.method, "protected": True,
            "check": "unauth", "auth_required": ep.auth, "source": ep.source,
        })
        # BFLA: a plain user must be denied privileged endpoints (runnable with a user token)
        if ep.auth in PRIVILEGED:
            specs.append({
                "name": f"BFLA {ep.auth} {ep.method} {ep.path}",
                "url": url, "method": ep.method, "protected": True,
                "check": "bfla", "forbidden_identity": "user", "auth_required": ep.auth,
                "source": ep.source,
            })
        # BOLA template: endpoints addressing an object by id (need a victim id filled in)
        if ep.path_params and ep.auth in ("authenticated", "owner"):
            specs.append({
                "name": f"BOLA {ep.method} {ep.path}",
                "url": url, "method": ep.method, "protected": True,
                "check": "bola", "attacker_identity": "userB", "path_params": ep.path_params,
                "note": "Fill path params with a VICTIM (userA/dealerA) object id before running.",
                "source": ep.source,
            })
    return specs


def summarize(endpoints: list[Endpoint]) -> dict:
    by_auth: dict[str, int] = {}
    by_method: dict[str, int] = {}
    for ep in endpoints:
        by_auth[ep.auth] = by_auth.get(ep.auth, 0) + 1
        by_method[ep.method] = by_method.get(ep.method, 0) + 1
    return {"total": len(endpoints), "by_auth": by_auth, "by_method": by_method}
