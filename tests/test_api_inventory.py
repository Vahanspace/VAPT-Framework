import os
import textwrap

from vaptframework.testplan.api_inventory import (
    extract_from_source, load_from_openapi, build_api_tests, summarize, Endpoint,
)


def _write(tmp_path, name, code):
    d = tmp_path / "routes"
    d.mkdir(exist_ok=True)
    (d / name).write_text(textwrap.dedent(code), encoding="utf-8")
    return str(d)


def test_extract_paths_prefix_and_auth(tmp_path):
    routes = _write(tmp_path, "vehicles.py", '''
        from fastapi import APIRouter, Depends
        router = APIRouter(prefix="/vehicles", tags=["vehicles"])

        @router.get("")
        def list_vehicles(db=Depends(get_db)):
            ...

        @router.get("/{vehicle_id}")
        def get_vehicle(vehicle_id: int, user=Depends(get_current_user)):
            ...

        @router.delete("/{vehicle_id}", status_code=204)
        def delete_vehicle(vehicle_id: int, _=Depends(_admin)):
            ...
    ''')
    eps = extract_from_source(routes, api_prefix="/api/v1")
    by_path = {(e.method, e.path): e for e in eps}
    assert ("GET", "/api/v1/vehicles") in by_path
    assert by_path[("GET", "/api/v1/vehicles")].auth == "public"
    got = by_path[("GET", "/api/v1/vehicles/{vehicle_id}")]
    assert got.auth == "authenticated"
    assert got.path_params == ["vehicle_id"]
    assert by_path[("DELETE", "/api/v1/vehicles/{vehicle_id}")].auth == "admin"


def test_decorator_dependencies_detected(tmp_path):
    routes = _write(tmp_path, "admin.py", '''
        from fastapi import APIRouter, Depends
        router = APIRouter(prefix="/admin")

        @router.get("/metrics", dependencies=[Depends(_admin)])
        def metrics():
            ...
    ''')
    eps = extract_from_source(routes, api_prefix="/api/v1")
    assert eps[0].auth == "admin"
    assert eps[0].path == "/api/v1/admin/metrics"


def test_build_api_tests_generates_unauth_bfla_bola():
    eps = [
        Endpoint("GET", "/api/v1/admin/users", auth="admin"),
        Endpoint("GET", "/api/v1/vehicles/{id}", auth="authenticated", path_params=["id"]),
        Endpoint("GET", "/api/v1/vehicles", auth="public"),
        Endpoint("POST", "/api/v1/vehicles", auth="authenticated"),  # mutating -> skipped
    ]
    specs = build_api_tests(eps, base_url="https://staging.example")
    checks = {s["check"] for s in specs}
    assert "unauth" in checks and "bfla" in checks and "bola" in checks
    # public endpoint produces no spec; POST is skipped (read-only prep)
    assert all("/vehicles" != s["url"].split("staging.example")[1] for s in specs)
    assert all(s["method"] in ("GET", "HEAD") for s in specs)
    bfla = next(s for s in specs if s["check"] == "bfla")
    assert bfla["forbidden_identity"] == "user"


def test_load_from_openapi():
    spec = {"paths": {
        "/vehicles/{id}": {"get": {"security": [{"OAuth2": []}], "tags": ["vehicles"]}},
        "/health": {"get": {}},
    }}
    eps = load_from_openapi(spec, api_prefix="/api/v1")
    d = {(e.method, e.path): e for e in eps}
    assert d[("GET", "/api/v1/vehicles/{id}")].auth == "authenticated"
    assert d[("GET", "/api/v1/health")].auth == "public"


def test_summarize():
    eps = [Endpoint("GET", "/a", auth="admin"), Endpoint("POST", "/b", auth="public")]
    s = summarize(eps)
    assert s["total"] == 2
    assert s["by_auth"]["admin"] == 1
    assert s["by_method"]["POST"] == 1
