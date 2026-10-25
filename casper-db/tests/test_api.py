from fastapi.testclient import TestClient

from casper_db.api import create_app


def test_read_only_api_contract_and_draft_gate(store, case_data):
    store.add(case_data)
    params = {key: case_data[key] for key in ("target_id", "endpoint", "method")}
    with TestClient(create_app(store.path)) as client:
        assert client.get("/cases", params=params).json() == []
        assert client.get("/cases", params={"target_id": "LAB-DEMO"}).json() == []
        assert client.get("/cases/CASE-001").status_code == 409
        store.update({**case_data, "status": "ready"})
        response = client.get("/cases", params=params)
        assert response.status_code == 200
        assert [case["case_id"] for case in response.json()] == ["CASE-001"]
        detailed = {**params, "parameter": "q", "parameter_location": "query"}
        assert [case["case_id"] for case in client.get("/cases", params=detailed).json()] == [
            "CASE-001"
        ]
        assert client.get(
            "/cases", params={**detailed, "parameter_location": "body"}
        ).json() == []
        prior = client.get("/cases", params={"target_id": "LAB-DEMO"})
        assert prior.status_code == 200
        assert prior.json()[0]["reported_on"] == case_data["reported_on"]
        assert prior.json()[0]["remediation"] == case_data["remediation"]
        detail = client.get("/cases/CASE-001")
        assert detail.status_code == 200
        assert detail.json()["payload"] == case_data["payload"]
        assert client.get("/cases/MISSING").status_code == 404
        assert client.get("/cases", params={**params, "method": "BAD"}).status_code == 422
        assert client.get("/cases", params={**params, "endpoint": "https://x/"}).status_code == 422
        assert client.get("/cases").status_code == 422
        incomplete = client.get("/cases", params={"target_id": "LAB-DEMO", "endpoint": "/search"})
        assert incomplete.status_code == 422
        assert client.post("/cases", json=case_data).status_code == 405
        assert client.delete("/cases/CASE-001").status_code == 405


def test_openapi_includes_the_team_data_contract(store):
    schema = create_app(store.path).openapi()
    assert set(schema["paths"]) == {"/cases", "/cases/{case_id}"}
    fields = schema["components"]["schemas"]["CaseRecord"]["properties"]
    assert {"procedure", "payload", "success_condition", "status"}.issubset(fields)
