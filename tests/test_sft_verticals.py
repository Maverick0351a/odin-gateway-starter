
from odin_core.sft import transform_payload


def test_health_observation_vendor_to_fhir():
    payload = {
        "observation_id": "obs123",
        "code": "heart-rate",
        "value": 72,
        "unit": "bpm",
        "patient_id": "pat9",
        "effective_at": "2024-05-01T10:00:00Z",
    }
    out, meta = transform_payload(payload, "health.observation.vendor.v1", "fhir.observation.v1")
    assert out["resourceType"] == "Observation"
    assert out["id"] == "obs123"
    assert out["valueQuantity"]["value"] == 72
    assert meta["fields_mapped"]


def test_health_patient_vendor_to_fhir():
    payload = {
        "patient_id": "pat9",
        "name": "Ada Lovelace",
        "gender": "female",
        "birth_date": "1815-12-10",
    }
    out, meta = transform_payload(payload, "health.patient.vendor.v1", "fhir.patient.v1")
    assert out["resourceType"] == "Patient"
    assert out["id"] == "pat9"
    assert out["name"][0]["text"] == "Ada Lovelace"
    assert "patient_id->id" in meta["fields_mapped"][0]


def test_insurance_claim_notice():
    payload = {
        "claim_number": "CLM-77",
        "loss_date": "2024-01-02",
        "insured_name": "Contoso LLC",
        "description": "Minor water damage",
    }
    out, meta = transform_payload(payload, "insurance.claim_notice.vendor.v1", "acord.claim_notice.v1")
    cn = out["ClaimNotice"]
    assert cn["ClaimNumber"] == "CLM-77"
    assert cn["Insured"]["Name"] == "Contoso LLC"
    assert any("claim_number" in m for m in meta["fields_mapped"])


def test_procurement_three_way_match():
    payload = {
        "po": {"id": "PO1", "amount": 100.0},
        "gr": {"id": "GR1", "amount": 100.0},
        "invoice": {"id": "INV1", "amount": 100.0},
    }
    out, meta = transform_payload(payload, "procurement.match.vendor.v1", "procurement.match.v1")
    twm = out["three_way_match"]
    assert twm["po"]["id"] == "PO1"
    assert twm["amounts_consistent"] is True
    assert meta["consistency"] is True


def test_procurement_three_way_match_inconsistent():
    payload = {
        "po": {"id": "PO1", "amount": 100.0},
        "gr": {"id": "GR1", "amount": 90.0},
        "invoice": {"id": "INV1", "amount": 100.0},
    }
    out, meta = transform_payload(payload, "procurement.match.vendor.v1", "procurement.match.v1")
    assert out["three_way_match"]["amounts_consistent"] is False
    assert meta["consistency"] is False
