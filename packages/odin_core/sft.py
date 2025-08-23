import json
from typing import Any, Callable, Dict, Tuple, TypeVar


class SFTError(Exception):
    pass

# Simple registry for semantic format transformations
# key: (from_type, to_type) -> transformer(payload) -> (new_payload, notes)
TransformFn = Callable[[Dict[str, Any]], Tuple[Dict[str, Any], Dict[str, Any]]]
_REGISTRY: Dict[tuple[str, str], TransformFn] = {}

F = TypeVar("F", bound=TransformFn)

def sft(from_type: str, to_type: str) -> Callable[[F], F]:
    def decorator(fn: F) -> F:
        _REGISTRY[(from_type, to_type)] = fn
        return fn
    return decorator

# ---------------------------
# Common helper used by all mappers
# ---------------------------
def _map_invoice_to_iso20022(args: Dict[str, Any], created_at: str | None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    mapped = {
        "Document": {
            "FIToFICstmrCdtTrf": {
                "GrpHdr": {
                    "MsgId": args.get("invoice_id"),
                    "CreDtTm": created_at,
                },
                "CdtTrfTxInf": [{
                    "Amt": {"InstdAmt": {"ccy": args.get("currency", "USD"), "value": args.get("amount")}},
                    "Cdtr": {"Nm": args.get("customer_name")},
                    "RmtInf": {"Ustrd": [args.get("description", "")]},
                }],
            }
        }
    }
    notes = {"fields_mapped": ["invoice_id->MsgId", "amount->InstdAmt", "customer_name->Cdtr.Nm"]}
    return mapped, notes

# ---------------------------
# 1) Vendor → ISO20022
# ---------------------------
@sft("invoice.vendor.v1", "invoice.iso20022.v1")
def _vendor_to_iso20022(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    return _map_invoice_to_iso20022(payload, payload.get("created_at"))

# ---------------------------
# 2) OpenAI tool-use → ISO20022
#    Expects OpenAI-style tool_calls with arguments as JSON string.
# ---------------------------
@sft("openai.tooluse.invoice.v1", "invoice.iso20022.v1")
def _openai_tooluse_invoice_to_iso20022(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    try:
        tool_calls = payload.get("tool_calls", [])
        if not tool_calls:
            raise SFTError("No tool_calls found")

        # Assume first tool_call is the invoice function
        func = tool_calls[0].get("function", {})
        args_json = func.get("arguments")
        if isinstance(args_json, str):
            args = json.loads(args_json)
        elif isinstance(args_json, dict):
            args = args_json
        else:
            raise SFTError("Function arguments missing")

        return _map_invoice_to_iso20022(args, payload.get("created_at"))
    except Exception as e:
        raise SFTError(f"Failed to map openai.tooluse.invoice.v1: {e}")

# ---------------------------
# 3) Claude tool-use → ISO20022
#    Supports both string and dict arguments for parity.
# ---------------------------
@sft("claude.tooluse.invoice.v1", "invoice.iso20022.v1")
def _claude_tooluse_invoice_to_iso20022(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    try:
        # Newer shape: tool_calls (parity with OpenAI)
        tool_calls = payload.get("tool_calls", [])
        args = None
        if tool_calls:
            call = tool_calls[0]
            func = call.get("function", {}) or call
            args_json = func.get("arguments")
            if isinstance(args_json, str):
                args = json.loads(args_json)
            elif isinstance(args_json, dict):
                args = args_json
        # Legacy Anthropic shape: content list with tool_use entries
        if args is None:
            for item in payload.get("content", []):
                if item.get("type") == "tool_use":
                    tool_input = item.get("input")
                    if isinstance(tool_input, dict):
                        args = tool_input
                        break
        if args is None:
            raise SFTError("No tool_use arguments found")
        return _map_invoice_to_iso20022(args, payload.get("created_at"))
    except Exception as e:
        raise SFTError(f"Failed to map claude.tooluse.invoice.v1: {e}")

def transform_payload(payload: Dict[str, Any], payload_type: str, target_type: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    if payload_type == target_type:
        return payload, {"notes": "already_normalized"}
    key = (payload_type, target_type)
    fn = _REGISTRY.get(key)
    if fn is None:
        raise SFTError(f"No SFT transformer registered for {payload_type} -> {target_type}")
    return fn(payload)

# ---------------------------
# 4) ISO20022 → OpenAI tool-use (reverse mapping for audit / round-trip demo)
# ---------------------------
@sft("invoice.iso20022.v1", "openai.tooluse.invoice.v1")
def _iso20022_back_to_openai(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    try:
        doc = payload.get("Document", {})
        main = doc.get("FIToFICstmrCdtTrf", {})
        grp = main.get("GrpHdr", {})
        txs = main.get("CdtTrfTxInf", [])
        if not txs:
            raise SFTError("Missing CdtTrfTxInf array")
        first = txs[0]
        amt = first.get("Amt", {}).get("InstdAmt", {})
        creditor = first.get("Cdtr", {})
        rmt = first.get("RmtInf", {}).get("Ustrd", [])
        args = {
            "invoice_id": grp.get("MsgId"),
            "amount": amt.get("value"),
            "currency": amt.get("ccy"),
            "customer_name": creditor.get("Nm"),
            "description": rmt[0] if rmt else None,
        }
        created_at = grp.get("CreDtTm")
        tool_payload = {
            "tool_calls": [{
                "type": "function",
                "function": {
                    "name": "create_invoice",
                    "arguments": json.dumps({k: v for k, v in args.items() if v is not None})
                }
            }],
            "created_at": created_at,
        }
        notes = {"fields_mapped": ["MsgId->invoice_id", "InstdAmt->amount", "Cdtr.Nm->customer_name"], "reverse": True}
        return tool_payload, notes
    except Exception as e:
        raise SFTError(f"Failed to map invoice.iso20022.v1 -> openai.tooluse.invoice.v1: {e}")

# ---------------------------
# 5) Healthcare: FHIR Observation (vendor) -> fhir.observation.v1
# Minimal subset mapping (example fields): id, code, value, unit, subject (patient id), effectiveDateTime
# ---------------------------
@sft("health.observation.vendor.v1", "fhir.observation.v1")
def _vendor_obs_to_fhir(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    try:
        fhir = {
            "resourceType": "Observation",
            "id": payload.get("observation_id"),
            "code": {"text": payload.get("code")},
            "valueQuantity": {
                "value": payload.get("value"),
                "unit": payload.get("unit"),
            },
            "subject": {"reference": f"Patient/{payload.get('patient_id')}"},
            "effectiveDateTime": payload.get("effective_at"),
        }
        notes = {"fields_mapped": ["observation_id->id", "code->code.text", "value->valueQuantity.value", "patient_id->subject.reference"]}
        return fhir, notes
    except Exception as e:
        raise SFTError(f"Failed to map health.observation.vendor.v1: {e}")

@sft("health.patient.vendor.v1", "fhir.patient.v1")
def _vendor_patient_to_fhir(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    try:
        fhir = {
            "resourceType": "Patient",
            "id": payload.get("patient_id"),
            "name": [{"text": payload.get("name")}],
            "gender": payload.get("gender"),
            "birthDate": payload.get("birth_date"),
        }
        notes = {"fields_mapped": ["patient_id->id", "name->name[0].text"]}
        return fhir, notes
    except Exception as e:
        raise SFTError(f"Failed to map health.patient.vendor.v1: {e}")

# ---------------------------
# 6) Insurance: ACORD claim notice vendor -> acord.claim_notice.v1 (simplified subset)
# ---------------------------
@sft("insurance.claim_notice.vendor.v1", "acord.claim_notice.v1")
def _vendor_claim_notice(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    try:
        acord = {
            "ClaimNotice": {
                "ClaimNumber": payload.get("claim_number"),
                "LossDate": payload.get("loss_date"),
                "Insured": {"Name": payload.get("insured_name")},
                "LossDescription": payload.get("description"),
            }
        }
        notes = {"fields_mapped": ["claim_number->ClaimNumber", "insured_name->Insured.Name"]}
        return acord, notes
    except Exception as e:
        raise SFTError(f"Failed to map insurance.claim_notice.vendor.v1: {e}")

# ---------------------------
# 7) Procurement: 3-way match skeleton (PO, receipt, invoice) -> procurement.match.v1
# Input expects keys: po{ id, amount }, gr{ id, amount }, invoice{ id, amount }
# ---------------------------
@sft("procurement.match.vendor.v1", "procurement.match.v1")
def _vendor_three_way_match(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    try:
        po = payload.get("po", {})
        gr = payload.get("gr", {})
        inv = payload.get("invoice", {})
        match = {
            "three_way_match": {
                "po": {"id": po.get("id"), "amount": po.get("amount")},
                "goods_receipt": {"id": gr.get("id"), "amount": gr.get("amount")},
                "invoice": {"id": inv.get("id"), "amount": inv.get("amount")},
                "amounts_consistent": all(
                    a is not None and a == po.get("amount") for a in [gr.get("amount"), inv.get("amount")]
                ),
            }
        }
        notes = {"fields_mapped": ["po.id->three_way_match.po.id", "invoice.id->three_way_match.invoice.id"], "consistency": match["three_way_match"]["amounts_consistent"]}
        return match, notes
    except Exception as e:
        raise SFTError(f"Failed to map procurement.match.vendor.v1: {e}")
