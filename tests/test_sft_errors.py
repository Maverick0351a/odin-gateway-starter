import sys, pathlib, json
from datetime import datetime, timezone

PKG_DIR = pathlib.Path(__file__).resolve().parents[1] / 'packages'
if str(PKG_DIR) not in sys.path:
    sys.path.insert(0, str(PKG_DIR))

from odin_core.sft import transform_payload, SFTError  # noqa


def test_transform_same_type_short_circuit():
    payload = {"a": 1}
    out, notes = transform_payload(payload, 'x.v1', 'x.v1')
    assert out is payload
    assert notes.get('notes') == 'already_normalized'


def test_transform_unknown_mapping():
    try:
        transform_payload({}, 'no.such', 'target.v1')
    except SFTError as e:
        assert 'No SFT transformer' in str(e)
    else:
        assert False, 'expected SFTError'


def test_openai_tooluse_missing_tool_calls():
    from odin_core import sft as sft_mod
    fn = sft_mod._REGISTRY[("openai.tooluse.invoice.v1", "invoice.iso20022.v1")]
    try:
        fn({"tool_calls": []})
    except Exception as e:
        assert 'No tool_calls' in str(e)
    else:
        assert False, 'expected error'


def test_claude_tooluse_missing_args():
    from odin_core import sft as sft_mod
    fn = sft_mod._REGISTRY[("claude.tooluse.invoice.v1", "invoice.iso20022.v1")]
    try:
        fn({"tool_calls": []})
    except Exception as e:
        assert 'No tool_use arguments' in str(e)
    else:
        assert False, 'expected error'


def test_reverse_iso_missing_txs():
    from odin_core import sft as sft_mod
    fn = sft_mod._REGISTRY[("invoice.iso20022.v1", "openai.tooluse.invoice.v1")]
    try:
        fn({"Document": {"FIToFICstmrCdtTrf": {"GrpHdr": {}, "CdtTrfTxInf": []}}})
    except Exception as e:
        assert 'Missing CdtTrfTxInf' in str(e)
    else:
        assert False, 'expected error'
