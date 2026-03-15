from __future__ import annotations

import uuid
from typing import Any, Optional

from tcp.tcp import TCPClient, encode_string, iter_fields

from .base import PluginBase

MSG_ID_CS_FACTORY_QUERY_SHARED_BLUEPRINT = 262
MSG_ID_SC_FACTORY_QUERY_SHARED_BLUEPRINT = 249

FACTORY_BP_REVIEW_STATUS = {
    0: "Pending",
    1: "InProgress",
    2: "Approved",
}

FACTORY_BP_SOURCE_TYPE = {
    0: "FbstMine",
    1: "FbstSys",
    2: "FbstGift",
    3: "FbstPreset",
}


def _decode_text(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


def _parse_index_only(data: bytes) -> str:
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            return _decode_text(value)
    return ""


def _parse_vec3_int(data: bytes) -> dict[str, int]:
    out = {"x": 0, "y": 0, "z": 0}
    for field_no, wire, value in iter_fields(data):
        if wire != 0 or not isinstance(value, int):
            continue
        if field_no == 1:
            out["x"] = int(value)
        elif field_no == 2:
            out["y"] = int(value)
        elif field_no == 3:
            out["z"] = int(value)
    return out


def _parse_blueprint_size(data: bytes) -> dict[str, int]:
    out = {"x_len": 0, "z_len": 0}
    for field_no, wire, value in iter_fields(data):
        if wire != 0 or not isinstance(value, int):
            continue
        if field_no == 1:
            out["x_len"] = int(value)
        elif field_no == 2:
            out["z_len"] = int(value)
    return out


def _parse_blueprint_icon(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"icon": "", "base_color": 0}
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            out["icon"] = _decode_text(value)
        elif field_no == 2 and wire == 0 and isinstance(value, int):
            out["base_color"] = int(value)
    return out


def _parse_gift_blueprint_key(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "bp_uid": 0,
        "target_role_id": 0,
        "share_idx": 0,
    }
    for field_no, wire, value in iter_fields(data):
        if wire != 0 or not isinstance(value, int):
            continue
        if field_no == 1:
            out["bp_uid"] = int(value)
        elif field_no == 2:
            out["target_role_id"] = int(value)
        elif field_no == 3:
            out["share_idx"] = int(value)
    return out


def _parse_blueprint_param(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "source_type": 0,
        "source_type_name": FACTORY_BP_SOURCE_TYPE.get(0, "Unknown"),
        "payload_type": None,
        "payload": None,
    }
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 0 and isinstance(value, int):
            source_type = int(value)
            out["source_type"] = source_type
            out["source_type_name"] = FACTORY_BP_SOURCE_TYPE.get(source_type, f"Unknown({source_type})")
            continue

        if field_no == 11 and wire == 0 and isinstance(value, int):
            out["payload_type"] = "my_bp_uid"
            out["payload"] = int(value)
        elif field_no == 12 and wire == 2 and isinstance(value, bytes):
            out["payload_type"] = "sys_bp_key"
            out["payload"] = _decode_text(value)
        elif field_no == 13 and wire == 2 and isinstance(value, bytes):
            out["payload_type"] = "gift_bp_key"
            out["payload"] = _parse_gift_blueprint_key(value)
        elif field_no == 14 and wire == 2 and isinstance(value, bytes):
            out["payload_type"] = "preset_bp_key"
            out["payload"] = _decode_text(value)
    return out


def _parse_blueprint_component(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "com_type": 0,
        "com_pos": 0,
        "payload_type": None,
    }
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 0 and isinstance(value, int):
            out["com_type"] = int(value)
        elif field_no == 2 and wire == 0 and isinstance(value, int):
            out["com_pos"] = int(value)
        elif field_no == 10 and wire == 2 and isinstance(value, bytes):
            out["payload_type"] = "selector"
        elif field_no == 11 and wire == 2 and isinstance(value, bytes):
            out["payload_type"] = "formula_man"
        elif field_no == 12 and wire == 2 and isinstance(value, bytes):
            out["payload_type"] = "box_valve"
        elif field_no == 13 and wire == 2 and isinstance(value, bytes):
            out["payload_type"] = "fluid_valve"
        elif field_no == 14 and wire == 2 and isinstance(value, bytes):
            out["payload_type"] = "sign"
    return out


def _parse_blueprint_transform(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "position": None,
        "direction": None,
        "direction_in": None,
        "direction_out": None,
        "points": [],
        "has_interactive_param": False,
    }
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            out["position"] = _parse_vec3_int(value)
        elif field_no == 2 and wire == 2 and isinstance(value, bytes):
            out["direction"] = _parse_vec3_int(value)
        elif field_no == 3 and wire == 2 and isinstance(value, bytes):
            out["has_interactive_param"] = True
        elif field_no == 6 and wire == 2 and isinstance(value, bytes):
            out["direction_in"] = _parse_vec3_int(value)
        elif field_no == 7 and wire == 2 and isinstance(value, bytes):
            out["direction_out"] = _parse_vec3_int(value)
        elif field_no == 8 and wire == 2 and isinstance(value, bytes):
            out["points"].append(_parse_vec3_int(value))
    return out


def _parse_blueprint_node(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "template_id": "",
        "product_icon": "",
        "node_id": 0,
        "transform": None,
        "components": [],
    }
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            out["template_id"] = _decode_text(value)
        elif field_no == 2 and wire == 2 and isinstance(value, bytes):
            out["product_icon"] = _decode_text(value)
        elif field_no == 3 and wire == 0 and isinstance(value, int):
            out["node_id"] = int(value)
        elif field_no == 4 and wire == 2 and isinstance(value, bytes):
            out["transform"] = _parse_blueprint_transform(value)
        elif field_no == 5 and wire == 2 and isinstance(value, bytes):
            out["components"].append(_parse_blueprint_component(value))
    return out


def _parse_blueprint_data(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "name": "",
        "desc": "",
        "bp_size": None,
        "bp_icon": None,
        "bp_tags": [],
        "review_status": 0,
        "review_status_name": FACTORY_BP_REVIEW_STATUS.get(0, "Unknown"),
        "bp_param": None,
        "use_count": 0,
        "creator_role_id": 0,
        "creator_user_id": "",
        "nodes": [],
        "is_new": False,
        "fetch_time": 0,
    }
    for field_no, wire, value in iter_fields(data):
        if field_no == 3 and wire == 2 and isinstance(value, bytes):
            out["name"] = _decode_text(value)
        elif field_no == 4 and wire == 2 and isinstance(value, bytes):
            out["desc"] = _decode_text(value)
        elif field_no == 5 and wire == 2 and isinstance(value, bytes):
            out["bp_size"] = _parse_blueprint_size(value)
        elif field_no == 7 and wire == 2 and isinstance(value, bytes):
            out["bp_icon"] = _parse_blueprint_icon(value)
        elif field_no == 8 and wire == 0 and isinstance(value, int):
            out["bp_tags"].append(int(value))
        elif field_no == 9 and wire == 0 and isinstance(value, int):
            status = int(value)
            out["review_status"] = status
            out["review_status_name"] = FACTORY_BP_REVIEW_STATUS.get(status, f"Unknown({status})")
        elif field_no == 10 and wire == 2 and isinstance(value, bytes):
            out["bp_param"] = _parse_blueprint_param(value)
        elif field_no == 11 and wire == 0 and isinstance(value, int):
            out["use_count"] = int(value)
        elif field_no == 12 and wire == 0 and isinstance(value, int):
            out["creator_role_id"] = int(value)
        elif field_no == 13 and wire == 2 and isinstance(value, bytes):
            out["creator_user_id"] = _decode_text(value)
        elif field_no == 14 and wire == 2 and isinstance(value, bytes):
            out["nodes"].append(_parse_blueprint_node(value))
        elif field_no == 15 and wire == 0 and isinstance(value, int):
            out["is_new"] = bool(value)
        elif field_no == 16 and wire == 0 and isinstance(value, int):
            out["fetch_time"] = int(value)

    out["node_count"] = len(out["nodes"])
    out["component_count"] = sum(len(item["components"]) for item in out["nodes"])
    return out


def build_query_shared_blueprint_body(index: str, share_code: str) -> bytes:
    return encode_string(1, index) + encode_string(2, share_code)


def parse_query_shared_blueprint_response(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"index": "", "blueprint_data": None}
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            out["index"] = _decode_text(value)
        elif field_no == 2 and wire == 2 and isinstance(value, bytes):
            out["blueprint_data"] = _parse_blueprint_data(value)
    return out


class BlueprintQueryPlugin(PluginBase):
    name = "blueprint-query"

    async def query_shared_blueprint(self, share_code: str, *, timeout: float = 10.0) -> dict[str, Any]:
        normalized_share_code = str(share_code or "").strip()
        if not normalized_share_code:
            raise ValueError("share_code 不能为空")

        request_index = f"bpq-{uuid.uuid4().hex[:16]}"
        request_body = build_query_shared_blueprint_body(request_index, normalized_share_code)

        _, response_body = await self.tcp_client.request_message(
            MSG_ID_CS_FACTORY_QUERY_SHARED_BLUEPRINT,
            request_body,
            response_msgid=MSG_ID_SC_FACTORY_QUERY_SHARED_BLUEPRINT,
            predicate=lambda _head, body: _parse_index_only(body) == request_index,
            timeout=timeout,
        )

        parsed = parse_query_shared_blueprint_response(response_body)
        blueprint_data = parsed.get("blueprint_data")
        if not blueprint_data:
            raise RuntimeError("蓝图查询回包缺少 BluePrintData")

        return {
            "request_index": request_index,
            "share_code": normalized_share_code,
            "response_index": parsed.get("index", ""),
            "blueprint_data": blueprint_data,
        }
