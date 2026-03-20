from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import zlib
from collections import Counter, deque
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from tcp.proto_errors import ERROR_CODES, ERROR_EXPLANATIONS
from tcp.tcp import (
    MSG_ID_SC_ERROR,
    TCPClient,
    _parse_error_response,
    _lz4_decompress_block,
    decode_varint,
    encode_string,
    encode_uint64,
    iter_fields,
)

from .base import PluginBase

logger = logging.getLogger(__name__)

MSG_ID_CS_ITEM_BAG_CHG_SPACESHIP_CHAPTER = 1033
MSG_ID_SC_ITEM_BAG_CHG_SPACESHIP_CHAPTER = 1036
MSG_ID_CS_FRIEND_LIST_SIMPLE_SYNC = 539
MSG_ID_CS_FRIEND_LIST_QUERY = 540
MSG_ID_CS_SHOP_BEGIN = 1100
MSG_ID_CS_SHOP_QUERY_FRIEND_GOODS_PRICE = 1115
MSG_ID_CS_SHOP_QUERY_FRIEND_SHOP = 1117
MSG_ID_SC_FRIEND_LIST_SIMPLE_SYNC = 710
MSG_ID_SC_FRIEND_LIST_QUERY = 711
MSG_ID_SC_SHOP_BEGIN = 1351
MSG_ID_SC_SHOP_SYNC = 1352
MSG_ID_SC_SHOP_QUERY_FRIEND_GOODS_PRICE = 1364
MSG_ID_SC_SHOP_QUERY_FRIEND_SHOP = 1366
MSG_ID_CS_DOMAIN_DEVELOPMENT_READ_VERSION_INFO = 1553
MSG_ID_SC_DOMAIN_DEVELOPMENT_SYSTEM_SYNC = 1742
MSG_ID_SC_DOMAIN_DEVELOPMENT_SYNC = 1745
MSG_ID_SC_DOMAIN_DEVELOPMENT_READ_VERSION_INFO_MODIFY = 1746

PING_MSG_IDS = {5, 8}

DOMAIN_DEVELOPMENT_READ_VERSION_TYPE_NAMES = {
    0: "DomainDevSystem",
    1: "DomainDevKiteStation",
    2: "DomainDevSettlement",
    3: "DomainDevDomainShop",
    4: "DomainDevDomainDepot",
}

SHOP_REFRESH_DATA_CASE_NAMES = {
    0: "None",
    21: "RandomRefresh",
    22: "RandomDomain",
}

MESSAGE_NAMES = {
    MSG_ID_SC_ERROR: "ScError",
    MSG_ID_SC_ITEM_BAG_CHG_SPACESHIP_CHAPTER: "ScItemBagChgSpaceshipChapter",
    MSG_ID_SC_FRIEND_LIST_SIMPLE_SYNC: "ScFriendListSimpleSync",
    MSG_ID_SC_FRIEND_LIST_QUERY: "ScFriendListQuery",
    MSG_ID_SC_SHOP_BEGIN: "ScShopBegin",
    MSG_ID_SC_SHOP_SYNC: "ScShopSync",
    MSG_ID_SC_SHOP_QUERY_FRIEND_GOODS_PRICE: "ScShopQueryFriendGoodsPrice",
    MSG_ID_SC_SHOP_QUERY_FRIEND_SHOP: "ScShopQueryFriendShop",
    MSG_ID_SC_DOMAIN_DEVELOPMENT_SYSTEM_SYNC: "ScDomainDevelopmentSystemSync",
    MSG_ID_SC_DOMAIN_DEVELOPMENT_SYNC: "ScDomainDevelopmentSync",
    MSG_ID_SC_DOMAIN_DEVELOPMENT_READ_VERSION_INFO_MODIFY: "ScDomainDevelopmentReadVersionInfoModify",
}

BINDINGS_PATH = (
    Path(__file__).resolve().parent.parent / "Data" / "tmp" / "shop_price_query_bindings.json"
)


def _now_ts() -> float:
    return time.time()


def _now_iso(ts: Optional[float] = None) -> str:
    value = _now_ts() if ts is None else float(ts)
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))


def _decode_text(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


def _parse_packed_varints(raw: bytes) -> list[int]:
    items: list[int] = []
    offset = 0
    while offset < len(raw):
        value, offset = decode_varint(raw, offset)
        items.append(int(value))
    return items


def _append_varint_field(out: list[int], wire: int, value: bytes | int) -> None:
    if wire == 0 and isinstance(value, int):
        out.append(int(value))
        return
    if wire == 2 and isinstance(value, bytes):
        out.extend(_parse_packed_varints(value))


def _build_local_goods_entry(goods_id: str, item: dict[str, Any]) -> dict[str, Any]:
    history_prices = [int(value) for value in (item.get("history_prices") or [])]
    history_price_count = int(item.get("history_price_count", len(history_prices)) or 0)
    quantity = int(item.get("quantity", 0) or 0)
    avg_price = int(item.get("avg_price", 0) or 0)
    today_price = int(history_prices[0] or 0) if history_prices else 0
    return {
        "goods_id": goods_id,
        "goods_template_id": str(item.get("goods_template_id") or ""),
        "avg_price": avg_price,
        "quantity": quantity,
        "holding_avg_price": avg_price,
        "holding_quantity": quantity,
        "is_owned": quantity > 0,
        "today_price": today_price,
        "has_today_price": history_price_count > 0,
        "today_price_source": "history_prices[0]" if history_price_count > 0 else "",
        "history_prices": history_prices,
        "history_price_count": history_price_count,
    }


def _sort_key_by_numeric_tail(value: str) -> tuple[str, int, str]:
    text = str(value or "")
    match = re.search(r"(\d+)(?!.*\d)", text)
    if not match:
        return (text, -1, text)
    prefix = text[:match.start()]
    return (prefix, int(match.group(1)), text)


def _infer_domainshop_id_from_shop_id(shop_id: str) -> str:
    text = str(shop_id or "").strip()
    if not text.startswith("domainshop_page_"):
        return ""

    suffix = text[len("domainshop_page_") :]
    for prefix in ("rand_", "com_", "common_"):
        if suffix.startswith(prefix):
            suffix = suffix[len(prefix) :]
            break
    suffix = suffix.strip("_")
    return f"domainshop_{suffix}" if suffix else ""


def _infer_domainshop_kind_from_shop_id(shop_id: str) -> str:
    text = str(shop_id or "").strip()
    if "_page_rand_" in text:
        return "rand"
    if "_page_com_" in text:
        return "com"
    if text.startswith("domainshop_page_"):
        return "page"
    return ""


def _parse_string_int_map_entry(data: bytes) -> tuple[str, int]:
    key = ""
    mapped_value = 0
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            key = _decode_text(value)
        elif field_no == 2 and wire == 0 and isinstance(value, int):
            mapped_value = int(value)
    return key, mapped_value


def _parse_string_bool_map_entry(data: bytes) -> tuple[str, bool]:
    key = ""
    mapped_value = False
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            key = _decode_text(value)
        elif field_no == 2 and wire == 0 and isinstance(value, int):
            mapped_value = bool(value)
    return key, mapped_value


def _parse_string_message_map_entry(
    data: bytes, value_parser: Callable[[bytes], dict[str, Any]]
) -> tuple[str, dict[str, Any]]:
    key = ""
    mapped_value: dict[str, Any] = {}
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            key = _decode_text(value)
        elif field_no == 2 and wire == 2 and isinstance(value, bytes):
            mapped_value = value_parser(value)
    return key, mapped_value


def _summarize_proto_fields(data: bytes, *, limit: int = 8) -> str:
    summary: list[str] = []
    try:
        for index, (field_no, wire, value) in enumerate(iter_fields(data)):
            if index >= limit:
                summary.append("...")
                break
            if wire == 0 and isinstance(value, int):
                summary.append(f"{field_no}=u{value}")
            elif wire == 2 and isinstance(value, bytes):
                summary.append(f"{field_no}=bytes[{len(value)}]")
            else:
                summary.append(f"{field_no}=wire{wire}")
    except Exception as exc:
        summary.append(f"parse_error={exc}")
    return ", ".join(summary) if summary else "<empty>"


def _summarize_proto_field_list(data: bytes, *, limit: int = 8) -> list[str]:
    text = _summarize_proto_fields(data, limit=limit)
    if not text or text == "<empty>":
        return []
    return [item.strip() for item in text.split(",")]


def _parse_domain_development_degree(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "exp": 0,
        "level": 0,
        "rewarded_level": 0,
        "source": [],
    }
    source: list[int] = []
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 0 and isinstance(value, int):
            out["exp"] = int(value)
        elif field_no == 2 and wire == 0 and isinstance(value, int):
            out["level"] = int(value)
        elif field_no == 3 and wire == 0 and isinstance(value, int):
            out["rewarded_level"] = int(value)
        elif field_no == 4:
            _append_varint_field(source, wire, value)
    out["source"] = source
    out["source_count"] = len(source)
    return out


def _parse_domain_development(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "chapter_id": "",
        "domain_id": "",
        "version": "",
        "dev_degree": None,
        "level": 0,
        "exp": 0,
    }
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            chapter_id = _decode_text(value)
            out["chapter_id"] = chapter_id
            out["domain_id"] = chapter_id
        elif field_no == 2 and wire == 2 and isinstance(value, bytes):
            dev_degree = _parse_domain_development_degree(value)
            out["dev_degree"] = dev_degree
            out["level"] = int(dev_degree.get("level", 0) or 0)
            out["exp"] = int(dev_degree.get("exp", 0) or 0)
        elif field_no == 3 and wire == 2 and isinstance(value, bytes):
            out["version"] = _decode_text(value)
    return out


def _parse_domain_development_system_sync(data: bytes) -> dict[str, Any]:
    domains: list[dict[str, Any]] = []
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            domains.append(_parse_domain_development(value))
    return {
        "domains": domains,
        "count": len(domains),
        "chapter_ids": [item.get("chapter_id", "") for item in domains if item.get("chapter_id")],
    }


def _parse_domain_development_sync(data: bytes) -> dict[str, Any]:
    domain = None
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            domain = _parse_domain_development(value)
    return {"domain": domain}


def _parse_domain_development_read_version_record(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "data_type": 0,
        "data_type_name": DOMAIN_DEVELOPMENT_READ_VERSION_TYPE_NAMES.get(0, "Unknown"),
        "chapter_id": "",
        "domain_id": "",
        "version": "",
    }
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 0 and isinstance(value, int):
            data_type = int(value)
            out["data_type"] = data_type
            out["data_type_name"] = DOMAIN_DEVELOPMENT_READ_VERSION_TYPE_NAMES.get(
                data_type, f"Unknown({data_type})"
            )
        elif field_no == 2 and wire == 2 and isinstance(value, bytes):
            chapter_id = _decode_text(value)
            out["chapter_id"] = chapter_id
            out["domain_id"] = chapter_id
        elif field_no == 3 and wire == 2 and isinstance(value, bytes):
            out["version"] = _decode_text(value)
    return out


def _parse_domain_development_read_version_info_modify(data: bytes) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            records.append(_parse_domain_development_read_version_record(value))
    return {
        "records": records,
        "count": len(records),
        "chapter_ids": [item.get("chapter_id", "") for item in records if item.get("chapter_id")],
    }


def _parse_item_bag_change_spaceship_chapter(data: bytes) -> dict[str, Any]:
    out = {
        "spaceship_chapter_id": "",
        "domain_id": "",
        "chapter_id": "",
    }
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            chapter_id = _decode_text(value)
            out["spaceship_chapter_id"] = chapter_id
            out["domain_id"] = chapter_id
            out["chapter_id"] = chapter_id
    return out


def _parse_shop_unlock_conditions(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": "",
        "unlock_condition_values": {},
        "unlock_condition_flags": {},
    }
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            out["id"] = _decode_text(value)
        elif field_no == 2 and wire == 2 and isinstance(value, bytes):
            key, mapped_value = _parse_string_int_map_entry(value)
            if key:
                out["unlock_condition_values"][key] = mapped_value
        elif field_no == 3 and wire == 2 and isinstance(value, bytes):
            key, mapped_value = _parse_string_bool_map_entry(value)
            if key:
                out["unlock_condition_flags"][key] = mapped_value
    return out


def _parse_shop_frequency_limit(data: bytes) -> dict[str, Any]:
    out = {"frequency_limit_id": "", "count": 0}
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            out["frequency_limit_id"] = _decode_text(value)
        elif field_no == 2 and wire == 0 and isinstance(value, int):
            out["count"] = int(value)
    return out


def _parse_domain_shop_goods(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "goods_id": "",
        "history_prices": [],
    }
    history_prices: list[int] = []
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            out["goods_id"] = _decode_text(value)
        elif field_no == 2:
            _append_varint_field(history_prices, wire, value)
    out["history_prices"] = history_prices
    out["history_price_count"] = len(history_prices)
    return out


def _parse_domain_shop_positions(data: bytes) -> dict[str, Any]:
    out = {"quantity": 0, "avg_price": 0}
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 0 and isinstance(value, int):
            out["quantity"] = int(value)
        elif field_no == 2 and wire == 0 and isinstance(value, int):
            out["avg_price"] = int(value)
    return out


def _parse_shop_dynamic_goods(data: bytes) -> dict[str, Any]:
    out = {"goods_id": "", "goods_template_id": ""}
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            out["goods_id"] = _decode_text(value)
        elif field_no == 2 and wire == 2 and isinstance(value, bytes):
            out["goods_template_id"] = _decode_text(value)
    return out


def _parse_shop_random_refresh(data: bytes) -> dict[str, Any]:
    dynamic_goods: list[dict[str, Any]] = []
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            dynamic_goods.append(_parse_shop_dynamic_goods(value))
    return {
        "dynamic_goods": dynamic_goods,
        "dynamic_goods_count": len(dynamic_goods),
    }


def _parse_shop_random_domain(data: bytes) -> dict[str, Any]:
    domain_rand_goods: list[dict[str, Any]] = []
    positions: dict[str, dict[str, Any]] = {}
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            domain_rand_goods.append(_parse_domain_shop_goods(value))
        elif field_no == 2 and wire == 2 and isinstance(value, bytes):
            key, mapped_value = _parse_string_message_map_entry(value, _parse_domain_shop_positions)
            if key:
                positions[key] = mapped_value
    return {
        "domain_rand_goods": domain_rand_goods,
        "domain_rand_goods_count": len(domain_rand_goods),
        "positions": positions,
        "position_count": len(positions),
    }


def _parse_shop_domain_channel(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "domain_id": "",
        "channels": {},
        "version": "",
    }
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            out["domain_id"] = _decode_text(value)
        elif field_no == 2 and wire == 2 and isinstance(value, bytes):
            key, mapped_value = _parse_string_int_map_entry(value)
            if key:
                out["channels"][key] = mapped_value
        elif field_no == 3 and wire == 2 and isinstance(value, bytes):
            out["version"] = _decode_text(value)
    out["channel_count"] = len(out["channels"])
    return out


def _parse_shop_group_data(data: bytes) -> dict[str, Any]:
    domain_channels: list[dict[str, Any]] = []
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            domain_channels.append(_parse_shop_domain_channel(value))
    return {
        "domain_channels": domain_channels,
        "domain_channel_count": len(domain_channels),
    }


def _parse_shop(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "shop_id": "",
        "shop_refresh_type": 0,
        "unlock_condition_values": {},
        "unlock_condition_flags": {},
        "discount_count": 0,
        "goods_unlock_conditions": [],
        "is_dynamic_good": False,
        "is_dynamic_discount": False,
        "goods_time_range_count": 0,
        "random_type": 0,
        "refresh_data_case": "None",
        "refresh_data_case_value": 0,
        "random_refresh": None,
        "random_domain": None,
    }
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            out["shop_id"] = _decode_text(value)
        elif field_no == 2 and wire == 0 and isinstance(value, int):
            out["shop_refresh_type"] = int(value)
        elif field_no == 3 and wire == 2 and isinstance(value, bytes):
            key, mapped_value = _parse_string_int_map_entry(value)
            if key:
                out["unlock_condition_values"][key] = mapped_value
        elif field_no == 4 and wire == 2 and isinstance(value, bytes):
            key, mapped_value = _parse_string_bool_map_entry(value)
            if key:
                out["unlock_condition_flags"][key] = mapped_value
        elif field_no == 5 and wire == 2 and isinstance(value, bytes):
            out["discount_count"] += 1
        elif field_no == 6 and wire == 2 and isinstance(value, bytes):
            out["goods_unlock_conditions"].append(_parse_shop_unlock_conditions(value))
        elif field_no == 7 and wire == 0 and isinstance(value, int):
            out["is_dynamic_good"] = bool(value)
        elif field_no == 8 and wire == 0 and isinstance(value, int):
            out["is_dynamic_discount"] = bool(value)
        elif field_no == 9 and wire == 0 and isinstance(value, int):
            out["random_type"] = int(value)
        elif field_no == 10 and wire == 2 and isinstance(value, bytes):
            out["goods_time_range_count"] += 1
        elif field_no == 21 and wire == 2 and isinstance(value, bytes):
            out["refresh_data_case"] = SHOP_REFRESH_DATA_CASE_NAMES.get(21, "RandomRefresh")
            out["refresh_data_case_value"] = 21
            out["random_refresh"] = _parse_shop_random_refresh(value)
        elif field_no == 22 and wire == 2 and isinstance(value, bytes):
            out["refresh_data_case"] = SHOP_REFRESH_DATA_CASE_NAMES.get(22, "RandomDomain")
            out["refresh_data_case_value"] = 22
            out["random_domain"] = _parse_shop_random_domain(value)
    return out


def _parse_shop_sync(data: bytes) -> dict[str, Any]:
    shop_group_conditions: list[dict[str, Any]] = []
    shops: list[dict[str, Any]] = []
    frequency_limits: list[dict[str, Any]] = []
    manual_refresh_limits: list[dict[str, Any]] = []
    shop_group_data = None
    frequency_limit_mgr_summary = None

    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            shop_group_conditions.append(_parse_shop_unlock_conditions(value))
        elif field_no == 2 and wire == 2 and isinstance(value, bytes):
            shops.append(_parse_shop(value))
        elif field_no == 3 and wire == 2 and isinstance(value, bytes):
            frequency_limits.append(_parse_shop_frequency_limit(value))
        elif field_no == 4 and wire == 2 and isinstance(value, bytes):
            manual_refresh_limits.append(_parse_shop_frequency_limit(value))
        elif field_no == 5 and wire == 2 and isinstance(value, bytes):
            shop_group_data = _parse_shop_group_data(value)
        elif field_no == 6 and wire == 2 and isinstance(value, bytes):
            frequency_limit_mgr_summary = {
                "body_len": len(value),
                "fields": _summarize_proto_fields(value, limit=6),
            }

    return {
        "shop_group_conditions": shop_group_conditions,
        "shops": shops,
        "frequency_limits": frequency_limits,
        "manual_refresh_limits": manual_refresh_limits,
        "shop_group_data": shop_group_data,
        "frequency_limit_mgr_summary": frequency_limit_mgr_summary,
        "shop_count": len(shops),
    }


def _hex_prefix(data: bytes, *, size: int = 24) -> str:
    return data[:size].hex()


def _payload_signature(data: bytes) -> tuple[int, bytes, bytes]:
    prefix = data[:24]
    suffix = data[-24:] if len(data) > 24 else data
    return len(data), prefix, suffix


def _score_shop_sync_parse(parsed: dict[str, Any]) -> int:
    shops = parsed.get("shops") or []
    valid_shop_count = sum(1 for item in shops if str(item.get("shop_id") or "").strip())
    group_data = parsed.get("shop_group_data") or {}
    domain_channels = group_data.get("domain_channels") or []
    valid_domain_channel_count = sum(
        1 for item in domain_channels if str(item.get("domain_id") or "").strip()
    )
    refresh_goods_count = 0
    history_goods_count = 0
    for shop in shops:
        random_refresh = shop.get("random_refresh") or {}
        random_domain = shop.get("random_domain") or {}
        refresh_goods_count += len(random_refresh.get("dynamic_goods") or [])
        history_goods_count += len(random_domain.get("domain_rand_goods") or [])
        history_goods_count += len(random_domain.get("positions") or {})

    score = 0
    score += valid_shop_count * 20
    score += valid_domain_channel_count * 12
    score += len(parsed.get("shop_group_conditions") or []) * 4
    score += len(parsed.get("frequency_limits") or []) * 3
    score += len(parsed.get("manual_refresh_limits") or []) * 2
    score += refresh_goods_count * 2
    score += history_goods_count
    if parsed.get("frequency_limit_mgr_summary"):
        score += 1
    return score


def _shop_sync_has_content(parsed: dict[str, Any]) -> bool:
    if _score_shop_sync_parse(parsed) > 0:
        return True
    if parsed.get("shop_group_conditions"):
        return True
    if parsed.get("frequency_limits"):
        return True
    if parsed.get("manual_refresh_limits"):
        return True
    if parsed.get("frequency_limit_mgr_summary"):
        return True
    return False


def _decompress_shop_sync_payloads(data: bytes) -> list[tuple[str, bytes]]:
    results: list[tuple[str, bytes]] = []
    for method, decoder in (
        ("lz4-block", _lz4_decompress_block),
        ("zlib", lambda raw: zlib.decompress(raw)),
        ("raw-deflate", lambda raw: zlib.decompress(raw, -zlib.MAX_WBITS)),
        ("gzip", lambda raw: zlib.decompress(raw, zlib.MAX_WBITS | 16)),
    ):
        try:
            payload = decoder(data)
        except Exception:
            continue
        if payload:
            results.append((f"decompress:{method}", payload))
    return results


def _extract_embedded_payloads(data: bytes, *, source: str, limit: int = 8) -> list[tuple[str, bytes]]:
    results: list[tuple[str, bytes]] = []
    try:
        for index, (field_no, wire, value) in enumerate(iter_fields(data)):
            if index >= limit:
                break
            if wire == 2 and isinstance(value, bytes) and len(value) >= 16:
                results.append((f"{source}:field{field_no}", value))
    except Exception:
        pass
    return results


def _build_shop_sync_attempt(
    *,
    source: str,
    payload: bytes,
    error: str = "",
    parsed: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    attempt = {
        "source": source,
        "payload_len": len(payload),
        "body_hex_prefix": _hex_prefix(payload),
        "error": error,
        "score": 0,
        "shop_count": 0,
        "domain_channel_count": 0,
    }
    if parsed is None:
        return attempt

    shop_group_data = parsed.get("shop_group_data") or {}
    attempt["score"] = _score_shop_sync_parse(parsed)
    attempt["has_content"] = _shop_sync_has_content(parsed)
    attempt["shop_count"] = sum(
        1 for item in parsed.get("shops") or [] if str(item.get("shop_id") or "").strip()
    )
    attempt["domain_channel_count"] = sum(
        1
        for item in shop_group_data.get("domain_channels") or []
        if str(item.get("domain_id") or "").strip()
    )
    attempt["refresh_case_counts"] = dict(
        Counter(str(item.get("refresh_data_case") or "None") for item in parsed.get("shops") or [])
    )
    return attempt


def _parse_shop_sync_with_fallbacks(data: bytes) -> dict[str, Any]:
    candidate_payloads: list[tuple[str, bytes]] = [("direct", data)]
    candidate_payloads.extend(_decompress_shop_sync_payloads(data))

    seen_payloads: set[tuple[int, bytes, bytes]] = set()
    expanded_candidates: list[tuple[str, bytes]] = []
    for source, payload in candidate_payloads:
        signature = _payload_signature(payload)
        if signature in seen_payloads:
            continue
        seen_payloads.add(signature)
        expanded_candidates.append((source, payload))
        for child_source, child_payload in _extract_embedded_payloads(payload, source=source):
            child_signature = _payload_signature(child_payload)
            if child_signature in seen_payloads:
                continue
            seen_payloads.add(child_signature)
            expanded_candidates.append((child_source, child_payload))

    attempts: list[dict[str, Any]] = []
    best_parsed: Optional[dict[str, Any]] = None
    best_attempt: Optional[dict[str, Any]] = None

    for source, payload in expanded_candidates:
        for offset in range(0, min(len(payload), 129)):
            attempt_source = source if offset == 0 else f"{source}+offset:{offset}"
            attempt_payload = payload[offset:]
            if not attempt_payload:
                continue
            try:
                parsed = _parse_shop_sync(attempt_payload)
            except Exception as exc:
                attempts.append(
                    _build_shop_sync_attempt(
                        source=attempt_source,
                        payload=attempt_payload,
                        error=str(exc),
                    )
                )
                continue

            attempt = _build_shop_sync_attempt(
                source=attempt_source,
                payload=attempt_payload,
                parsed=parsed,
            )
            attempts.append(attempt)
            if best_attempt is None or int(attempt.get("score", 0) or 0) > int(
                best_attempt.get("score", 0) or 0
            ):
                best_attempt = attempt
                best_parsed = parsed

    return {
        "success": bool(best_parsed is not None and (best_attempt or {}).get("has_content")),
        "parsed": best_parsed,
        "best_attempt": best_attempt,
        "attempt_count": len(attempts),
        "attempts": attempts[:24],
    }


def _parse_goods_his_price(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "role_id": 0,
        "shop_id": "",
        "goods_id": "",
        "prices": [],
    }
    prices: list[int] = []
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 0 and isinstance(value, int):
            out["role_id"] = int(value)
        elif field_no == 2 and wire == 2 and isinstance(value, bytes):
            out["shop_id"] = _decode_text(value)
        elif field_no == 3 and wire == 2 and isinstance(value, bytes):
            out["goods_id"] = _decode_text(value)
        elif field_no == 4:
            _append_varint_field(prices, wire, value)
    out["prices"] = prices
    out["price_count"] = len(prices)
    return out


def _parse_friend_simple_info(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "role_id": 0,
        "last_logout_time": 0,
        "online": False,
        "adventure_level": 0,
        "create_time": 0,
        "help_flag": False,
        "clue_flag": False,
        "name": "",
        "remark_name": "",
        "help_status": 0,
        "guest_room_unlock": False,
        "short_id": "",
        "signature": "",
        "user_avatar_id": 0,
        "user_avatar_frame_id": 0,
        "business_card_topic_id": 0,
        "clue_room_unlock": False,
    }
    for field_no, wire, value in iter_fields(data):
        if wire == 0 and isinstance(value, int):
            if field_no == 1:
                out["role_id"] = int(value)
            elif field_no == 2:
                out["last_logout_time"] = int(value)
            elif field_no == 3:
                out["online"] = bool(value)
            elif field_no == 4:
                out["adventure_level"] = int(value)
            elif field_no == 5:
                out["create_time"] = int(value)
            elif field_no == 6:
                out["help_flag"] = bool(value)
            elif field_no == 7:
                out["clue_flag"] = bool(value)
            elif field_no == 10:
                out["help_status"] = int(value)
            elif field_no == 11:
                out["guest_room_unlock"] = bool(value)
            elif field_no == 14:
                out["user_avatar_id"] = int(value)
            elif field_no == 15:
                out["user_avatar_frame_id"] = int(value)
            elif field_no == 16:
                out["business_card_topic_id"] = int(value)
            elif field_no == 17:
                out["clue_room_unlock"] = bool(value)
        elif wire == 2 and isinstance(value, bytes):
            if field_no == 8:
                out["name"] = _decode_text(value)
            elif field_no == 9:
                out["remark_name"] = _decode_text(value)
            elif field_no == 12:
                out["short_id"] = _decode_text(value)
            elif field_no == 13:
                out["signature"] = _decode_text(value)
    return out


def _parse_friend_list_simple_sync(data: bytes) -> dict[str, Any]:
    friend_list: list[dict[str, Any]] = []
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            friend_list.append(_parse_friend_simple_info(value))
    role_ids = [
        int(item.get("role_id", 0) or 0)
        for item in friend_list
        if int(item.get("role_id", 0) or 0) > 0
    ]
    return {"friend_list": friend_list, "count": len(friend_list), "role_ids": role_ids}


def _parse_friend_base_user_info(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "role_id": 0,
        "name": "",
        "short_id": "",
        "last_login_time": 0,
        "last_logout_time": 0,
        "online": False,
        "adventure_level": 0,
        "signature": "",
        "business_card_topic_id": 0,
        "user_avatar_id": 0,
        "user_avatar_frame_id": 0,
    }
    for field_no, wire, value in iter_fields(data):
        if wire == 0 and isinstance(value, int):
            if field_no == 1:
                out["role_id"] = int(value)
            elif field_no == 5:
                out["last_login_time"] = int(value)
            elif field_no == 6:
                out["last_logout_time"] = int(value)
            elif field_no == 7:
                out["online"] = bool(value)
            elif field_no == 8:
                out["adventure_level"] = int(value)
            elif field_no == 11:
                out["business_card_topic_id"] = int(value)
            elif field_no == 12:
                out["user_avatar_id"] = int(value)
            elif field_no == 13:
                out["user_avatar_frame_id"] = int(value)
        elif wire == 2 and isinstance(value, bytes):
            if field_no == 3:
                out["name"] = _decode_text(value)
            elif field_no == 4:
                out["short_id"] = _decode_text(value)
            elif field_no == 9:
                out["signature"] = _decode_text(value)
    return out


def _parse_friend_spaceship_default_data(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "help_flag": False,
        "clue_flag": False,
        "unlock_guest_room": False,
        "help_status": 0,
        "unlock_clue_room": False,
    }
    for field_no, wire, value in iter_fields(data):
        if wire != 0 or not isinstance(value, int):
            continue
        if field_no == 1:
            out["help_flag"] = bool(value)
        elif field_no == 2:
            out["clue_flag"] = bool(value)
        elif field_no == 3:
            out["unlock_guest_room"] = bool(value)
        elif field_no == 4:
            out["help_status"] = int(value)
        elif field_no == 5:
            out["unlock_clue_room"] = bool(value)
    return out


def _parse_friend_user_info(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "data_type": 0,
        "base_data": {},
        "spaceship_default": {},
    }
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 0 and isinstance(value, int):
            out["data_type"] = int(value)
        elif field_no == 2 and wire == 2 and isinstance(value, bytes):
            out["base_data"] = _parse_friend_base_user_info(value)
        elif field_no == 3 and wire == 2 and isinstance(value, bytes):
            out["spaceship_default"] = _parse_friend_spaceship_default_data(value)
    return out


def _parse_friend_info(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "role_id": 0,
        "create_time": 0,
        "remark_name": "",
        "friend_user_info": {},
    }
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            out["friend_user_info"] = _parse_friend_user_info(value)
        elif field_no == 2 and wire == 0 and isinstance(value, int):
            out["create_time"] = int(value)
        elif field_no == 3 and wire == 2 and isinstance(value, bytes):
            out["remark_name"] = _decode_text(value)
    base_data = ((out.get("friend_user_info") or {}).get("base_data") or {})
    out["role_id"] = int(base_data.get("role_id", 0) or 0)
    return out


def _parse_friend_list_query_response(data: bytes) -> dict[str, Any]:
    friend_list: list[dict[str, Any]] = []
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            friend_list.append(_parse_friend_info(value))
    role_ids = [
        int(item.get("role_id", 0) or 0)
        for item in friend_list
        if int(item.get("role_id", 0) or 0) > 0
    ]
    return {"friend_list": friend_list, "count": len(friend_list), "role_ids": role_ids}


def _parse_shop_goods_price(data: bytes) -> dict[str, Any]:
    discount_count = 0
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            discount_count += 1
    return {"discount_count": discount_count}


def _parse_friend_goods_price_response(data: bytes) -> dict[str, Any]:
    his_price: list[dict[str, Any]] = []
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 2 and isinstance(value, bytes):
            his_price.append(_parse_goods_his_price(value))
    return {"his_price": his_price, "count": len(his_price)}


def _parse_friend_shop_response(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "friend_role_id": 0,
        "shop_goods": {},
        "his_price": [],
    }
    for field_no, wire, value in iter_fields(data):
        if field_no == 1 and wire == 0 and isinstance(value, int):
            out["friend_role_id"] = int(value)
        elif field_no == 2 and wire == 2 and isinstance(value, bytes):
            key, mapped_value = _parse_string_message_map_entry(value, _parse_shop_goods_price)
            if key:
                out["shop_goods"][key] = mapped_value
        elif field_no == 3 and wire == 2 and isinstance(value, bytes):
            out["his_price"].append(_parse_goods_his_price(value))
    out["shop_goods_count"] = len(out["shop_goods"])
    out["his_price_count"] = len(out["his_price"])
    return out


def build_domain_development_read_version_info_body(chapter_id: str) -> bytes:
    return encode_string(1, chapter_id)


def build_change_spaceship_chapter_body(domain_id: str) -> bytes:
    return encode_string(1, domain_id)


def build_shop_begin_body() -> bytes:
    return b""


def build_friend_list_simple_sync_body() -> bytes:
    return b""


def build_friend_list_query_body(role_ids: Iterable[int], *, info_type: int = 0) -> bytes:
    body = encode_uint64(1, int(info_type))
    for role_id in role_ids:
        body += encode_uint64(2, int(role_id))
    return body


def build_query_friend_goods_price_body(
    shop_id: str, goods_id: str, role_ids: Iterable[int]
) -> bytes:
    body = encode_string(1, shop_id) + encode_string(2, goods_id)
    for role_id in role_ids:
        body += encode_uint64(3, int(role_id))
    return body


def build_query_friend_shop_body(friend_role_id: int, shop_ids: Iterable[str]) -> bytes:
    body = encode_uint64(1, int(friend_role_id))
    for shop_id in shop_ids:
        body += encode_string(2, shop_id)
    return body


class ShopPriceQueryPlugin(PluginBase):
    name = "shop-price-query"

    def __init__(self, tcp_client: TCPClient):
        super().__init__(tcp_client)
        self._operation_lock = asyncio.Lock()
        self._message_counters: Counter[int] = Counter()
        self._raw_message_counters: Counter[int] = Counter()
        self._recent_events: deque[dict[str, Any]] = deque(maxlen=80)
        self._recent_raw_messages: deque[dict[str, Any]] = deque(maxlen=120)
        self._domain_snapshots: dict[str, dict[str, Any]] = {}
        self._domain_version_records: list[dict[str, Any]] = []
        self._domain_version_by_type: dict[str, dict[int, str]] = {}
        self._domain_order: list[str] = []
        self._current_domain_id = ""
        self._current_chapter_id = ""
        self._shop_group_conditions: list[dict[str, Any]] = []
        self._shops: dict[str, dict[str, Any]] = {}
        self._queryable_shops: dict[str, dict[str, Any]] = {}
        self._goods_index: dict[str, dict[str, Any]] = {}
        self._frequency_limits: dict[str, int] = {}
        self._manual_refresh_limits: dict[str, int] = {}
        self._domain_channels: dict[str, dict[str, Any]] = {}
        self._refresh_case_counts: Counter[str] = Counter()
        self._frequency_limit_mgr_summary: Optional[dict[str, Any]] = None
        self._last_shop_sync_parse_meta: Optional[dict[str, Any]] = None
        self._last_shop_sync_feedback: Optional[dict[str, Any]] = None
        self._domain_shop_bindings = self._load_domain_shop_bindings()
        self._friend_simple_list: dict[str, dict[str, Any]] = {}
        self._friend_details: dict[str, dict[str, Any]] = {}

        self._last_domain_version_request: Optional[dict[str, Any]] = None
        self._last_domain_switch_request: Optional[dict[str, Any]] = None
        self._last_shop_begin_request: Optional[dict[str, Any]] = None
        self._last_friend_list_query: Optional[dict[str, Any]] = None
        self._last_friend_goods_price_query: Optional[dict[str, Any]] = None
        self._last_friend_shop_query: Optional[dict[str, Any]] = None

        self._structured_waiters: list[dict[str, Any]] = []
        self._raw_waiters: list[dict[str, Any]] = []
        self.tcp_client.add_message_listener(self._on_message)

    def _load_domain_shop_bindings(self) -> dict[str, dict[str, Any]]:
        if not BINDINGS_PATH.exists():
            return {}
        try:
            payload = json.loads(BINDINGS_PATH.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("[Plugin shop-price-query] 读取绑定文件失败: %s", exc)
            return {}

        bindings = payload.get("bindings") if isinstance(payload, dict) else None
        if not isinstance(bindings, dict):
            return {}

        normalized: dict[str, dict[str, Any]] = {}
        for domain_id, raw in bindings.items():
            if not isinstance(domain_id, str) or not isinstance(raw, dict):
                continue
            shop_ids = [str(item) for item in raw.get("shop_ids", []) if str(item or "").strip()]
            preferred_shop_id = str(raw.get("preferred_shop_id") or "")
            if preferred_shop_id and preferred_shop_id not in shop_ids:
                shop_ids.insert(0, preferred_shop_id)
            normalized[domain_id] = {
                "domain_id": domain_id,
                "shop_ids": shop_ids,
                "preferred_shop_id": preferred_shop_id,
                "channel_id": str(raw.get("channel_id") or ""),
                "note": str(raw.get("note") or ""),
                "updated_at": float(raw.get("updated_at") or 0.0),
                "updated_at_text": str(raw.get("updated_at_text") or ""),
                "source": str(raw.get("source") or "manual"),
            }
        return normalized

    def _save_domain_shop_bindings(self) -> None:
        BINDINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": _now_ts(),
            "updated_at_text": _now_iso(),
            "bindings": self._domain_shop_bindings,
        }
        BINDINGS_PATH.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def _apply_friend_list_simple_sync(self, parsed: dict[str, Any]) -> None:
        for item in parsed.get("friend_list") or []:
            role_id = int(item.get("role_id", 0) or 0)
            if role_id <= 0:
                continue
            self._friend_simple_list[str(role_id)] = dict(item)

    def _apply_friend_list_query(self, parsed: dict[str, Any]) -> None:
        for item in parsed.get("friend_list") or []:
            role_id = int(item.get("role_id", 0) or 0)
            if role_id <= 0:
                continue
            self._friend_details[str(role_id)] = dict(item)

    def _serialize_friend_list(self) -> list[dict[str, Any]]:
        role_keys = sorted(
            set(self._friend_simple_list.keys()) | set(self._friend_details.keys()),
            key=lambda item: int(item),
        )
        entries: list[dict[str, Any]] = []
        for role_key in role_keys:
            simple = dict(self._friend_simple_list.get(role_key) or {})
            detail = dict(self._friend_details.get(role_key) or {})
            friend_user_info = dict(detail.get("friend_user_info") or {})
            base_data = dict(friend_user_info.get("base_data") or {})
            spaceship_default = dict(friend_user_info.get("spaceship_default") or {})
            role_id = int(base_data.get("role_id", simple.get("role_id", 0)) or 0)
            entries.append(
                {
                    "role_id": role_id,
                    "name": str(base_data.get("name") or simple.get("name") or ""),
                    "remark_name": str(detail.get("remark_name") or simple.get("remark_name") or ""),
                    "short_id": str(base_data.get("short_id") or simple.get("short_id") or ""),
                    "online": bool(base_data.get("online", simple.get("online", False))),
                    "adventure_level": int(
                        base_data.get("adventure_level", simple.get("adventure_level", 0)) or 0
                    ),
                    "signature": str(base_data.get("signature") or simple.get("signature") or ""),
                    "create_time": int(detail.get("create_time", simple.get("create_time", 0)) or 0),
                    "last_login_time": int(base_data.get("last_login_time", 0) or 0),
                    "last_logout_time": int(
                        base_data.get("last_logout_time", simple.get("last_logout_time", 0)) or 0
                    ),
                    "user_avatar_id": int(
                        base_data.get("user_avatar_id", simple.get("user_avatar_id", 0)) or 0
                    ),
                    "user_avatar_frame_id": int(
                        base_data.get("user_avatar_frame_id", simple.get("user_avatar_frame_id", 0)) or 0
                    ),
                    "business_card_topic_id": int(
                        base_data.get("business_card_topic_id", simple.get("business_card_topic_id", 0)) or 0
                    ),
                    "help_flag": bool(spaceship_default.get("help_flag", simple.get("help_flag", False))),
                    "clue_flag": bool(spaceship_default.get("clue_flag", simple.get("clue_flag", False))),
                    "help_status": int(
                        spaceship_default.get("help_status", simple.get("help_status", 0)) or 0
                    ),
                    "guest_room_unlock": bool(
                        spaceship_default.get("unlock_guest_room", simple.get("guest_room_unlock", False))
                    ),
                    "clue_room_unlock": bool(
                        spaceship_default.get("unlock_clue_room", simple.get("clue_room_unlock", False))
                    ),
                    "source": [
                        source
                        for source, present in (
                            ("simple_sync", bool(simple)),
                            ("query", bool(detail)),
                        )
                        if present
                    ],
                }
            )
        entries.sort(
            key=lambda item: (
                0 if item.get("online") else 1,
                str(item.get("remark_name") or item.get("name") or ""),
                int(item.get("role_id", 0) or 0),
            )
        )
        return entries

    def _message_name(self, msgid: int) -> str:
        return MESSAGE_NAMES.get(int(msgid), f"Msg{int(msgid)}")

    def _serialize_counter(self, counter: Counter[int]) -> list[dict[str, Any]]:
        items = [
            {"msgid": int(msgid), "name": self._message_name(int(msgid)), "count": int(count)}
            for msgid, count in counter.items()
        ]
        items.sort(key=lambda item: (-int(item["count"]), int(item["msgid"])))
        return items

    def _push_event(self, event: dict[str, Any]) -> None:
        stored = {
            key: value
            for key, value in event.items()
            if key not in {"parsed"}
        }
        self._recent_events.appendleft(stored)

    def _record_raw_message(self, msgid: int, head_info: dict[str, Any], body: bytes) -> Optional[dict[str, Any]]:
        if msgid in PING_MSG_IDS:
            return None

        now = _now_ts()
        entry: dict[str, Any] = {
            "msgid": int(msgid),
            "message_name": self._message_name(msgid),
            "received_at": now,
            "received_at_text": _now_iso(now),
            "body_len": len(body),
            "up_seqid": int(head_info.get("up_seqid", 0) or 0),
            "down_seqid": int(head_info.get("down_seqid", 0) or 0),
            "checksum": int(head_info.get("checksum", 0) or 0),
            "is_compress": bool(head_info.get("is_compress", False)),
            "compressed_body_len": int(head_info.get("compressed_body_len", 0) or 0),
            "decompressed_body_len": int(head_info.get("decompressed_body_len", 0) or 0),
            "decompress_method": str(head_info.get("decompress_method") or ""),
            "decompress_error": str(head_info.get("decompress_error") or ""),
            "head_parse_error": str(head_info.get("parse_error") or ""),
            "body_hex_prefix": _hex_prefix(body, size=32),
            "fields": _summarize_proto_field_list(body, limit=8),
            "field_summary": _summarize_proto_fields(body, limit=8),
        }

        if msgid == MSG_ID_SC_ERROR:
            try:
                error_info = _parse_error_response(body)
            except Exception as exc:
                error_info = {"parse_error": str(exc)}

            error_code = int(error_info.get("error_code", -1))
            entry["error_code"] = error_code
            entry["error_name"] = ERROR_CODES.get(error_code, f"Unknown({error_code})")
            entry["error_explanation"] = ERROR_EXPLANATIONS.get(error_code, "")
            entry["error_details"] = str(error_info.get("details", "") or "")

        self._raw_message_counters[int(msgid)] += 1
        self._recent_raw_messages.appendleft(entry)
        return entry

    def _create_structured_waiter(self, msgids: Iterable[int]) -> asyncio.Future[dict[str, Any]]:
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._structured_waiters.append({"msgids": {int(item) for item in msgids}, "future": future})
        return future

    def _remove_structured_waiter(self, future: asyncio.Future[dict[str, Any]]) -> None:
        self._structured_waiters = [
            item for item in self._structured_waiters if item.get("future") is not future
        ]

    def _create_raw_waiter(self, msgid: Optional[int] = None) -> asyncio.Future[dict[str, Any]]:
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        msgids = None if msgid is None else {int(msgid)}
        self._raw_waiters.append({"msgids": msgids, "future": future})
        return future

    def _remove_raw_waiter(self, future: asyncio.Future[dict[str, Any]]) -> None:
        self._raw_waiters = [item for item in self._raw_waiters if item.get("future") is not future]

    def _notify_waiters(
        self,
        msgid: int,
        structured_event: Optional[dict[str, Any]],
        raw_entry: Optional[dict[str, Any]],
    ) -> None:
        if structured_event is not None:
            for item in list(self._structured_waiters):
                future = item["future"]
                if future.done():
                    continue
                if int(msgid) in item["msgids"]:
                    future.set_result(dict(structured_event))

        if raw_entry is not None:
            for item in list(self._raw_waiters):
                future = item["future"]
                if future.done():
                    continue
                msgids = item.get("msgids")
                if msgids is None or int(msgid) in msgids:
                    future.set_result(dict(raw_entry))

    def _upsert_domain_snapshot(self, domain: dict[str, Any], *, source: str) -> None:
        domain_id = str(domain.get("domain_id") or domain.get("chapter_id") or "").strip()
        if not domain_id:
            return

        current = dict(self._domain_snapshots.get(domain_id, {}))
        merged = {
            "domain_id": domain_id,
            "chapter_id": str(domain.get("chapter_id") or current.get("chapter_id") or domain_id),
            "version": str(domain.get("version") or current.get("version") or ""),
            "level": int(domain.get("level", current.get("level", 0)) or 0),
            "exp": int(domain.get("exp", current.get("exp", 0)) or 0),
            "dev_degree": domain.get("dev_degree") or current.get("dev_degree"),
            "updated_at": _now_ts(),
            "updated_at_text": _now_iso(),
            "sources": sorted(
                {
                    *list(current.get("sources", [])),
                    source,
                }
            ),
        }
        self._domain_snapshots[domain_id] = merged
        if domain_id not in self._domain_order:
            self._domain_order.append(domain_id)

    def _record_domain_version_record(self, record: dict[str, Any]) -> None:
        domain_id = str(record.get("domain_id") or record.get("chapter_id") or "").strip()
        if not domain_id:
            return

        stored = dict(record)
        stored["updated_at"] = _now_ts()
        stored["updated_at_text"] = _now_iso()
        self._domain_version_records.append(stored)
        self._domain_version_records = self._domain_version_records[-120:]

        data_type = int(record.get("data_type", 0) or 0)
        version = str(record.get("version") or "")
        if version:
            self._domain_version_by_type.setdefault(domain_id, {})[data_type] = version
            snapshot = dict(self._domain_snapshots.get(domain_id, {}))
            snapshot.setdefault("sources", [])
            if data_type == 3 and not snapshot.get("version"):
                snapshot["version"] = version
            snapshot["domain_id"] = domain_id
            snapshot["chapter_id"] = domain_id
            snapshot["updated_at"] = _now_ts()
            snapshot["updated_at_text"] = _now_iso()
            snapshot["sources"] = sorted({*snapshot.get("sources", []), "version_record"})
            self._domain_snapshots[domain_id] = snapshot
            if domain_id not in self._domain_order:
                self._domain_order.append(domain_id)

    def _rebuild_shop_snapshot(self, parsed: dict[str, Any]) -> None:
        self._shop_group_conditions = list(parsed.get("shop_group_conditions") or [])
        self._frequency_limits = {
            str(item.get("frequency_limit_id") or ""): int(item.get("count", 0) or 0)
            for item in parsed.get("frequency_limits") or []
            if str(item.get("frequency_limit_id") or "")
        }
        self._manual_refresh_limits = {
            str(item.get("frequency_limit_id") or ""): int(item.get("count", 0) or 0)
            for item in parsed.get("manual_refresh_limits") or []
            if str(item.get("frequency_limit_id") or "")
        }
        self._frequency_limit_mgr_summary = parsed.get("frequency_limit_mgr_summary")

        self._domain_channels = {}
        group_data = parsed.get("shop_group_data") or {}
        for item in group_data.get("domain_channels") or []:
            domain_id = str(item.get("domain_id") or "")
            if not domain_id:
                continue
            self._domain_channels[domain_id] = {
                "domain_id": domain_id,
                "channels": dict(item.get("channels") or {}),
                "version": str(item.get("version") or ""),
                "channel_count": int(item.get("channel_count", len(item.get("channels") or {})) or 0),
            }
            if domain_id not in self._domain_snapshots:
                self._domain_snapshots[domain_id] = {
                    "domain_id": domain_id,
                    "chapter_id": domain_id,
                    "version": str(item.get("version") or ""),
                    "level": 0,
                    "exp": 0,
                    "dev_degree": None,
                    "updated_at": _now_ts(),
                    "updated_at_text": _now_iso(),
                    "sources": ["shop_group"],
                }
            else:
                snapshot = dict(self._domain_snapshots[domain_id])
                if not snapshot.get("version") and item.get("version"):
                    snapshot["version"] = str(item.get("version") or "")
                snapshot["updated_at"] = _now_ts()
                snapshot["updated_at_text"] = _now_iso()
                snapshot["sources"] = sorted({*snapshot.get("sources", []), "shop_group"})
                self._domain_snapshots[domain_id] = snapshot
            if domain_id not in self._domain_order:
                self._domain_order.append(domain_id)

        shops: dict[str, dict[str, Any]] = {}
        queryable_shops: dict[str, dict[str, Any]] = {}
        goods_index: dict[str, dict[str, Any]] = {}
        refresh_case_counts: Counter[str] = Counter()

        for raw_shop in parsed.get("shops") or []:
            shop_id = str(raw_shop.get("shop_id") or "").strip()
            if not shop_id:
                continue

            goods_map: dict[str, dict[str, Any]] = {}
            random_domain = raw_shop.get("random_domain") or {}
            for item in random_domain.get("domain_rand_goods") or []:
                goods_id = str(item.get("goods_id") or "").strip()
                if not goods_id:
                    continue
                goods_map.setdefault(goods_id, {"goods_id": goods_id})
                goods_map[goods_id]["history_prices"] = list(item.get("history_prices") or [])
                goods_map[goods_id]["history_price_count"] = int(
                    item.get("history_price_count", len(item.get("history_prices") or [])) or 0
                )

            for goods_id, position in (random_domain.get("positions") or {}).items():
                normalized_goods_id = str(goods_id or "").strip()
                if not normalized_goods_id:
                    continue
                goods_map.setdefault(normalized_goods_id, {"goods_id": normalized_goods_id})
                goods_map[normalized_goods_id]["quantity"] = int(position.get("quantity", 0) or 0)
                goods_map[normalized_goods_id]["avg_price"] = int(position.get("avg_price", 0) or 0)

            random_refresh = raw_shop.get("random_refresh") or {}
            for item in random_refresh.get("dynamic_goods") or []:
                goods_id = str(item.get("goods_id") or "").strip()
                if not goods_id:
                    continue
                goods_map.setdefault(goods_id, {"goods_id": goods_id})
                goods_map[goods_id]["goods_template_id"] = str(item.get("goods_template_id") or "")

            local_goods: list[dict[str, Any]] = []
            for goods_id, item in goods_map.items():
                local_goods.append(_build_local_goods_entry(goods_id, item))

            local_goods.sort(key=lambda item: _sort_key_by_numeric_tail(str(item.get("goods_id") or "")))
            today_price_goods_count = sum(1 for item in local_goods if item.get("has_today_price"))
            owned_goods_count = sum(1 for item in local_goods if item.get("is_owned"))
            dynamic_goods_count = len(random_refresh.get("dynamic_goods") or [])
            domain_rand_goods_count = int(random_domain.get("domain_rand_goods_count", 0) or 0)
            position_count = int(random_domain.get("position_count", 0) or 0)

            overview = {
                "shop_id": shop_id,
                "shop_refresh_type": int(raw_shop.get("shop_refresh_type", 0) or 0),
                "unlock_condition_values": dict(raw_shop.get("unlock_condition_values") or {}),
                "unlock_condition_flags": dict(raw_shop.get("unlock_condition_flags") or {}),
                "discount_count": int(raw_shop.get("discount_count", 0) or 0),
                "goods_unlock_conditions": list(raw_shop.get("goods_unlock_conditions") or []),
                "is_dynamic_good": bool(raw_shop.get("is_dynamic_good")),
                "is_dynamic_discount": bool(raw_shop.get("is_dynamic_discount")),
                "goods_time_range_count": int(raw_shop.get("goods_time_range_count", 0) or 0),
                "random_type": int(raw_shop.get("random_type", 0) or 0),
                "refresh_data_case": str(raw_shop.get("refresh_data_case") or "None"),
                "refresh_data_case_value": int(raw_shop.get("refresh_data_case_value", 0) or 0),
                "dynamic_goods_count": dynamic_goods_count,
                "domain_rand_goods_count": domain_rand_goods_count,
                "position_count": position_count,
                "owned_goods_count": owned_goods_count,
                "today_price_goods_count": today_price_goods_count,
                "local_goods_count": len(local_goods),
                "updated_at": _now_ts(),
                "updated_at_text": _now_iso(),
            }
            shops[shop_id] = overview
            refresh_case_counts[overview["refresh_data_case"]] += 1

            if local_goods:
                queryable_shops[shop_id] = {
                    **overview,
                    "local_goods": local_goods,
                }
                for goods in local_goods:
                    key = f"{shop_id}::{goods['goods_id']}"
                    goods_index[key] = {
                        "key": key,
                        "shop_id": shop_id,
                        **goods,
                    }

        self._shops = shops
        self._queryable_shops = queryable_shops
        self._goods_index = goods_index
        self._refresh_case_counts = refresh_case_counts

    def _build_domain_candidates(self) -> list[dict[str, Any]]:
        domain_ids: set[str] = set(self._domain_snapshots.keys())
        domain_ids.update(self._domain_channels.keys())
        domain_ids.update(self._domain_shop_bindings.keys())
        domain_ids.update(
            str(item.get("domain_id") or item.get("chapter_id") or "")
            for item in self._domain_version_records
            if str(item.get("domain_id") or item.get("chapter_id") or "")
        )
        if self._current_domain_id:
            domain_ids.add(self._current_domain_id)

        ordered_ids = [
            item for item in self._domain_order if item in domain_ids
        ] + sorted(item for item in domain_ids if item not in self._domain_order)

        derived: list[dict[str, Any]] = []
        for domain_id in ordered_ids:
            snapshot = dict(self._domain_snapshots.get(domain_id, {}))
            channel_data = dict(self._domain_channels.get(domain_id, {}))
            binding = dict(self._domain_shop_bindings.get(domain_id, {}))
            versions_by_type = dict(self._domain_version_by_type.get(domain_id, {}))

            channel_levels = dict(channel_data.get("channels") or {})
            channel_ids = sorted(channel_levels.keys())
            preferred_shop_id = str(binding.get("preferred_shop_id") or "")
            bound_shop_ids = [
                str(item)
                for item in binding.get("shop_ids", [])
                if str(item or "").strip()
            ]
            if preferred_shop_id and preferred_shop_id not in bound_shop_ids:
                bound_shop_ids.insert(0, preferred_shop_id)

            level = int(snapshot.get("level", 0) or 0)
            version = (
                str(snapshot.get("version") or "")
                or str(versions_by_type.get(3) or "")
                or str(channel_data.get("version") or "")
            )
            current = domain_id == self._current_domain_id if self._current_domain_id else False

            derived.append(
                {
                    "domain_id": domain_id,
                    "chapter_id": str(snapshot.get("chapter_id") or domain_id),
                    "display_name": str(binding.get("display_name") or domain_id),
                    "current": current,
                    "level": level,
                    "exp": int(snapshot.get("exp", 0) or 0),
                    "version": version,
                    "channel_ids": channel_ids,
                    "channel_levels": channel_levels,
                    "channel_count": len(channel_ids),
                    "shop_version": str(channel_data.get("version") or ""),
                    "bound_shop_ids": bound_shop_ids,
                    "bound_shop_count": len(bound_shop_ids),
                    "preferred_shop_id": preferred_shop_id,
                    "binding_channel_id": str(binding.get("channel_id") or ""),
                    "binding_note": str(binding.get("note") or ""),
                    "known_from": sorted(
                        {
                            *list(snapshot.get("sources", [])),
                            *(["binding"] if binding else []),
                            *(["shop_group"] if channel_data else []),
                            *(["chapter_switch"] if current else []),
                        }
                    ),
                }
            )
        return derived

    def _build_domainshop_summary(self) -> dict[str, Any]:
        domainshops: list[dict[str, Any]] = []
        total_goods_count = 0
        total_owned_goods_count = 0
        total_today_price_goods_count = 0
        total_holding_quantity = 0

        for shop_id in sorted(self._queryable_shops.keys(), key=_sort_key_by_numeric_tail):
            shop = dict(self._queryable_shops.get(shop_id) or {})
            normalized_shop_id = str(shop.get("shop_id") or shop_id or "").strip()
            if not normalized_shop_id.startswith("domainshop_page_"):
                continue

            refresh_case = str(shop.get("refresh_data_case") or "")
            domain_rand_goods_count = int(shop.get("domain_rand_goods_count", 0) or 0)
            local_goods = list(shop.get("local_goods") or [])
            if not local_goods and refresh_case != "RandomDomain" and domain_rand_goods_count <= 0:
                continue

            domainshop_id = _infer_domainshop_id_from_shop_id(normalized_shop_id)
            domain_channel = dict(self._domain_channels.get(domainshop_id) or {})
            domain_snapshot = dict(self._domain_snapshots.get(domainshop_id) or {})
            channel_levels = dict(domain_channel.get("channels") or {})
            channel_ids = sorted(channel_levels.keys(), key=_sort_key_by_numeric_tail)

            goods_payload: list[dict[str, Any]] = []
            holding_quantity_total = 0
            owned_goods_count = 0
            today_price_goods_count = 0
            for raw_goods in sorted(
                local_goods,
                key=lambda item: _sort_key_by_numeric_tail(str(item.get("goods_id") or "")),
            ):
                history_prices = [int(value) for value in (raw_goods.get("history_prices") or [])]
                holding_quantity = int(raw_goods.get("holding_quantity", raw_goods.get("quantity", 0)) or 0)
                holding_avg_price = int(raw_goods.get("holding_avg_price", raw_goods.get("avg_price", 0)) or 0)
                has_today_price = bool(raw_goods.get("has_today_price")) or bool(history_prices)
                today_price = int(raw_goods.get("today_price", history_prices[0] if history_prices else 0) or 0)
                is_owned = bool(raw_goods.get("is_owned")) or holding_quantity > 0
                history_price_count = int(
                    raw_goods.get("history_price_count", len(history_prices)) or len(history_prices)
                )

                goods_payload.append(
                    {
                        "goods_id": str(raw_goods.get("goods_id") or ""),
                        "goods_template_id": str(raw_goods.get("goods_template_id") or ""),
                        "today_price": today_price,
                        "has_today_price": has_today_price,
                        "holding_quantity": holding_quantity,
                        "holding_avg_price": holding_avg_price,
                        "is_owned": is_owned,
                        "history_prices": history_prices,
                        "history_price_count": history_price_count,
                    }
                )

                holding_quantity_total += holding_quantity
                if is_owned:
                    owned_goods_count += 1
                if has_today_price:
                    today_price_goods_count += 1

            goods_count = len(goods_payload)
            total_goods_count += goods_count
            total_owned_goods_count += owned_goods_count
            total_today_price_goods_count += today_price_goods_count
            total_holding_quantity += holding_quantity_total

            domainshops.append(
                {
                    "domainshop_id": domainshop_id,
                    "shop_id": normalized_shop_id,
                    "shop_kind": _infer_domainshop_kind_from_shop_id(normalized_shop_id),
                    "refresh_data_case": refresh_case,
                    "refresh_data_case_value": int(shop.get("refresh_data_case_value", 0) or 0),
                    "version": str(domain_snapshot.get("version") or domain_channel.get("version") or ""),
                    "channel_ids": channel_ids,
                    "channel_levels": channel_levels,
                    "channel_count": len(channel_ids),
                    "goods_count": goods_count,
                    "domain_rand_goods_count": domain_rand_goods_count,
                    "position_count": int(shop.get("position_count", 0) or 0),
                    "owned_goods_count": owned_goods_count,
                    "today_price_goods_count": today_price_goods_count,
                    "holding_quantity_total": holding_quantity_total,
                    "goods": goods_payload,
                }
            )

        return {
            "generated_at": _now_ts(),
            "generated_at_text": _now_iso(),
            "domainshop_count": len(domainshops),
            "goods_count": total_goods_count,
            "owned_goods_count": total_owned_goods_count,
            "today_price_goods_count": total_today_price_goods_count,
            "holding_quantity_total": total_holding_quantity,
            "domainshops": domainshops,
        }

    def _serialize_shops(self) -> list[dict[str, Any]]:
        return [self._shops[key] for key in sorted(self._shops.keys())]

    def _serialize_queryable_shops(self) -> list[dict[str, Any]]:
        return [self._queryable_shops[key] for key in sorted(self._queryable_shops.keys())]

    def _serialize_goods_index(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for key in sorted(self._goods_index.keys()):
            goods = self._goods_index[key]
            entries.append(
                {
                    "key": str(goods.get("key") or key),
                    "shop_id": str(goods.get("shop_id") or ""),
                    "goods_id": str(goods.get("goods_id") or ""),
                    "goods_template_id": str(goods.get("goods_template_id") or ""),
                    "today_price": int(goods.get("today_price", 0) or 0),
                    "has_today_price": bool(goods.get("has_today_price")),
                    "avg_price": int(goods.get("avg_price", 0) or 0),
                    "quantity": int(goods.get("quantity", 0) or 0),
                    "holding_avg_price": int(goods.get("holding_avg_price", 0) or 0),
                    "holding_quantity": int(goods.get("holding_quantity", 0) or 0),
                    "is_owned": bool(goods.get("is_owned")),
                    "history_price_count": int(goods.get("history_price_count", 0) or 0),
                }
            )
        return entries

    def get_domainshop_summary(self) -> dict[str, Any]:
        return self._build_domainshop_summary()

    def get_state(self) -> dict[str, Any]:
        derived_domains = self._build_domain_candidates()
        domainshop_summary = self._build_domainshop_summary()
        friend_list = self._serialize_friend_list()
        return {
            "plugin": self.name,
            "generated_at": _now_ts(),
            "generated_at_text": _now_iso(),
            "current_domain_id": self._current_domain_id,
            "current_chapter_id": self._current_chapter_id,
            "known_domains": [
                self._domain_snapshots[key]
                for key in sorted(self._domain_snapshots.keys())
            ],
            "domain_version_records": list(self._domain_version_records),
            "derived_domains": derived_domains,
            "domainshop_summary": domainshop_summary,
            "shop_group_conditions": list(self._shop_group_conditions),
            "shops": self._serialize_shops(),
            "queryable_shops": self._serialize_queryable_shops(),
            "goods_index": self._serialize_goods_index(),
            "frequency_limits": [
                {"frequency_limit_id": key, "count": value}
                for key, value in sorted(self._frequency_limits.items())
            ],
            "manual_refresh_limits": [
                {"frequency_limit_id": key, "count": value}
                for key, value in sorted(self._manual_refresh_limits.items())
            ],
            "domain_channels": [
                self._domain_channels[key]
                for key in sorted(self._domain_channels.keys())
            ],
            "last_shop_sync_parse_meta": self._last_shop_sync_parse_meta,
            "last_shop_sync_feedback": self._last_shop_sync_feedback,
            "refresh_case_counts": [
                {"case": key, "count": int(value)}
                for key, value in sorted(self._refresh_case_counts.items())
            ],
            "bindings": self._domain_shop_bindings,
            "friend_list": friend_list,
            "message_counters": self._serialize_counter(self._message_counters),
            "raw_message_counters": self._serialize_counter(self._raw_message_counters),
            "recent_events": list(self._recent_events),
            "recent_raw_messages": list(self._recent_raw_messages),
            "last_domain_version_request": self._last_domain_version_request,
            "last_domain_switch_request": self._last_domain_switch_request,
            "last_shop_begin_request": self._last_shop_begin_request,
            "last_friend_list_query": self._last_friend_list_query,
            "last_friend_goods_price_query": self._last_friend_goods_price_query,
            "last_friend_shop_query": self._last_friend_shop_query,
            "summary": {
                "domain_count": len(derived_domains),
                "known_domain_count": len(self._domain_snapshots),
                "record_count": len(self._domain_version_records),
                "shop_count": len(self._shops),
                "queryable_shop_count": len(self._queryable_shops),
                "goods_count": len(self._goods_index),
                "domainshop_count": int(domainshop_summary.get("domainshop_count", 0) or 0),
                "domainshop_goods_count": int(domainshop_summary.get("goods_count", 0) or 0),
                "domainshop_owned_goods_count": int(domainshop_summary.get("owned_goods_count", 0) or 0),
                "domainshop_holding_quantity_total": int(domainshop_summary.get("holding_quantity_total", 0) or 0),
                "today_price_goods_count": sum(
                    1 for goods in self._goods_index.values() if bool(goods.get("has_today_price"))
                ),
                "owned_goods_count": sum(
                    1 for goods in self._goods_index.values() if bool(goods.get("is_owned"))
                ),
                "domain_rand_goods_count": sum(
                    int(shop.get("domain_rand_goods_count", 0) or 0) for shop in self._shops.values()
                ),
                "friend_count": len(friend_list),
                "bound_domain_count": len(self._domain_shop_bindings),
                "current_domain_id": self._current_domain_id,
                "last_shop_sync_parse_source": str(
                    ((self._last_shop_sync_parse_meta or {}).get("best_attempt") or {}).get("source")
                    or ""
                ),
                "last_shop_sync_parse_score": int(
                    (((self._last_shop_sync_parse_meta or {}).get("best_attempt") or {}).get("score", 0) or 0)
                ),
            },
        }

    def _handle_structured_message(self, msgid: int, body: bytes) -> dict[str, Any]:
        now = _now_ts()
        event: dict[str, Any] = {
            "msgid": int(msgid),
            "message_name": self._message_name(msgid),
            "received_at": now,
            "received_at_text": _now_iso(now),
            "body_len": len(body),
            "kind": "message",
            "summary": {},
            "parsed": None,
        }
        self._message_counters[int(msgid)] += 1

        if msgid == MSG_ID_SC_ERROR:
            error_info = _parse_error_response(body)
            error_code = int(error_info.get("error_code", -1))
            event["kind"] = "error"
            event["summary"] = {
                "error_code": error_code,
                "error_name": ERROR_CODES.get(error_code, f"Unknown({error_code})"),
                "details": str(error_info.get("details", "") or ""),
            }
            event["parsed"] = event["summary"]
            return event

        if msgid == MSG_ID_SC_ITEM_BAG_CHG_SPACESHIP_CHAPTER:
            parsed = _parse_item_bag_change_spaceship_chapter(body)
            self._current_domain_id = str(parsed.get("domain_id") or "")
            self._current_chapter_id = str(parsed.get("chapter_id") or "")
            if self._current_domain_id:
                snapshot = dict(self._domain_snapshots.get(self._current_domain_id, {}))
                snapshot["domain_id"] = self._current_domain_id
                snapshot["chapter_id"] = self._current_domain_id
                snapshot["updated_at"] = _now_ts()
                snapshot["updated_at_text"] = _now_iso()
                snapshot["sources"] = sorted({*snapshot.get("sources", []), "chapter_switch"})
                self._domain_snapshots[self._current_domain_id] = snapshot
                if self._current_domain_id not in self._domain_order:
                    self._domain_order.append(self._current_domain_id)
            event["kind"] = "chapter_switch"
            event["summary"] = {"domain_id": self._current_domain_id}
            event["parsed"] = parsed
            return event

        if msgid == MSG_ID_SC_DOMAIN_DEVELOPMENT_SYSTEM_SYNC:
            parsed = _parse_domain_development_system_sync(body)
            for item in parsed.get("domains") or []:
                self._upsert_domain_snapshot(item, source="development_system_sync")
            event["kind"] = "domain_development_system_sync"
            event["summary"] = {
                "count": int(parsed.get("count", 0) or 0),
                "chapter_ids": parsed.get("chapter_ids") or [],
            }
            event["parsed"] = parsed
            return event

        if msgid == MSG_ID_SC_DOMAIN_DEVELOPMENT_SYNC:
            parsed = _parse_domain_development_sync(body)
            domain = parsed.get("domain")
            if isinstance(domain, dict):
                self._upsert_domain_snapshot(domain, source="development_sync")
            event["kind"] = "domain_development_sync"
            event["summary"] = {
                "domain_id": domain.get("domain_id") if isinstance(domain, dict) else "",
                "version": domain.get("version") if isinstance(domain, dict) else "",
                "level": domain.get("level") if isinstance(domain, dict) else 0,
            }
            event["parsed"] = parsed
            return event

        if msgid == MSG_ID_SC_DOMAIN_DEVELOPMENT_READ_VERSION_INFO_MODIFY:
            parsed = _parse_domain_development_read_version_info_modify(body)
            for item in parsed.get("records") or []:
                self._record_domain_version_record(item)
            event["kind"] = "domain_development_read_version_info_modify"
            event["summary"] = {
                "count": int(parsed.get("count", 0) or 0),
                "chapter_ids": parsed.get("chapter_ids") or [],
            }
            event["parsed"] = parsed
            return event

        if msgid == MSG_ID_SC_FRIEND_LIST_SIMPLE_SYNC:
            parsed = _parse_friend_list_simple_sync(body)
            self._apply_friend_list_simple_sync(parsed)
            event["kind"] = "friend_list_simple_sync"
            event["summary"] = {
                "count": int(parsed.get("count", 0) or 0),
                "role_ids": parsed.get("role_ids") or [],
            }
            event["parsed"] = parsed
            return event

        if msgid == MSG_ID_SC_FRIEND_LIST_QUERY:
            parsed = _parse_friend_list_query_response(body)
            self._apply_friend_list_query(parsed)
            event["kind"] = "friend_list_query"
            event["summary"] = {
                "count": int(parsed.get("count", 0) or 0),
                "role_ids": parsed.get("role_ids") or [],
            }
            event["parsed"] = parsed
            return event

        if msgid == MSG_ID_SC_SHOP_BEGIN:
            event["kind"] = "shop_begin"
            event["summary"] = {"fields": _summarize_proto_field_list(body, limit=8)}
            event["parsed"] = {"fields": event["summary"]["fields"]}
            return event

        if msgid == MSG_ID_SC_SHOP_SYNC:
            parse_result = _parse_shop_sync_with_fallbacks(body)
            best_attempt = dict(parse_result.get("best_attempt") or {})
            self._last_shop_sync_parse_meta = {
                "received_at": now,
                "received_at_text": _now_iso(now),
                "attempt_count": int(parse_result.get("attempt_count", 0) or 0),
                "best_attempt": best_attempt,
                "attempts": list(parse_result.get("attempts") or []),
            }

            parsed = parse_result.get("parsed")
            if parse_result.get("success") and isinstance(parsed, dict):
                self._rebuild_shop_snapshot(parsed)
                event["kind"] = "shop_sync"
                event["summary"] = {
                    "shop_count": int(parsed.get("shop_count", 0) or 0),
                    "queryable_shop_count": len(self._queryable_shops),
                    "domain_channel_count": len(self._domain_channels),
                    "refresh_case_counts": {
                        key: int(value) for key, value in self._refresh_case_counts.items()
                    },
                    "parse_source": str(best_attempt.get("source") or ""),
                    "parse_score": int(best_attempt.get("score", 0) or 0),
                    "attempt_count": int(parse_result.get("attempt_count", 0) or 0),
                }
                event["parsed"] = {
                    **parsed,
                    "parse_meta": self._last_shop_sync_parse_meta,
                }
            else:
                event["kind"] = "shop_sync_unparsed"
                event["summary"] = {
                    "parse_source": str(best_attempt.get("source") or ""),
                    "parse_score": int(best_attempt.get("score", 0) or 0),
                    "best_error": str(best_attempt.get("error") or ""),
                    "attempt_count": int(parse_result.get("attempt_count", 0) or 0),
                    "body_hex_prefix": _hex_prefix(body, size=32),
                }
                event["parsed"] = {
                    "best_attempt": best_attempt,
                    "attempts": list(parse_result.get("attempts") or []),
                }
            return event

        if msgid == MSG_ID_SC_SHOP_QUERY_FRIEND_GOODS_PRICE:
            parsed = _parse_friend_goods_price_response(body)
            event["kind"] = "friend_goods_price"
            event["summary"] = {"count": int(parsed.get("count", 0) or 0)}
            event["parsed"] = parsed
            return event

        if msgid == MSG_ID_SC_SHOP_QUERY_FRIEND_SHOP:
            parsed = _parse_friend_shop_response(body)
            event["kind"] = "friend_shop"
            event["summary"] = {
                "friend_role_id": int(parsed.get("friend_role_id", 0) or 0),
                "shop_goods_count": int(parsed.get("shop_goods_count", 0) or 0),
                "his_price_count": int(parsed.get("his_price_count", 0) or 0),
            }
            event["parsed"] = parsed
            return event

        event["summary"] = {"fields": _summarize_proto_field_list(body, limit=8)}
        event["parsed"] = {"fields": event["summary"]["fields"]}
        return event

    def _on_message(self, msgid: int, head_info: dict[str, Any], body: bytes) -> None:
        raw_entry = self._record_raw_message(int(msgid), head_info, body)
        structured_event = None
        if int(msgid) in {
            MSG_ID_SC_ERROR,
            MSG_ID_SC_ITEM_BAG_CHG_SPACESHIP_CHAPTER,
            MSG_ID_SC_DOMAIN_DEVELOPMENT_SYSTEM_SYNC,
            MSG_ID_SC_DOMAIN_DEVELOPMENT_SYNC,
            MSG_ID_SC_DOMAIN_DEVELOPMENT_READ_VERSION_INFO_MODIFY,
            MSG_ID_SC_FRIEND_LIST_SIMPLE_SYNC,
            MSG_ID_SC_FRIEND_LIST_QUERY,
            MSG_ID_SC_SHOP_BEGIN,
            MSG_ID_SC_SHOP_SYNC,
            MSG_ID_SC_SHOP_QUERY_FRIEND_GOODS_PRICE,
            MSG_ID_SC_SHOP_QUERY_FRIEND_SHOP,
        }:
            structured_event = self._handle_structured_message(int(msgid), body)
            self._push_event(structured_event)

        if int(msgid) == MSG_ID_SC_SHOP_SYNC:
            self._last_shop_sync_feedback = {
                "msgid": int(msgid),
                "message_name": self._message_name(int(msgid)),
                "received_at": _now_ts(),
                "received_at_text": _now_iso(),
                "structured_event": dict(structured_event) if isinstance(structured_event, dict) else None,
                "raw_message": dict(raw_entry) if isinstance(raw_entry, dict) else None,
            }

        self._notify_waiters(int(msgid), structured_event, raw_entry)

    @staticmethod
    def _default_raw_probe_timeout(timeout: float) -> float:
        value = float(timeout or 0.0)
        if value <= 0:
            return 3.0
        return max(2.0, min(value, 6.0))

    async def _wait_for_observation(
        self,
        msgids: Iterable[int],
        *,
        timeout: float,
    ) -> dict[str, Any]:
        future = self._create_structured_waiter(msgids)
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        finally:
            self._remove_structured_waiter(future)

    async def _wait_for_raw_observation(
        self,
        *,
        timeout: float,
        msgid: Optional[int] = None,
    ) -> dict[str, Any]:
        future = self._create_raw_waiter(msgid)
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        finally:
            self._remove_raw_waiter(future)

    async def _wait_for_existing_observation_with_raw_fallback(
        self,
        *,
        expected_msgids: Iterable[int],
        timeout: float,
        raw_msgid: Optional[int] = None,
        raw_probe_timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        structured_future = self._create_structured_waiter(expected_msgids)
        raw_future = self._create_raw_waiter(raw_msgid)
        raw_probe_window = (
            self._default_raw_probe_timeout(timeout)
            if raw_probe_timeout is None
            else float(raw_probe_timeout)
        )
        try:
            try:
                observed = await asyncio.wait_for(structured_future, timeout=timeout)
                return {
                    "observation_kind": "expected",
                    "observed": observed,
                    "raw_observed": None,
                    "raw_probe_timeout": raw_probe_window,
                }
            except asyncio.TimeoutError:
                try:
                    raw_observed = await asyncio.wait_for(raw_future, timeout=raw_probe_window)
                    return {
                        "observation_kind": "raw",
                        "observed": None,
                        "raw_observed": raw_observed,
                        "raw_probe_timeout": raw_probe_window,
                    }
                except asyncio.TimeoutError:
                    return {
                        "observation_kind": "timeout",
                        "observed": None,
                        "raw_observed": None,
                        "raw_probe_timeout": raw_probe_window,
                    }
        finally:
            self._remove_structured_waiter(structured_future)
            self._remove_raw_waiter(raw_future)

    async def _send_and_wait_for_observation_with_raw_fallback(
        self,
        *,
        msgid: int,
        body: bytes,
        expected_msgids: Iterable[int],
        timeout: float,
        raw_msgid: Optional[int] = None,
        raw_probe_timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        structured_future = self._create_structured_waiter(expected_msgids)
        raw_future = self._create_raw_waiter(raw_msgid)
        raw_probe_window = (
            self._default_raw_probe_timeout(timeout)
            if raw_probe_timeout is None
            else float(raw_probe_timeout)
        )
        try:
            send_meta = await self.tcp_client.send_message(int(msgid), body)
            try:
                observed = await asyncio.wait_for(structured_future, timeout=timeout)
                return {
                    "send_meta": send_meta,
                    "observation_kind": "expected",
                    "observed": observed,
                    "raw_observed": None,
                    "raw_probe_timeout": raw_probe_window,
                }
            except asyncio.TimeoutError:
                try:
                    raw_observed = await asyncio.wait_for(raw_future, timeout=raw_probe_window)
                    return {
                        "send_meta": send_meta,
                        "observation_kind": "raw",
                        "observed": None,
                        "raw_observed": raw_observed,
                        "raw_probe_timeout": raw_probe_window,
                    }
                except asyncio.TimeoutError:
                    return {
                        "send_meta": send_meta,
                        "observation_kind": "timeout",
                        "observed": None,
                        "raw_observed": None,
                        "raw_probe_timeout": raw_probe_window,
                    }
        finally:
            self._remove_structured_waiter(structured_future)
            self._remove_raw_waiter(raw_future)

    async def _read_domain_development_versions_impl(
        self,
        chapter_ids: list[str],
        *,
        timeout: float,
    ) -> dict[str, Any]:
        requested_at = _now_ts()
        results: list[dict[str, Any]] = []
        for chapter_id in chapter_ids:
            response = await self._send_and_wait_for_observation_with_raw_fallback(
                msgid=MSG_ID_CS_DOMAIN_DEVELOPMENT_READ_VERSION_INFO,
                body=build_domain_development_read_version_info_body(chapter_id),
                expected_msgids={
                    MSG_ID_SC_DOMAIN_DEVELOPMENT_READ_VERSION_INFO_MODIFY,
                    MSG_ID_SC_DOMAIN_DEVELOPMENT_SYSTEM_SYNC,
                    MSG_ID_SC_DOMAIN_DEVELOPMENT_SYNC,
                },
                timeout=timeout,
            )
            results.append({"chapter_id": chapter_id, **response})

        payload = {
            "requested_at": requested_at,
            "requested_at_text": _now_iso(requested_at),
            "requested_chapter_ids": chapter_ids,
            "responses": results,
            "summary": {
                "count": len(results),
                "chapter_ids": chapter_ids,
                "record_count": len(self._domain_version_records),
            },
            "state": self.get_state(),
        }
        self._last_domain_version_request = payload
        return payload

    async def read_domain_development_versions(
        self,
        chapter_id: Optional[str] = None,
        *,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        async with self._operation_lock:
            candidates: list[str] = []
            normalized_chapter_id = str(chapter_id or "").strip()
            if normalized_chapter_id:
                candidates = [normalized_chapter_id]
            elif self._current_domain_id:
                candidates = [self._current_domain_id]
            else:
                candidates = [item["domain_id"] for item in self._build_domain_candidates()]

            if not candidates:
                raise RuntimeError("当前没有可读取版本的地区")

            deduped: list[str] = []
            seen: set[str] = set()
            for item in candidates:
                if item not in seen:
                    deduped.append(item)
                    seen.add(item)
            return await self._read_domain_development_versions_impl(deduped, timeout=float(timeout))

    async def observe_domain_development(self, *, timeout: float = 10.0) -> dict[str, Any]:
        async with self._operation_lock:
            try:
                observed = await self._wait_for_observation(
                    {
                        MSG_ID_SC_DOMAIN_DEVELOPMENT_SYSTEM_SYNC,
                        MSG_ID_SC_DOMAIN_DEVELOPMENT_SYNC,
                        MSG_ID_SC_DOMAIN_DEVELOPMENT_READ_VERSION_INFO_MODIFY,
                    },
                    timeout=float(timeout),
                )
                return {"timeout": False, "observed": observed, "state": self.get_state()}
            except asyncio.TimeoutError:
                return {"timeout": True, "observed": None, "state": self.get_state()}

    async def _change_current_domain_impl(self, domain_id: str, *, timeout: float) -> dict[str, Any]:
        request_started = _now_ts()
        payload = {
            "domain_id": domain_id,
            "sent_at": request_started,
            "sent_at_text": _now_iso(request_started),
            "timeout": float(timeout),
        }
        response = await self._send_and_wait_for_observation_with_raw_fallback(
            msgid=MSG_ID_CS_ITEM_BAG_CHG_SPACESHIP_CHAPTER,
            body=build_change_spaceship_chapter_body(domain_id),
            expected_msgids={MSG_ID_SC_ITEM_BAG_CHG_SPACESHIP_CHAPTER},
            timeout=float(timeout),
        )
        payload.update(response)
        payload["completed_at"] = _now_ts()
        payload["completed_at_text"] = _now_iso(payload["completed_at"])
        payload["observed_msgid"] = (
            int((payload.get("observed") or {}).get("msgid", 0) or 0)
            if payload.get("observed")
            else 0
        )
        payload["raw_observed_msgid"] = (
            int((payload.get("raw_observed") or {}).get("msgid", 0) or 0)
            if payload.get("raw_observed")
            else 0
        )
        self._last_domain_switch_request = payload
        return {**payload, "state": self.get_state()}

    async def change_current_domain(self, domain_id: str, *, timeout: float = 10.0) -> dict[str, Any]:
        normalized_domain_id = str(domain_id or "").strip()
        if not normalized_domain_id:
            raise ValueError("domain_id 不能为空")
        async with self._operation_lock:
            return await self._change_current_domain_impl(normalized_domain_id, timeout=float(timeout))

    def _has_shop_sync_snapshot(self) -> bool:
        if self._shops or self._queryable_shops or self._domain_channels:
            return True
        best_attempt = ((self._last_shop_sync_parse_meta or {}).get("best_attempt") or {})
        return int(best_attempt.get("score", 0) or 0) > 0

    def _get_latest_shop_sync_event(self) -> Optional[dict[str, Any]]:
        for event in self._recent_events:
            if int(event.get("msgid", 0) or 0) == MSG_ID_SC_SHOP_SYNC:
                return dict(event)
        return None

    async def _enter_shop_impl(self, *, domain_id: Optional[str], timeout: float) -> dict[str, Any]:
        resolved_domain_id = str(domain_id or "").strip()
        if not resolved_domain_id:
            if self._current_domain_id:
                resolved_domain_id = self._current_domain_id
            else:
                derived_domains = self._build_domain_candidates()
                if len(derived_domains) == 1:
                    resolved_domain_id = str(derived_domains[0].get("domain_id") or "")

        domain_switch = None
        if resolved_domain_id and resolved_domain_id != self._current_domain_id:
            domain_switch = await self._change_current_domain_impl(
                resolved_domain_id,
                timeout=min(float(timeout), 8.0),
            )

        preflight_domain_version = None
        preflight_domain_version_error = None
        preflight_requested = False
        if resolved_domain_id:
            preflight_requested = True
            try:
                preflight_domain_version = await self._read_domain_development_versions_impl(
                    [resolved_domain_id],
                    timeout=min(max(float(timeout) / 2.0, 2.0), 5.0),
                )
            except Exception as exc:
                preflight_domain_version_error = str(exc)

        request_started = _now_ts()
        if self._has_shop_sync_snapshot():
            response = {
                "strategy": "reuse_existing_shop_sync",
                "protocol_note": "recovered proto/types 未发现可靠的 CS_SHOP_BEGIN，直接复用已收到的 SC_SHOP_SYNC。",
                "send_meta": None,
                "observation_kind": "cached",
                "observed": self._get_latest_shop_sync_event(),
                "raw_observed": None,
                "raw_probe_timeout": self._default_raw_probe_timeout(timeout),
            }
        else:
            response = await self._wait_for_existing_observation_with_raw_fallback(
                expected_msgids={MSG_ID_SC_SHOP_SYNC},
                timeout=float(timeout),
                raw_msgid=MSG_ID_SC_SHOP_SYNC,
            )
            response["strategy"] = "wait_shop_sync_without_send"
            response["protocol_note"] = (
                "recovered proto/types 未发现可靠的 CS_SHOP_BEGIN，本次仅等待服务端推送 SC_SHOP_SYNC。"
            )

        payload = {
            "domain_id": resolved_domain_id,
            "sent_at": request_started,
            "sent_at_text": _now_iso(request_started),
            "timeout": float(timeout),
            "preflight_version_requested": preflight_requested,
            "domain_switch": domain_switch,
            "preflight_domain_version": preflight_domain_version,
            "preflight_domain_version_error": preflight_domain_version_error,
            **response,
        }
        payload["completed_at"] = _now_ts()
        payload["completed_at_text"] = _now_iso(payload["completed_at"])
        payload["observed_msgid"] = (
            int((payload.get("observed") or {}).get("msgid", 0) or 0)
            if payload.get("observed")
            else 0
        )
        payload["raw_observed_msgid"] = (
            int((payload.get("raw_observed") or {}).get("msgid", 0) or 0)
            if payload.get("raw_observed")
            else 0
        )
        self._last_shop_begin_request = payload
        return {**payload, "state": self.get_state()}

    async def enter_shop(self, domain_id: Optional[str] = None, *, timeout: float = 10.0) -> dict[str, Any]:
        async with self._operation_lock:
            return await self._enter_shop_impl(domain_id=domain_id, timeout=float(timeout))

    async def observe_shop_sync(self, *, timeout: float = 10.0) -> dict[str, Any]:
        async with self._operation_lock:
            try:
                observed = await self._wait_for_observation(
                    {MSG_ID_SC_SHOP_BEGIN, MSG_ID_SC_SHOP_SYNC},
                    timeout=float(timeout),
                )
                return {"timeout": False, "observed": observed, "state": self.get_state()}
            except asyncio.TimeoutError:
                return {"timeout": True, "observed": None, "state": self.get_state()}

    async def observe_inbound_messages(
        self,
        *,
        timeout: float = 10.0,
        msgid: Optional[int] = None,
    ) -> dict[str, Any]:
        async with self._operation_lock:
            try:
                observed = await self._wait_for_raw_observation(timeout=float(timeout), msgid=msgid)
                return {"timeout": False, "observed": observed, "state": self.get_state()}
            except asyncio.TimeoutError:
                return {"timeout": True, "observed": None, "state": self.get_state()}

    def get_friend_list(self) -> dict[str, Any]:
        friends = self._serialize_friend_list()
        return {
            "generated_at": _now_ts(),
            "generated_at_text": _now_iso(),
            "count": len(friends),
            "friends": friends,
        }

    async def query_friend_list(
        self,
        *,
        timeout: float = 10.0,
        info_type: int = 0,
    ) -> dict[str, Any]:
        async with self._operation_lock:
            request_started = _now_ts()
            normalized_info_type = int(info_type)
            simple_send_meta, simple_body = await self.tcp_client.request_message(
                MSG_ID_CS_FRIEND_LIST_SIMPLE_SYNC,
                build_friend_list_simple_sync_body(),
                response_msgid=MSG_ID_SC_FRIEND_LIST_SIMPLE_SYNC,
                timeout=float(timeout),
            )
            simple_parsed = _parse_friend_list_simple_sync(simple_body)
            self._apply_friend_list_simple_sync(simple_parsed)

            role_ids = [
                int(item)
                for item in (simple_parsed.get("role_ids") or [])
                if int(item or 0) > 0
            ]

            query_send_meta = None
            query_error = ""
            query_parsed = {"friend_list": [], "count": 0, "role_ids": []}
            if role_ids:
                try:
                    query_send_meta, query_body = await self.tcp_client.request_message(
                        MSG_ID_CS_FRIEND_LIST_QUERY,
                        build_friend_list_query_body(role_ids, info_type=normalized_info_type),
                        response_msgid=MSG_ID_SC_FRIEND_LIST_QUERY,
                        timeout=float(timeout),
                    )
                    query_parsed = _parse_friend_list_query_response(query_body)
                    self._apply_friend_list_query(query_parsed)
                except Exception as exc:
                    query_error = str(exc)

            payload = {
                "sent_at": request_started,
                "sent_at_text": _now_iso(request_started),
                "timeout": float(timeout),
                "info_type": normalized_info_type,
                "simple_sync": {
                    "send_meta": simple_send_meta,
                    "response": simple_parsed,
                },
                "query": {
                    "send_meta": query_send_meta,
                    "response": query_parsed,
                    "error": query_error,
                },
                "state": self.get_state(),
            }
            self._last_friend_list_query = payload
            return payload

    async def query_friend_goods_price(
        self,
        shop_id: str,
        goods_id: str,
        role_ids: Iterable[int],
        *,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        normalized_shop_id = str(shop_id or "").strip()
        normalized_goods_id = str(goods_id or "").strip()
        normalized_role_ids = [int(item) for item in role_ids]
        if not normalized_shop_id:
            raise ValueError("shop_id 不能为空")
        if not normalized_goods_id:
            raise ValueError("goods_id 不能为空")
        if not normalized_role_ids:
            raise ValueError("role_ids 不能为空")

        async with self._operation_lock:
            request_started = _now_ts()
            _, response_body = await self.tcp_client.request_message(
                MSG_ID_CS_SHOP_QUERY_FRIEND_GOODS_PRICE,
                build_query_friend_goods_price_body(
                    normalized_shop_id,
                    normalized_goods_id,
                    normalized_role_ids,
                ),
                response_msgid=MSG_ID_SC_SHOP_QUERY_FRIEND_GOODS_PRICE,
                timeout=float(timeout),
            )
            parsed = _parse_friend_goods_price_response(response_body)
            payload = {
                "shop_id": normalized_shop_id,
                "goods_id": normalized_goods_id,
                "role_ids": normalized_role_ids,
                "sent_at": request_started,
                "sent_at_text": _now_iso(request_started),
                "timeout": float(timeout),
                "response": parsed,
                "state": self.get_state(),
            }
            self._last_friend_goods_price_query = payload
            return payload

    async def query_friend_shop(
        self,
        friend_role_id: int,
        shop_ids: Iterable[str],
        *,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        normalized_friend_role_id = int(friend_role_id)
        normalized_shop_ids = [
            str(item).strip()
            for item in shop_ids
            if str(item or "").strip()
        ]
        if normalized_friend_role_id <= 0:
            raise ValueError("friend_role_id 必须大于 0")
        if not normalized_shop_ids:
            raise ValueError("shop_ids 不能为空")

        async with self._operation_lock:
            request_started = _now_ts()
            _, response_body = await self.tcp_client.request_message(
                MSG_ID_CS_SHOP_QUERY_FRIEND_SHOP,
                build_query_friend_shop_body(normalized_friend_role_id, normalized_shop_ids),
                response_msgid=MSG_ID_SC_SHOP_QUERY_FRIEND_SHOP,
                timeout=float(timeout),
            )
            parsed = _parse_friend_shop_response(response_body)
            payload = {
                "friend_role_id": normalized_friend_role_id,
                "shop_ids": normalized_shop_ids,
                "sent_at": request_started,
                "sent_at_text": _now_iso(request_started),
                "timeout": float(timeout),
                "response": parsed,
                "state": self.get_state(),
            }
            self._last_friend_shop_query = payload
            return payload

    async def update_domain_shop_binding(
        self,
        domain_id: str,
        shop_id: str,
        *,
        channel_id: Optional[str] = None,
        preferred: bool = True,
        note: Optional[str] = None,
    ) -> dict[str, Any]:
        normalized_domain_id = str(domain_id or "").strip()
        normalized_shop_id = str(shop_id or "").strip()
        normalized_channel_id = str(channel_id or "").strip()
        normalized_note = str(note or "").strip()
        if not normalized_domain_id:
            raise ValueError("domain_id 不能为空")
        if not normalized_shop_id:
            raise ValueError("shop_id 不能为空")

        async with self._operation_lock:
            current = dict(self._domain_shop_bindings.get(normalized_domain_id, {}))
            shop_ids = [
                str(item)
                for item in current.get("shop_ids", [])
                if str(item or "").strip()
            ]
            if normalized_shop_id not in shop_ids:
                shop_ids.append(normalized_shop_id)
            if preferred:
                preferred_shop_id = normalized_shop_id
            else:
                preferred_shop_id = str(current.get("preferred_shop_id") or normalized_shop_id)

            payload = {
                "domain_id": normalized_domain_id,
                "shop_ids": shop_ids,
                "preferred_shop_id": preferred_shop_id,
                "channel_id": normalized_channel_id or str(current.get("channel_id") or ""),
                "note": normalized_note or str(current.get("note") or ""),
                "updated_at": _now_ts(),
                "updated_at_text": _now_iso(),
                "source": "manual",
            }
            self._domain_shop_bindings[normalized_domain_id] = payload
            self._save_domain_shop_bindings()
            return {"binding": payload, "state": self.get_state()}
