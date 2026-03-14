"""Error code names and human-readable explanations for Proto.CODE."""

from __future__ import annotations

import re

from tcp.proto_error_codes import ERROR_CODES

_ERROR_NAME_NORMALIZATIONS = {
    "Dbsave": "DBSave",
    "Psnaccount": "PSNAccount",
    "Gmkick": "GMKick",
    "Gskick": "GSKick",
    "Gsfailed": "GSFailed",
    "Reconnct": "Reconnect",
    "Aoiobject": "AOIObject",
    "Aoiupdate": "AOIUpdate",
    "Bpbegin": "BPBegin",
    "Bpend": "BPEnd",
    "Bpinvalid": "BPInvalid",
    "Bptrack": "BPTrack",
    "Bplevel": "BPLevel",
    "Bptake": "BPTake",
    "Bpseason": "BPSeason",
    "Bpdrop": "BPDrop",
    "Bpcost": "BPCost",
    "Bpadd": "BPAdd",
    "Bpreceived": "BPReceived",
    "Bpscore": "BPScore",
    "Bptech": "BPTech",
    "Bpadventure": "BPAdventure",
    "Bpcheck": "BPCheck",
    "Mcard": "MCard",
    "Ugcpunished": "UGCPunished",
    "Snsmoment": "SNSMoment",
    "Achive": "Achieve",
    "Aleary": "Already",
    "Cgid": "CGId",
    "Ynot": "YNot",
    "Quey": "Query",
    "InvaliSign": "InvalidSign",
    "OpErr": "OpError",
    "Laftakeout": "LAFTakeout",
    "Cnt": "Count",
    "Tms": "Times",
}

_ERROR_NAME_MERGES = {
    ("Blue", "Print"): "Blueprint",
    ("Week", "Raid"): "WeekRaid",
    ("Item", "Bag"): "ItemBag",
    ("Char", "Bag"): "CharBag",
    ("Domain", "Depot"): "DomainDepot",
    ("Safe", "Zone"): "SafeZone",
    ("Story", "SafeZone"): "StorySafeZone",
    ("World", "Energy", "Point"): "WorldEnergyPoint",
    ("Check", "Point"): "Checkpoint",
    ("AOI", "Object"): "AOIObject",
    ("AOI", "Update"): "AOIUpdate",
    ("PSN", "Account"): "PSNAccount",
    ("UGC", "Punished"): "UGCPunished",
    ("BP", "Track"): "BPTrack",
    ("M", "Card"): "MCard",
}

_ERROR_TOKEN_TRANSLATIONS = {
    "unknown": "未知",
    "success": "成功",
    "common": "通用",
    "uid": "UID",
    "alloc": "分配",
    "param": "参数",
    "invalid": "无效",
    "msg": "消息",
    "frequency": "频率",
    "blocked": "被限制",
    "sensitive": "敏感内容",
    "game": "游戏",
    "mode": "模式",
    "forbid": "禁止",
    "action": "动作",
    "invoke": "调用",
    "system": "系统",
    "locked": "已锁定",
    "server": "服务端",
    "overload": "过载",
    "error": "错误",
    "internal": "内部",
    "res": "资源",
    "resource": "资源",
    "can": "可",
    "not": "不",
    "found": "找到",
    "feature": "功能",
    "forbidden": "被禁用",
    "tmp": "临时",
    "check": "校验",
    "validate": "校验",
    "fail": "失败",
    "failed": "失败",
    "kick": "踢下线",
    "session": "会话",
    "closed": "关闭",
    "version": "版本",
    "too": "过于",
    "low": "过低",
    "client": "客户端",
    "equal": "一致",
    "gm": "GM",
    "login": "登录",
    "multiple": "多重",
    "archive": "存档",
    "load": "加载",
    "first": "首个",
    "package": "包",
    "token": "令牌",
    "format": "格式",
    "process": "流程",
    "send": "发送",
    "platform": "平台",
    "minor": "未成年",
    "timeout": "超时",
    "lua": "Lua",
    "script": "脚本",
    "db": "数据库",
    "save": "保存",
    "gen": "生成",
    "short": "短",
    "id": "ID",
    "create": "创建",
    "role": "角色",
    "rate": "频率",
    "limit": "限制",
    "queue": "排队",
    "full": "已满",
    "transfer": "切服",
    "gs": "GS",
    "work": "工作",
    "routine": "协程",
    "unrecoverable": "不可恢复",
    "errorcode": "错误码",
    "duplicate": "重复",
    "set": "设置",
    "gender": "性别",
    "migrate": "迁移",
    "afk": "挂机",
    "loc": "地区",
    "unmatch": "不匹配",
    "area": "区域",
    "white": "白",
    "list": "名单",
    "battle": "战斗",
    "data": "数据",
    "expired": "已过期",
    "reconnect": "重连",
    "incr": "增量",
    "ban": "封禁",
    "malicious": "恶意",
    "cheat": "作弊",
    "violation": "违规",
    "policy": "策略",
    "requirement": "要求",
    "account": "账号",
    "dispute": "争议",
    "abnormal": "异常",
    "situation": "情况",
    "temporary": "临时",
    "restriction": "限制",
    "psnaccount": "PSN账号",
    "delete": "删除",
    "busy": "繁忙",
    "achieve": "成就",
    "already": "已",
    "complete": "完成",
    "take": "领取",
    "reward": "奖励",
    "char": "角色",
    "charbag": "角色编队",
    "team": "队伍",
    "but": "但",
    "leader": "队长",
    "dead": "死亡",
    "changing": "变更中",
    "level": "等级",
    "up": "提升",
    "lack": "缺少",
    "item": "物品",
    "unlock": "解锁",
    "talent": "天赋",
    "node": "节点",
    "break": "突破",
    "stage": "阶段",
    "need": "需要",
    "use": "使用",
    "exp": "经验",
    "type": "类型",
    "match": "匹配",
    "generic": "通用",
    "skill": "技能",
    "cgid": "CGID",
    "potential": "潜能",
    "scene": "场景",
    "nil": "为空",
    "has": "已",
    "in": "在",
    "world": "世界中",
    "exist": "存在",
    "exists": "已存在",
    "target": "目标",
    "name": "名称",
    "host": "宿主",
    "monster": "怪物",
    "interactive": "交互物",
    "record": "记录",
    "repeated": "重复",
    "property": "属性",
    "key": "键",
    "aoiobject": "AOI对象",
    "pos": "位置",
    "npc": "NPC",
    "duplicated": "重复",
    "collected": "已采集",
    "impl": "实现",
    "sp": "特殊",
    "op": "操作",
    "teleport": "传送",
    "aoiupdate": "AOI更新",
    "trigger": "触发",
    "custom": "自定义",
    "event": "事件",
    "recursion": "递归",
    "depth": "深度",
    "access": "访问",
    "deny": "拒绝",
    "template": "模板",
    "done": "完成",
    "update": "更新",
    "deco": "装饰",
    "checkpoint": "检查点",
    "doodad": "物件",
    "pick": "拾取",
    "space": "空间",
    "tree": "树木",
    "wood": "木材",
    "count": "数量",
    "over": "超过",
    "of": "",
    "get": "获取",
    "unstuck": "脱困",
    "cooldown": "冷却",
    "interact": "交互",
    "ether": "以太",
    "submit": "提交",
    "move": "移动",
    "cross": "跨越",
    "border": "边界",
    "poop": "便便",
    "cow": "奶牛",
    "daily": "每日",
    "cs": "客户端",
    "is": "处于",
    "wallet": "钱包",
    "money": "货币",
    "change": "变更",
    "out": "超出",
    "max": "上限",
    "undefine": "未定义",
    "combi": "组合",
    "cannot": "不可",
    "itembag": "物品背包",
    "bag": "背包",
    "depot": "仓库",
    "grid": "格子",
    "inst": "实例",
    "discard": "丢弃",
    "abandon": "放弃",
    "reject": "拒绝",
    "adventure": "冒险",
    "and": "与",
    "dump": "倾倒",
    "fluid": "液体",
    "overflow": "溢出",
    "to": "到",
    "factory": "工厂",
    "destroy": "销毁",
    "split": "拆分",
    "spray": "喷洒",
    "laf": "LAF",
    "takeout": "取出",
    "whole": "整体",
    "blueprint": "蓝图",
    "weekraid": "周常突袭",
    "bp": "BP",
    "bptrack": "BP路线",
    "tech": "科技",
    "safezone": "安全区",
    "storysafezone": "剧情安全区",
    "worldenergypoint": "世界能量点",
    "domaindepot": "据点仓储",
    "ugc": "UGC",
    "ugcpunished": "UGC处罚",
    "punished": "处罚",
    "snsmoment": "SNS动态",
    "mcard": "月卡",
    "pay": "支付",
    "cash": "现金",
    "shop": "商店",
    "goods": "商品",
    "friend": "好友",
    "room": "房间",
    "equip": "装备",
    "guest": "访客",
    "cost": "消耗",
    "weapon": "武器",
    "clue": "线索",
    "building": "建筑",
    "dungeon": "副本",
    "td": "TD",
    "no": "无",
    "exceed": "超出",
    "enough": "足够",
    "refine": "精炼",
    "mark": "标记",
    "mechanics": "机制",
    "expedition": "远征",
    "map": "地图",
    "info": "信息",
    "exchange": "兑换",
    "request": "请求",
    "gacha": "抽卡",
    "activity": "活动",
    "biz": "商业",
    "hub": "枢纽",
    "domain": "据点",
    "batch": "批量",
    "gem": "结晶",
    "config": "配置",
    "cd": "CD",
    "progress": "进度",
    "delegate": "委托",
    "by": "由",
    "find": "查找",
    "time": "时间",
    "formula": "配方",
    "black": "黑名单",
    "valid": "有效",
    "add": "添加",
    "enhance": "强化",
    "redeem": "兑换",
    "open": "开启",
    "drop": "掉落",
    "stamina": "体力",
    "manufacturing": "制造",
    "sns": "SNS",
    "unlocked": "已解锁",
    "pool": "卡池",
    "product": "产物",
    "transport": "运输",
    "route": "路线",
    "dev": "开发",
    "free": "免费",
    "all": "全部",
    "mail": "邮件",
    "lv": "等级",
    "inner": "内部",
    "completed": "已完成",
    "present": "礼物",
    "moment": "动态",
    "option": "选项",
    "settlement": "聚落",
    "cool": "冷却",
    "down": "下降",
    "dynamic": "动态",
    "placed": "已放置",
    "be": "为",
    "empty": "为空",
    "conflict": "冲突",
    "code": "代码",
    "start": "开始",
    "dialog": "对话",
    "test": "测试",
    "recycle": "回收",
    "pre": "前置",
    "make": "生成",
    "ticket": "票据",
    "reach": "达到",
    "met": "满足",
    "spaceship": "飞船",
    "station": "站点",
    "len": "人数",
    "lock": "锁定",
    "deliver": "交付",
    "mission": "任务",
    "edit": "编辑",
    "activate": "激活",
    "times": "时间",
    "expire": "到期",
    "place": "放置",
    "sign": "标识",
    "manual": "手动",
    "refresh": "刷新",
    "region": "区域",
    "state": "状态",
    "credit": "信用",
    "buyer": "买家",
    "from": "来自",
    "near": "靠近",
    "self": "自己",
    "other": "其他",
    "query": "查询",
    "report": "举报",
    "share": "分享",
    "review": "审核",
    "current": "当前",
    "cur": "当前",
    "fetch": "领取",
    "gift": "赠礼",
    "num": "数量",
    "quest": "任务",
    "chapter": "章节",
    "status": "状态",
    "for": "针对",
    "track": "路线",
    "next": "下一阶段",
    "point": "点",
}

_ERROR_EXPLANATION_OVERRIDES = {
    -1: "未知错误，服务端未返回可辨识的业务错误码。",
    0: "成功，没有错误。",
    32: "服务端版本过低，当前客户端要求的服务端协议或版本不满足。",
    33: "客户端版本不匹配，当前游戏客户端版本与服务端要求不一致。",
    34: "客户端资源版本不匹配，本地资源版本未通过服务端校验。",
    37: "检测到同一账号/UID 已有另一条活跃会话，当前连接被判定为顶号或重复登录。",
    40: "登录令牌无效，grant code、token 或其签名/时效校验失败。",
    41: "登录消息格式无效，CsLogin 的字段内容或编码格式未通过服务端校验。",
    42: "登录流程处理中，账号当前处于登录过程中的中间状态，暂时不能重复发起登录。",
    43: "登录消息发送失败，登录链路上的消息下发或转发过程出错。",
    44: "平台标识无效，channel/platform/source 等平台信息与服务端预期不一致。",
    45: "触发未成年限制，当前账号因防沉迷或年龄策略被踢下线。",
    46: "会话超时，当前连接长时间未满足服务端活跃性要求。",
    52: "登录排队超时，未在服务端允许的等待时间内完成排队进入。",
    53: "登录队列已满，当前服务器登录排队容量达到上限。",
    54: "账号已登录但正在切换或迁移游戏服，当前阶段不能建立新的稳定会话。",
    61: "长时间挂机未操作，服务端主动结束当前会话。",
    62: "登录区域或定位不匹配，账号当前登录位置/区服归属与服务端策略不一致。",
    65: "增量重连失败，服务端无法接受当前会话的增量同步重连。",
    76: "资源数据版本校验失败，本地资源数据版本未通过检查。",
    77: "分支版本校验失败，当前客户端分支标识与服务端要求不一致。",
    78: "渠道 ID 校验失败，当前渠道号或分发渠道标识未通过服务端检查。",
    79: "服务器繁忙，当前请求或登录无法继续处理。",
}

_ERROR_TOKEN_PATTERN = re.compile(r"[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+")
_ERROR_ACRONYM_TOKENS = {"aoi", "bp", "cd", "cgid", "gm", "gs", "laf", "npc", "psn", "sns", "td", "ugc"}
_ERROR_KNOWN_TOKENS = set(_ERROR_TOKEN_TRANSLATIONS)
_ERROR_KNOWN_TOKENS.update(token.lower() for token in ("Begin", "End", *(_ERROR_NAME_MERGES.values())))
_ERROR_KNOWN_TOKENS.update(_ERROR_ACRONYM_TOKENS)


def _split_unknown_error_token(token: str) -> list[str]:
    lower = token.lower()
    memo: dict[str, list[str] | None] = {}

    def solve(part: str) -> list[str] | None:
        if not part:
            return []
        if part in memo:
            return memo[part]
        best: list[str] | None = None
        for i in range(len(part), 0, -1):
            prefix = part[:i]
            if prefix not in _ERROR_KNOWN_TOKENS:
                continue
            suffix = solve(part[i:])
            if suffix is None:
                continue
            candidate = [prefix] + suffix
            if best is None or len(candidate) < len(best):
                best = candidate
        memo[part] = best
        return best

    parts = solve(lower)
    if not parts or len(parts) == 1:
        return [token]

    normalized: list[str] = []
    for part in parts:
        if part == "cgid":
            normalized.append("CGId")
        elif part in _ERROR_ACRONYM_TOKENS:
            normalized.append(part.upper())
        else:
            normalized.append(part.title())
    return normalized


def _split_error_name(error_name: str) -> list[str]:
    base = error_name[3:] if error_name.startswith("Err") else error_name
    for old, new in _ERROR_NAME_NORMALIZATIONS.items():
        base = base.replace(old, new)

    tokens: list[str] = []
    for token in _ERROR_TOKEN_PATTERN.findall(base):
        tokens.extend(_split_unknown_error_token(token))

    changed = True
    while changed:
        changed = False
        merged: list[str] = []
        i = 0
        while i < len(tokens):
            matched = False
            for size in (3, 2):
                key = tuple(tokens[i : i + size])
                if key in _ERROR_NAME_MERGES:
                    merged.append(_ERROR_NAME_MERGES[key])
                    i += size
                    matched = True
                    changed = True
                    break
            if not matched:
                merged.append(tokens[i])
                i += 1
        tokens = merged
    return tokens


def _render_error_tokens(tokens: list[str]) -> str:
    return "".join(_ERROR_TOKEN_TRANSLATIONS.get(token.lower(), token) for token in tokens)


def _auto_explain_error_name(error_name: str) -> str:
    tokens = _split_error_name(error_name)
    if not tokens:
        return ""
    if tokens[-1] in {"Begin", "End"}:
        return f"{_render_error_tokens(tokens[:-1])}类错误码段{'起始' if tokens[-1] == 'Begin' else '结束'}标记，不表示具体业务失败。"
    if tokens == ["Unknown"]:
        return "未知错误，服务端未返回可辨识的业务错误码。"
    if tokens == ["Success"]:
        return "成功，没有错误。"
    if len(tokens) >= 2 and tokens[-2:] == ["Not", "Enough"]:
        return f"{_render_error_tokens(tokens[:-2])}不足。"
    if len(tokens) >= 4 and tokens[-4:-2] == ["Not", "Enough"] and tokens[-2] == "By":
        return f"{_render_error_tokens(tokens[:-4])}不足，原因：{_render_error_tokens(tokens[-1:])}。"
    if "Not" in tokens and "Enough" in tokens:
        not_idx = tokens.index("Not")
        if not_idx + 1 < len(tokens) and tokens[not_idx + 1] == "Enough":
            reason_tokens = []
            if not_idx + 2 < len(tokens) and tokens[not_idx + 2] in {"By", "For"}:
                reason_tokens = tokens[not_idx + 3 :]
            if reason_tokens:
                return f"{_render_error_tokens(tokens[:not_idx])}不足，原因：{_render_error_tokens(reason_tokens)}。"
    if len(tokens) >= 2 and tokens[-2:] in (["Not", "Found"], ["Not", "Exist"]):
        return f"{_render_error_tokens(tokens[:-2])}不存在。"
    if len(tokens) >= 2 and tokens[-2:] == ["Not", "Next"]:
        return f"{_render_error_tokens(tokens[:-2])}不是下一阶段。"
    if len(tokens) >= 2 and tokens[-2:] == ["Not", "Generic"]:
        return f"{_render_error_tokens(tokens[:-2])}不属于通用类型。"
    if tokens[-1] == "Nil":
        return f"{_render_error_tokens(tokens[:-1])}为空。"
    if len(tokens) >= 2 and tokens[-2:] == ["Already", "Complete"]:
        return f"{_render_error_tokens(tokens[:-2])}已完成。"
    if len(tokens) >= 2 and tokens[-2:] == ["Has", "Activate"]:
        return f"{_render_error_tokens(tokens[:-2])}已激活。"
    if tokens[-1] == "Lock":
        return f"{_render_error_tokens(tokens[:-1])}被锁定。"
    if len(tokens) >= 3 and tokens[-3:] == ["Already", "Take", "Reward"]:
        return f"{_render_error_tokens(tokens[:-3])}奖励已领取。"
    if "For" in tokens:
        for_idx = tokens.index("For")
        if "Failed" in tokens:
            failed_idx = len(tokens) - 1 - tokens[::-1].index("Failed")
            if failed_idx < for_idx:
                subject_tokens = tokens[:failed_idx]
                detail_tokens = tokens[for_idx + 1 :]
                if subject_tokens and detail_tokens:
                    if subject_tokens[-1] == "Check":
                        return f"{_render_error_tokens(subject_tokens[:-1])}针对{_render_error_tokens(detail_tokens)}的校验失败。"
                    return f"{_render_error_tokens(subject_tokens)}针对{_render_error_tokens(detail_tokens)}失败。"
        if "Fail" in tokens:
            fail_idx = len(tokens) - 1 - tokens[::-1].index("Fail")
            if fail_idx < for_idx:
                subject_tokens = tokens[:fail_idx]
                detail_tokens = tokens[for_idx + 1 :]
                if subject_tokens and detail_tokens:
                    return f"{_render_error_tokens(subject_tokens)}针对{_render_error_tokens(detail_tokens)}失败。"
    if len(tokens) >= 2 and tokens[-2:] == ["Can", "Not"]:
        return f"{_render_error_tokens(tokens[:-2])}不可执行。"
    if tokens[-1] == "Cannot":
        return f"{_render_error_tokens(tokens[:-1])}不可执行。"
    if tokens[-1] == "Invalid":
        return f"{_render_error_tokens(tokens[:-1])}无效。"
    if tokens[-1] in {"Failed", "Fail"}:
        return f"{_render_error_tokens(tokens[:-1])}失败。"
    if tokens[-1] == "Full":
        return f"{_render_error_tokens(tokens[:-1])}已满。"
    if tokens[-1] == "Locked":
        return f"{_render_error_tokens(tokens[:-1])}已锁定。"
    if tokens[-1] == "Timeout":
        return f"{_render_error_tokens(tokens[:-1])}超时。"
    if len(tokens) >= 2 and tokens[-2:] == ["In", "CD"]:
        return f"{_render_error_tokens(tokens[:-2])}仍在冷却中。"
    if "Over" in tokens and "Place" in tokens and "Limit" in tokens:
        over_idx = tokens.index("Over")
        place_idx = tokens.index("Place", over_idx + 1)
        limit_idx = tokens.index("Limit", place_idx + 1)
        if over_idx < place_idx < limit_idx:
            subject = _render_error_tokens(tokens[:over_idx])
            target = _render_error_tokens(tokens[limit_idx + 1 :])
            if target:
                return f"{subject}超过{target}放置上限。"
            return f"{subject}超过放置上限。"
    return _render_error_tokens(tokens) + "。"


def get_error_explanation(error_code: int, error_name: str | None = None) -> str:
    if error_code in _ERROR_EXPLANATION_OVERRIDES:
        return _ERROR_EXPLANATION_OVERRIDES[error_code]
    name = error_name or ERROR_CODES.get(error_code)
    if not name:
        return ""
    return _auto_explain_error_name(name)


ERROR_EXPLANATIONS = {
    code: get_error_explanation(code, name)
    for code, name in ERROR_CODES.items()
}

__all__ = ["ERROR_CODES", "ERROR_EXPLANATIONS", "get_error_explanation"]
