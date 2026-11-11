"""
injecagent_adapter.py
=====================
加载和解析 InjecAgent 数据集，转换为 MPBenchCase 统一格式。

InjecAgent (Qi et al., 2024) 是首个针对 LLM Agent 的 Indirect Prompt Injection (IPI)
基准测试。数据集包含三类文件:

    1. user_cases.jsonl        — 正常用户请求 + 工具响应模板（含 <Attacker Instruction> 占位符）
    2. attacker_cases_dh.jsonl — Direct Harm 攻击者指令（诱导 Agent 执行有害操作）
    3. attacker_cases_ds.jsonl — Data Stealing 攻击者指令（诱导 Agent 窃取/外传数据）

测试用例的形成方式:
    将 attacker 的 "Attacker Instruction" 替换到 user case 的 "Tool Response Template"
    中的 `<Attacker Instruction>` 占位符，形成一个完整的 IPI 攻击场景。

InjecAgent → MPBenchCase 字段映射:
    case_id              ← "{attack_class}_{user_tool}_{idx}"
    attack_class         ← "direct_harm" 或 "data_stealing"
    domain               ← User Tool（如 AmazonGetProductDetails）
    delivery_mode        ← "dynamic"（载荷通过工具返回值传递）
    payload              ← 注入了 Attacker Instruction 的 Tool Response Template
    target_instruction   ← Attacker Instruction
    task_description     ← User Instruction
    expected_memory_pattern  ← 从 Attacker Instruction 提取的关键动作短语
    expected_response_pattern ← 从 Expected Achievements 提取的关键短语
    signal_strength      ← "strong"（InjecAgent 使用显式指令）

参考: https://github.com/iliaschalkidis/injec-agent
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .mpbench_adapter import MPBenchCase


# 停用词列表（用于从 Attacker Instruction 中提取关键动作短语）
_STOPWORDS = {
    "please", "kindly", "could", "would", "should", "can", "may", "might",
    "i", "you", "my", "me", "the", "a", "an", "to", "for", "of", "and",
    "or", "in", "on", "at", "by", "with", "from", "this", "that", "these",
    "those", "your", "our", "their", "its", "as", "is", "are", "be", "been",
    "being", "have", "has", "had", "do", "does", "did", "will", "shall",
    "all", "any", "some", "every", "each", "no", "not", "so", "if", "but",
    "then", "than", "into", "over", "under", "about", "after", "before",
    "up", "down", "out", "off", "again", "further", "once", "here", "there",
    "when", "where", "why", "how", "what", "which", "who", "whom",
}

# 占位符正则
_ATTACKER_PLACEHOLDER = re.compile(r"<Attacker Instruction>", re.IGNORECASE)


def _read_jsonl(path: Path) -> List[Dict]:
    """读取 JSONL 文件"""
    items = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            items.append(json.loads(line))
    return items


def _extract_key_phrase(text: str, max_words: int = 8) -> str:
    """
    从一段文本中提取关键动作短语（用于 ASR/RSR 判定模式）。

    策略:
        1. 取第一个句子/子句（遇到逗号、句号、分号截断）
        2. 保留前 max_words 个词（保持词序与连续性以确保子串匹配）
    """
    if not text:
        return ""

    first_clause = re.split(r"[,.;:]", text)[0].strip()
    words = re.findall(r"[A-Za-z0-9$]+", first_clause)
    if not words:
        return ""
    return " ".join(words[:max_words]).lower()


class InjecAgentAdapter:
    """InjecAgent 数据加载器，输出 MPBenchCase 统一格式"""

    # 攻击类型映射
    ATTACK_CLASS_MAP = {
        "dh": "direct_harm",
        "ds": "data_stealing",
    }

    def __init__(self, data_dir: str,
                 max_attacks_per_user: Optional[int] = None,
                 seed: int = 42):
        """
        Args:
            data_dir: InjecAgent 数据目录（包含三个 jsonl 文件）
            max_attacks_per_user: 每个 user case 最多搭配的 attacker case 数
                                  (None = 全部)。用于控制组合爆炸。
            seed: 随机种子（当限制组合数时用于采样）
        """
        self.data_dir = Path(data_dir)
        self.max_attacks_per_user = max_attacks_per_user
        self.seed = seed
        self.cases: List[MPBenchCase] = []
        self._load()

    def _load(self):
        """加载并组合所有测试用例"""
        user_path = self.data_dir / "user_cases.jsonl"
        dh_path = self.data_dir / "attacker_cases_dh.jsonl"
        ds_path = self.data_dir / "attacker_cases_ds.jsonl"

        for p in (user_path, dh_path, ds_path):
            if not p.exists():
                print(f"[WARN] 文件不存在: {p}")
                return

        user_cases = _read_jsonl(user_path)
        dh_cases = _read_jsonl(dh_path)
        ds_cases = _read_jsonl(ds_path)

        print(f"[INFO] InjecAgent: {len(user_cases)} user cases, "
              f"{len(dh_cases)} direct-harm, {len(ds_cases)} data-stealing")

        # 组合 user × attacker
        self.cases.extend(self._combine(user_cases, dh_cases, "dh"))
        self.cases.extend(self._combine(user_cases, ds_cases, "ds"))

        print(f"[INFO] InjecAgent: 共生成 {len(self.cases)} 个测试用例")

    def _combine(self, user_cases: List[Dict], attacker_cases: List[Dict],
                 attack_tag: str) -> List[MPBenchCase]:
        """
        将 user cases 与 attacker cases 组合成 MPBenchCase。

        每个 user case 可与多个 attacker case 组合（笛卡尔积，可选限制数量）。
        """
        import random
        rng = random.Random(self.seed)

        attack_class = self.ATTACK_CLASS_MAP[attack_tag]
        results: List[MPBenchCase] = []

        attackers = attacker_cases
        if self.max_attacks_per_user is not None:
            attackers = rng.sample(
                attacker_cases,
                k=min(self.max_attacks_per_user, len(attacker_cases))
            )

        idx = 0
        for u in user_cases:
            user_tool = u.get("User Tool", "unknown")
            user_instruction = u.get("User Instruction", "")
            tool_response_template = u.get("Tool Response Template", "")
            # domain: 从工具名提取类别前缀（如 Amazon, GitHub, Gmail...）
            domain = self._tool_to_domain(user_tool)

            for a in attackers:
                attacker_instruction = a.get("Attacker Instruction", "")
                expected_achievements = a.get("Expected Achievements", "")
                attack_type = a.get("Attack Type", "")

                # 注入: 将 <Attacker Instruction> 替换为攻击者指令
                payload = _ATTACKER_PLACEHOLDER.sub(
                    attacker_instruction, tool_response_template
                )
                # 如果占位符未匹配，直接拼接（兜底）
                if payload == tool_response_template and attacker_instruction:
                    payload = tool_response_template + "\n" + attacker_instruction

                # 提取判定模式
                memory_pattern = _extract_key_phrase(attacker_instruction)
                response_pattern = _extract_key_phrase(expected_achievements)

                case_id = f"{attack_class}_{user_tool}_{idx:04d}"

                case = MPBenchCase(
                    case_id=case_id,
                    attack_class=attack_class,
                    domain=domain,
                    delivery_mode="dynamic",
                    payload=payload,
                    target_instruction=attacker_instruction,
                    task_description=user_instruction,
                    expected_memory_pattern=memory_pattern,
                    expected_response_pattern=response_pattern,
                    signal_strength="strong",
                    metadata={
                        "source": "injecagent",
                        "user_tool": user_tool,
                        "attacker_tools": a.get("Attacker Tools", []),
                        "attack_type": attack_type,
                        "expected_achievements": expected_achievements,
                        "level": u.get("Level", ""),
                        "modified": a.get("Modifed", a.get("Modified", 0)),
                    },
                )
                results.append(case)
                idx += 1

        return results

    @staticmethod
    def _tool_to_domain(tool_name: str) -> str:
        """
        从 InjecAgent 工具名提取域类别。
        例如 'AmazonGetProductDetails' → 'amazon', 'GitHubGetUserDetails' → 'github'
        """
        # 按驼峰命名拆分，取第一个有意义的前缀
        match = re.match(r"([A-Z][a-z]+)", tool_name)
        if match:
            return match.group(1).lower()
        return tool_name.lower().split("_")[0] if tool_name else "unknown"

    def get_cases(self, attack_class: Optional[str] = None,
                  domain: Optional[str] = None,
                  signal_strength: Optional[str] = None,
                  limit: Optional[int] = None) -> List[MPBenchCase]:
        """按条件筛选测试用例（接口与 MPBenchAdapter 一致）"""
        cases = self.cases
        if attack_class:
            cases = [c for c in cases if c.attack_class == attack_class]
        if domain:
            cases = [c for c in cases if c.domain == domain]
        if signal_strength:
            cases = [c for c in cases if c.signal_strength == signal_strength]
        if limit:
            cases = cases[:limit]
        return cases

    def summary(self) -> Dict:
        """数据集统计摘要"""
        result = {
            "total": len(self.cases),
            "by_attack_class": {},
            "by_domain": {},
            "by_signal_strength": {},
            "by_attack_type": {},
        }
        for c in self.cases:
            result["by_attack_class"][c.attack_class] = \
                result["by_attack_class"].get(c.attack_class, 0) + 1
            result["by_domain"][c.domain] = \
                result["by_domain"].get(c.domain, 0) + 1
            result["by_signal_strength"][c.signal_strength] = \
                result["by_signal_strength"].get(c.signal_strength, 0) + 1
            at = c.metadata.get("attack_type", "unknown")
            result["by_attack_type"][at] = \
                result["by_attack_type"].get(at, 0) + 1
        return result
