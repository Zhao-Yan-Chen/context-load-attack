"""
mpbench_adapter.py
==================
加载和解析 MPBench 格式的测试用例。

MPBench 数据格式（基于论文描述）:
    每个测试用例包含:
        - attack_class: 攻击类型 (explicit_command, conditional_command,
                        salience_compaction, policy_conformant,
                        false_precedent, skill_procedure)
        - domain: 任务域 (file, web, email, calendar, slack, code, skill)
        - delivery_mode: static / dynamic
        - payload: 攻击载荷文本
        - target_instruction: 攻击者想让 Agent 记住/执行的指令
        - task_description: 给 Agent 的正常任务描述
        - expected_memory_pattern: 期望被写入记忆的内容模式（用于 ASR 判定）
        - expected_response_pattern: 期望在检索阶段出现的响应模式（用于 RSR 判定）

由于 MPBench 官方数据未公开发布，本模块同时支持:
    1. 官方 MPBench 数据（放入 data/mpbench/ 目录）
    2. 本项目重建的测试用例（data/reconstructed/ 目录）
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class MPBenchCase:
    """MPBench 测试用例"""
    case_id: str
    attack_class: str
    domain: str
    delivery_mode: str  # static or dynamic
    payload: str
    target_instruction: str
    task_description: str
    expected_memory_pattern: str
    expected_response_pattern: str
    signal_strength: str = ""  # strong or weak
    metadata: Dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Dict) -> "MPBenchCase":
        return cls(
            case_id=d.get("case_id", ""),
            attack_class=d.get("attack_class", ""),
            domain=d.get("domain", ""),
            delivery_mode=d.get("delivery_mode", "static"),
            payload=d.get("payload", ""),
            target_instruction=d.get("target_instruction", ""),
            task_description=d.get("task_description", ""),
            expected_memory_pattern=d.get("expected_memory_pattern", ""),
            expected_response_pattern=d.get("expected_response_pattern", ""),
            signal_strength=d.get("signal_strength", ""),
            metadata=d.get("metadata", {}),
        )


class MPBenchAdapter:
    """MPBench 数据加载器"""

    ATTACK_CLASSES = [
        "explicit_command",
        "conditional_command",
        "salience_compaction",
        "policy_conformant",
        "false_precedent",
        "skill_procedure",
    ]

    DOMAINS = ["file", "web", "email", "calendar", "slack", "code", "skill"]

    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.cases: List[MPBenchCase] = []
        self._load()

    def _load(self):
        """加载所有 JSON 测试用例"""
        if not self.data_dir.exists():
            print(f"[WARN] 数据目录不存在: {self.data_dir}")
            return

        for f in sorted(self.data_dir.glob("**/*.json")):
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                if isinstance(data, list):
                    for item in data:
                        self.cases.append(MPBenchCase.from_dict(item))
                elif isinstance(data, dict):
                    if "cases" in data:
                        for item in data["cases"]:
                            self.cases.append(MPBenchCase.from_dict(item))
                    else:
                        self.cases.append(MPBenchCase.from_dict(data))

    def get_cases(self, attack_class: Optional[str] = None,
                  domain: Optional[str] = None,
                  signal_strength: Optional[str] = None,
                  limit: Optional[int] = None) -> List[MPBenchCase]:
        """按条件筛选测试用例"""
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
        }
        for c in self.cases:
            result["by_attack_class"][c.attack_class] = \
                result["by_attack_class"].get(c.attack_class, 0) + 1
            result["by_domain"][c.domain] = \
                result["by_domain"].get(c.domain, 0) + 1
            result["by_signal_strength"][c.signal_strength] = \
                result["by_signal_strength"].get(c.signal_strength, 0) + 1
        return result
