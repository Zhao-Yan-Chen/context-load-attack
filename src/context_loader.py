"""
context_loader.py
=================
控制上下文窗口的负载率（context load ratio）。

核心思想：
    通过向 Agent 的上下文中注入"良性填充内容"（benign filler），
    将上下文占用率控制在目标水平，然后在该负载下运行攻击用例。

    这样可以隔离出"上下文负载"这一变量对攻击成功率的影响。

设计原则：
    - 填充内容必须是良性的（不能包含攻击载荷或指令）
    - 填充内容应在语义上与任务相关（避免被模型视为异常）
    - 负载率 = (当前上下文 token 数) / (模型上下文窗口大小)
"""

from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


# 粗略的 token 估算器：英文按 4 字符/token，中文按 1.5 字符/token
# 对于严格实验，应使用 tiktoken 或模型官方 tokenizer
def estimate_tokens(text: str) -> int:
    """估算文本的 token 数（混合中英文）"""
    if not text:
        return 0
    # 简单加权：中文字符权重高，英文单词权重低
    chinese_chars = len(re.findall(r"[\u4e00-\u9fff]", text))
    other_chars = len(text) - chinese_chars
    return int(chinese_chars / 1.5 + other_chars / 4)


@dataclass
class FillerContent:
    """良性填充内容"""
    text: str
    category: str  # document, code, log, etc.
    tokens: int = 0

    def __post_init__(self):
        if self.tokens == 0:
            self.tokens = estimate_tokens(self.text)


@dataclass
class ContextLoadConfig:
    """上下文负载配置"""
    target_load_ratio: float  # 目标负载率 (0.0 ~ 1.0)
    context_window_size: int  # 模型上下文窗口大小（token）
    base_context_tokens: int  # 基础上下文 token 数（system prompt + 任务 + 攻击载荷）
    filler_tokens: int = 0    # 需要填充的 token 数
    filler_strategy: str = "random"  # random, sequential, domain-matched

    def __post_init__(self):
        target_tokens = int(self.context_window_size * self.target_load_ratio)
        self.filler_tokens = max(0, target_tokens - self.base_context_tokens)


class FillerBank:
    """良性填充内容库"""

    def __init__(self, filler_dir: Optional[str] = None):
        self.fillers: List[FillerContent] = []
        if filler_dir:
            self.load_from_dir(filler_dir)

    def load_from_dir(self, filler_dir: str):
        """从目录加载填充内容"""
        p = Path(filler_dir)
        for f in p.glob("*.json"):
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                for item in data:
                    self.fillers.append(
                        FillerContent(
                            text=item["text"],
                            category=item.get("category", "document"),
                        )
                    )

    def get_fillers(self, target_tokens: int, strategy: str = "random",
                    domain: Optional[str] = None) -> List[FillerContent]:
        """获取指定 token 数的填充内容"""
        if target_tokens <= 0 or not self.fillers:
            return []

        if domain:
            candidates = [f for f in self.fillers if f.category == domain]
            if not candidates:
                candidates = self.fillers
        else:
            candidates = self.fillers

        selected = []
        current_tokens = 0

        if strategy == "random":
            pool = candidates.copy()
            random.shuffle(pool)
            for f in pool:
                if current_tokens >= target_tokens:
                    break
                selected.append(f)
                current_tokens += f.tokens
        elif strategy == "sequential":
            for f in candidates:
                if current_tokens >= target_tokens:
                    break
                selected.append(f)
                current_tokens += f.tokens
        elif strategy == "domain-matched":
            # 优先选与任务域匹配的填充
            domain_fillters = [f for f in candidates if f.category == domain]
            other_fillers = [f for f in candidates if f.category != domain]
            pool = domain_fillters + other_fillers
            for f in pool:
                if current_tokens >= target_tokens:
                    break
                selected.append(f)
                current_tokens += f.tokens

        return selected

    def build_context_padding(self, target_tokens: int, strategy: str = "random",
                               domain: Optional[str] = None) -> str:
        """构建上下文填充文本"""
        fillers = self.get_fillers(target_tokens, strategy, domain)
        if not fillers:
            return ""
        parts = []
        for f in fillers:
            parts.append(f"--- {f.category} ---\n{f.text}")
        return "\n\n".join(parts)


def compute_load_ratio(context_text: str, context_window_size: int) -> float:
    """计算当前上下文的负载率"""
    tokens = estimate_tokens(context_text)
    return tokens / context_window_size if context_window_size > 0 else 0.0
