"""
agentdojo_adapter.py
====================
加载和解析 AgentDojo 数据集，转换为 MPBenchCase 统一格式。

AgentDojo (Debenedetti et al., NeurIPS 2024) 是一个动态环境 benchmark，用于评测
LLM Agent 的提示注入攻击与防御。包含 4 个任务套件：workspace / banking / slack / travel。

数据来源（已内置在 data/agentdojo/）:
    1. injection_vectors/<suite>.yaml — 注入载荷（恶意内容）及其放置位置描述
    2. user_tasks/<suite>.py          — 用户正常任务（PROMPT 字段）
    3. injection_tasks/<suite>.py     — 攻击者目标（GOAL 字段）

测试用例的形成方式（遵循 AgentDojo 攻击范式）:
    将 injection_vector（恶意载荷）植入工具返回值中，Agent 在执行 user_task 时
    读取到该载荷，若 Agent 遵循了 injection_task 的 GOAL，则攻击成功。

AgentDojo → MPBenchCase 字段映射:
    case_id              ← "{suite}_{injection_vector}_{injection_task}_{idx}"
    attack_class         ← "agentdojo_{suite}" (如 agentdojo_workspace)
    domain               ← 套件名 (workspace / banking / slack / travel)
    delivery_mode        ← "dynamic"（载荷通过工具返回值传递）
    payload              ← 包装为工具返回值的 injection_vector 内容
    target_instruction   ← injection_task 的 GOAL
    task_description     ← user_task 的 PROMPT
    expected_memory_pattern  ← 从 GOAL 提取的关键动作短语
    expected_response_pattern ← 从 GOAL 提取的关键动作短语
    signal_strength      ← "strong"（显式指令注入）

参考: https://github.com/ethz-spylab/agentdojo
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from .mpbench_adapter import MPBenchCase


# 停用词（复用 injecagent_adapter 的逻辑，避免循环依赖这里内联）
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
    "send", "email", "message", "create", "delete", "file", "event",
    "transaction", "make", "give", "tell", "using", "use", "via",
}


# 套件列表（与 data/agentdojo/ 下的子目录对应）
SUITES = ["workspace", "banking", "slack", "travel"]


def _extract_key_phrase(text: str, max_words: int = 8) -> str:
    """
    从文本中提取关键动作短语（用于 ASR/RSR 判定）。

    注意: 保留原始词序与停用词以确保子串匹配的连续性。
    """
    if not text:
        return ""
    first_clause = re.split(r"[,.;:]", text)[0].strip()
    words = re.findall(r"[A-Za-z0-9$]+", first_clause)
    if not words:
        return ""
    return " ".join(words[:max_words]).lower()


# ---------------------------------------------------------------------------
# Python 任务文件解析（使用 ast 提取 PROMPT / GOAL，并求值 f-string）
# ---------------------------------------------------------------------------

class _TaskExtractor(ast.NodeVisitor):
    """
    从 user_tasks.py / injection_tasks.py 中提取每个任务类的
    PROMPT 或 GOAL 字段值。

    处理:
        - 普通字符串: PROMPT = "text"
        - f-string:   GOAL = f"...{_VAR}..."
        - 多行拼接:   PROMPT = ("line1" "line2") / f"..." f"..."
    """

    def __init__(self, field_name: str):
        self.field_name = field_name  # "PROMPT" or "GOAL"
        self.results: List[str] = []

    def visit_ClassDef(self, node: ast.ClassDef):
        # 收集类内的简单变量赋值（供 f-string 求值使用）
        env: Dict[str, str] = {}
        target_node: Optional[ast.expr] = None

        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        # 尝试提取简单常量赋值
                        value = self._eval_simple(stmt.value)
                        if value is not None:
                            env[target.id] = value
                        if target.id == self.field_name:
                            target_node = stmt.value

        if target_node is not None:
            text = self._eval_expr(target_node, env)
            if text:
                self.results.append(text)

        # 继续访问嵌套（任务类一般无子类，这里保险起见）
        self.generic_visit(node)

    @staticmethod
    def _eval_simple(node: ast.expr):
        """提取简单常量（str / int / float / None），否则返回 None"""
        if isinstance(node, ast.Constant):
            return node.value
        return None

    def _eval_expr(self, node: ast.expr, env: Dict[str, str]) -> Optional[str]:
        """递归求值表达式为字符串"""
        if isinstance(node, ast.Constant):
            return str(node.value) if node.value is not None else ""
        if isinstance(node, ast.JoinedStr):  # f-string
            parts = []
            for val in node.values:
                if isinstance(val, ast.Constant):
                    parts.append(str(val.value))
                elif isinstance(val, ast.FormattedValue):
                    inner = self._eval_expr(val.value, env)
                    if inner is not None:
                        parts.append(inner)
            return "".join(parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._eval_expr(node.left, env)
            right = self._eval_expr(node.right, env)
            if left is not None and right is not None:
                return left + right
        if isinstance(node, ast.Name):
            return env.get(node.id)
        if isinstance(node, ast.Attribute):
            # e.g. self._VAR — 忽略
            return None
        # 兜底：尝试从源代码还原（不适用于复杂表达式）
        return None


def _extract_strings_from_py(py_path: Path, field_name: str) -> List[str]:
    """解析 Python 任务文件，提取指定字段（PROMPT/GOAL）的值列表"""
    source = py_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    extractor = _TaskExtractor(field_name)
    extractor.visit(tree)
    return extractor.results


# ---------------------------------------------------------------------------
# 注入载荷 → 工具返回值包装
# ---------------------------------------------------------------------------

def _wrap_injection_vector(description: str, content: str) -> str:
    """
    根据 injection_vector 的 description，将恶意内容包装为逼真的工具返回值。

    AgentDojo 的注入载荷被放置在环境的特定位置（邮件正文、日历描述、
    云盘文件内容等）。这里模拟 Agent 调用工具后获得的返回值。
    """
    desc = (description or "").lower()
    content = content or ""

    if not content:
        # 空载荷（部分 injection_vector 的 default 为空），返回通用占位
        return f"[Tool Output]\n{content}"

    if any(k in desc for k in ["email", "mail"]):
        return (
            "[Tool Output: search_emails]\n"
            "Found 1 email:\n"
            f"  From: noreply@service.com\n"
            f"  Subject: Important notification\n"
            f"  Body: {content}"
        )
    if any(k in desc for k in ["calendar", "meeting", "event", "appointment"]):
        return (
            "[Tool Output: get_calendar_events]\n"
            "Found 1 event:\n"
            f"  Title: Scheduled event\n"
            f"  Description: {content}"
        )
    if any(k in desc for k in ["drive", "file", "document", "csv", "recipe",
                                "feedback", "packing", "grocery", "todo"]):
        return (
            "[Tool Output: read_file]\n"
            "File content:\n"
            f"{content}"
        )
    if any(k in desc for k in ["bill", "transaction", "bank", "iban",
                                "payment", "money", "transfer"]):
        return (
            "[Tool Output: get_transactions]\n"
            "Recent transactions:\n"
            f"  {content}"
        )
    if any(k in desc for k in ["slack", "channel", "message", "dm"]):
        return (
            "[Tool Output: read_messages]\n"
            "New messages:\n"
            f"  {content}"
        )
    if any(k in desc for k in ["flight", "hotel", "booking", "travel",
                                "trip", "reservation"]):
        return (
            "[Tool Output: get_bookings]\n"
            "Booking details:\n"
            f"  {content}"
        )
    # 通用兜底
    return f"[Tool Output]\n{content}"


# ---------------------------------------------------------------------------
# 主适配器
# ---------------------------------------------------------------------------

@dataclass
class _SuiteData:
    """单个套件的解析结果"""
    name: str
    injection_vectors: Dict[str, Dict]  # name -> {description, default}
    user_prompts: List[str]
    injection_goals: List[str]


class AgentDojoAdapter:
    """AgentDojo 数据加载器，输出 MPBenchCase 统一格式"""

    def __init__(self, data_dir: str,
                 max_cases: Optional[int] = None,
                 seed: int = 42):
        """
        Args:
            data_dir: AgentDojo 数据目录，结构:
                injection_vectors/<suite>.yaml
                user_tasks/<suite>.py
                injection_tasks/<suite>.py
            max_cases: 生成用例总数上限（None = 全部）
            seed: 随机种子（用于采样 user task）
        """
        self.data_dir = Path(data_dir)
        self.max_cases = max_cases
        self.seed = seed
        self.cases: List[MPBenchCase] = []
        self._load()

    def _load(self):
        suites_data = self._load_all_suites()
        total_vectors = sum(len(s.injection_vectors) for s in suites_data)
        total_goals = sum(len(s.injection_goals) for s in suites_data)
        total_prompts = sum(len(s.user_prompts) for s in suites_data)
        print(f"[INFO] AgentDojo: {len(suites_data)} suites, "
              f"{total_prompts} user tasks, {total_vectors} injection vectors, "
              f"{total_goals} injection goals")

        self.cases = self._build_cases(suites_data)
        print(f"[INFO] AgentDojo: 共生成 {len(self.cases)} 个测试用例")

    def _load_all_suites(self) -> List[_SuiteData]:
        suites: List[_SuiteData] = []
        for suite in SUITES:
            vec_path = self.data_dir / "injection_vectors" / f"{suite}.yaml"
            user_path = self.data_dir / "user_tasks" / f"{suite}.py"
            inj_path = self.data_dir / "injection_tasks" / f"{suite}.py"

            if not all(p.exists() for p in (vec_path, user_path, inj_path)):
                missing = [str(p) for p in (vec_path, user_path, inj_path)
                           if not p.exists()]
                print(f"[WARN] AgentDojo suite '{suite}' 缺少文件: {missing}")
                continue

            with open(vec_path, "r", encoding="utf-8") as f:
                vectors = yaml.safe_load(f) or {}

            user_prompts = _extract_strings_from_py(user_path, "PROMPT")
            injection_goals = _extract_strings_from_py(inj_path, "GOAL")

            suites.append(_SuiteData(
                name=suite,
                injection_vectors=vectors,
                user_prompts=user_prompts,
                injection_goals=injection_goals,
            ))
        return suites

    def _build_cases(self, suites: List[_SuiteData]) -> List[MPBenchCase]:
        """
        构建测试用例。

        组合策略（遵循 AgentDojo 攻击范式）:
            对每个套件，对每个 injection_vector，对每个 injection_goal:
                - payload = 包装后的 injection_vector 内容
                - target_instruction = injection_goal
                - task_description = 从套件 user_tasks 中轮询选取
        """
        import random
        rng = random.Random(self.seed)
        cases: List[MPBenchCase] = []

        for suite in suites:
            prompts = suite.user_prompts or ["Please help me with this task."]
            prompt_idx = 0

            for vec_name, vec_info in suite.injection_vectors.items():
                description = vec_info.get("description", "")
                content = vec_info.get("default", "")

                # 跳过完全为空的载荷
                if not content and not description:
                    continue

                payload = _wrap_injection_vector(description, content)

                for goal in suite.injection_goals:
                    task_desc = prompts[prompt_idx % len(prompts)]
                    prompt_idx += 1

                    # ASR 判定模式: 从注入载荷内容提取（Agent 读取的是载荷）
                    # 若载荷内容为空，则回退到目标指令
                    memory_pattern = _extract_key_phrase(content or goal)

                    case_id = (
                        f"agentdojo_{suite.name}_{vec_name}_"
                        f"goal{prompt_idx:03d}"
                    )

                    case = MPBenchCase(
                        case_id=case_id,
                        attack_class=f"agentdojo_{suite.name}",
                        domain=suite.name,
                        delivery_mode="dynamic",
                        payload=payload,
                        target_instruction=goal,
                        task_description=task_desc,
                        expected_memory_pattern=memory_pattern,
                        expected_response_pattern=memory_pattern,
                        signal_strength="strong",
                        metadata={
                            "source": "agentdojo",
                            "suite": suite.name,
                            "injection_vector": vec_name,
                            "vector_description": description,
                            "injection_goal": goal,
                        },
                    )
                    cases.append(case)

        # 限制总数
        if self.max_cases is not None and len(cases) > self.max_cases:
            cases = rng.sample(cases, k=self.max_cases)

        return cases

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
            "by_suite": {},
        }
        for c in self.cases:
            result["by_attack_class"][c.attack_class] = \
                result["by_attack_class"].get(c.attack_class, 0) + 1
            result["by_domain"][c.domain] = \
                result["by_domain"].get(c.domain, 0) + 1
            result["by_signal_strength"][c.signal_strength] = \
                result["by_signal_strength"].get(c.signal_strength, 0) + 1
            suite = c.metadata.get("suite", "unknown")
            result["by_suite"][suite] = \
                result["by_suite"].get(suite, 0) + 1
        return result
