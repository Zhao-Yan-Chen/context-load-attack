"""
experiment.py
=============
实验编排器：控制变量法验证上下文负载对攻击成功率的影响。

核心实验设计:
    自变量: 上下文负载率 (0.1, 0.3, 0.5, 0.7, 0.9)
    因变量: ASR, RSR
    控制变量: 同一攻击用例, 同一模型, 同一 Agent 系统

实验流程:
    1. 加载 MPBench 测试用例
    2. 对每个负载率:
        a. 对每个测试用例:
            - 构建带填充的上下文（控制负载率）
            - 运行 Agent（写入阶段 + 检索阶段）
            - 记录 ASR/RSR
    3. 按负载率、攻击类型、信号强度分组统计
    4. 输出结果
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .agent_runner import AgentRunner, OpenClawRunner
from .context_loader import ContextLoadConfig
from .evaluator import Evaluator
from .mpbench_adapter import MPBenchAdapter, MPBenchCase


def _load_adapter(data_source: str, data_dir: str):
    """根据数据源类型加载对应的适配器"""
    if data_source == "injecagent":
        from .injecagent_adapter import InjecAgentAdapter
        return InjecAgentAdapter(data_dir)
    elif data_source == "agentdojo":
        from .agentdojo_adapter import AgentDojoAdapter
        return AgentDojoAdapter(data_dir)
    elif data_source == "mpbench":
        return MPBenchAdapter(data_dir)
    else:
        raise ValueError(
            f"未知的 data_source: {data_source}。"
            f"支持: 'mpbench', 'injecagent', 'agentdojo'。"
        )


@dataclass
class ExperimentConfig:
    """实验配置"""
    # 数据
    data_source: str = "mpbench"  # mpbench / injecagent
    data_dir: str = "data/reconstructed"
    attack_classes: Optional[List[str]] = None  # None = 全部
    domains: Optional[List[str]] = None
    signal_strength: Optional[str] = None  # None, strong, weak
    num_cases_per_group: Optional[int] = None  # 每个分组的用例数

    # 负载率
    load_ratios: List[float] = field(default_factory=lambda: [0.1, 0.3, 0.5, 0.7, 0.9])
    context_window_size: int = 128000

    # Agent
    agent_config: Dict = field(default_factory=dict)

    # 输出
    output_dir: str = "results"
    run_name: str = "default"

    # 运行
    num_repeats: int = 1  # 每个用例重复次数（用于稳定性）
    run_retrieval: bool = True


class Experiment:
    """实验编排器"""

    def __init__(self, config: ExperimentConfig):
        self.config = config
        self.adapter = _load_adapter(config.data_source, config.data_dir)
        self.evaluator = Evaluator()

        # 初始化 Agent 运行器
        agent_type = config.agent_config.get("agent_type", "generic_llm")
        if agent_type == "openclaw":
            self.runner = OpenClawRunner(config.agent_config)
        else:
            self.runner = AgentRunner(config.agent_config)

        # 覆盖 context window
        self.runner.context_window = config.context_window_size

    def run(self):
        """运行完整实验"""
        print("=" * 60)
        print("上下文负载 vs 攻击成功率 实验")
        print("=" * 60)

        # 加载测试用例
        cases = self.adapter.get_cases(
            attack_class=self.config.attack_classes[0]
            if self.config.attack_classes and len(self.config.attack_classes) == 1
            else None,
            domain=self.config.domains[0]
            if self.config.domains and len(self.config.domains) == 1
            else None,
            signal_strength=self.config.signal_strength,
            limit=self.config.num_cases_per_group,
        )

        # 如果有多个 attack_class/domain 筛选条件，手动过滤
        if self.config.attack_classes:
            cases = [c for c in cases if c.attack_class in self.config.attack_classes]
        if self.config.domains:
            cases = [c for c in cases if c.domain in self.config.domains]

        print(f"[INFO] 数据源: {self.config.data_source} ({self.config.data_dir})")
        print(f"[INFO] 加载 {len(cases)} 个测试用例")
        print(f"[INFO] 负载率: {self.config.load_ratios}")
        print(f"[INFO] 上下文窗口: {self.config.context_window_size} tokens")
        print(f"[INFO] Agent: {self.config.agent_config.get('agent_type', 'generic_llm')}")
        print(f"[INFO] 模型: {self.config.agent_config.get('model', 'gpt-oss-120b')}")
        print()

        if not cases:
            print("[ERROR] 没有可用的测试用例")
            return

        total_runs = len(cases) * len(self.config.load_ratios) * self.config.num_repeats
        current = 0

        for load_ratio in self.config.load_ratios:
            print(f"\n--- 负载率 {load_ratio:.0%} ---")
            for case in cases:
                for repeat in range(self.config.num_repeats):
                    current += 1
                    print(f"  [{current}/{total_runs}] {case.case_id} "
                          f"(repeat {repeat + 1})", end=" ... ")

                    result = self.runner.run_case(
                        case, load_ratio,
                        run_retrieval=self.config.run_retrieval,
                    )
                    self.evaluator.add_result(result)

                    status = "OK" if not result.error else "ERROR"
                    asr = "ASR=Y" if result.asr_success else "ASR=N"
                    print(f"{status} {asr} (tokens={result.actual_tokens})")

        # 保存结果
        self._save_results()

        # 打印摘要
        self._print_summary()

    def _save_results(self):
        """保存实验结果"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_path = Path(self.config.output_dir) / f"{self.config.run_name}_{timestamp}.json"
        self.evaluator.save_results(str(output_path))
        print(f"\n[INFO] 结果已保存: {output_path}")

    def _print_summary(self):
        """打印实验摘要"""
        print("\n" + "=" * 60)
        print("实验摘要（整体）")
        print("=" * 60)
        print(f"{'负载率':<10} {'用例数':<8} {'ASR':<10} {'RSR':<10} {'错误数':<8}")
        print("-" * 50)
        for m in self.evaluator.compute_by_load_ratio():
            print(f"{m.load_ratio:<10.0%} {m.num_cases:<8} "
                  f"{m.asr:<10.2%} {m.rsr:<10.2%} {m.error_count:<8}")

        print("\n" + "=" * 60)
        print("实验摘要（按信号强度）")
        print("=" * 60)
        for signal, metrics_list in self.evaluator.compute_by_signal_strength().items():
            print(f"\n信号强度: {signal}")
            print(f"{'负载率':<10} {'用例数':<8} {'ASR':<10} {'RSR':<10}")
            print("-" * 40)
            for m in metrics_list:
                print(f"{m.load_ratio:<10.0%} {m.num_cases:<8} "
                      f"{m.asr:<10.2%} {m.rsr:<10.2%}")

        print("\n" + "=" * 60)
        print("关键发现")
        print("=" * 60)
        metrics = self.evaluator.compute_by_load_ratio()
        if len(metrics) >= 2:
            lowest = min(metrics, key=lambda m: m.asr)
            highest = max(metrics, key=lambda m: m.asr)
            print(f"最低 ASR: {lowest.asr:.2%} (负载率 {lowest.load_ratio:.0%})")
            print(f"最高 ASR: {highest.asr:.2%} (负载率 {highest.load_ratio:.0%})")
            if highest.load_ratio > lowest.load_ratio:
                trend = "随负载率上升"
            elif highest.load_ratio < lowest.load_ratio:
                trend = "随负载率下降"
            else:
                trend = "无明显趋势"
            print(f"趋势: ASR {trend}")
            diff = highest.asr - lowest.asr
            print(f"ASR 差值: {diff:+.2%}")


def run_from_config(config_path: str):
    """从配置文件运行实验"""
    with open(config_path, "r", encoding="utf-8") as f:
        config_data = json.load(f)

    config = ExperimentConfig(
        data_source=config_data.get("data_source", "mpbench"),
        data_dir=config_data.get("data_dir", "data/reconstructed"),
        attack_classes=config_data.get("attack_classes"),
        domains=config_data.get("domains"),
        signal_strength=config_data.get("signal_strength"),
        num_cases_per_group=config_data.get("num_cases_per_group"),
        load_ratios=config_data.get("load_ratios", [0.1, 0.3, 0.5, 0.7, 0.9]),
        context_window_size=config_data.get("context_window_size", 128000),
        agent_config=config_data.get("agent_config", {}),
        output_dir=config_data.get("output_dir", "results"),
        run_name=config_data.get("run_name", "default"),
        num_repeats=config_data.get("num_repeats", 1),
        run_retrieval=config_data.get("run_retrieval", True),
    )

    experiment = Experiment(config)
    experiment.run()
