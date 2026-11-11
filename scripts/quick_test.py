#!/usr/bin/env python3
"""
quick_test.py
=============
快速测试实验框架是否正常工作（不实际调用 LLM）。
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.mpbench_adapter import MPBenchAdapter
from src.injecagent_adapter import InjecAgentAdapter
from src.agentdojo_adapter import AgentDojoAdapter
from src.context_loader import FillerBank, estimate_tokens, ContextLoadConfig
from src.evaluator import ExperimentMetrics


def test_mpbench_adapter():
    print("测试 MPBenchAdapter...")
    adapter = MPBenchAdapter("data/reconstructed")
    summary = adapter.summary()
    print(f"  总用例数: {summary['total']}")
    print(f"  攻击类型: {list(summary['by_attack_class'].keys())}")
    print(f"  任务域: {list(summary['by_domain'].keys())}")
    assert summary["total"] > 0, "没有加载到测试用例"
    print("  [PASS]")


def test_injecagent_adapter():
    print("测试 InjecAgentAdapter...")
    adapter = InjecAgentAdapter("data/injecagent")
    summary = adapter.summary()
    print(f"  总用例数: {summary['total']}")
    print(f"  攻击类型: {list(summary['by_attack_class'].keys())}")
    print(f"  任务域: {list(summary['by_domain'].keys())}")
    print(f"  攻击子类型: {list(summary['by_attack_type'].keys())}")
    assert summary["total"] > 0, "没有加载到 InjecAgent 测试用例"
    assert "direct_harm" in summary["by_attack_class"], "缺少 direct_harm 类"
    assert "data_stealing" in summary["by_attack_class"], "缺少 data_stealing 类"

    # 检查单个用例的字段完整性
    cases = adapter.get_cases(limit=1)
    assert len(cases) == 1
    c = cases[0]
    assert c.payload, "payload 为空"
    assert c.task_description, "task_description 为空"
    assert c.target_instruction, "target_instruction 为空"
    assert c.expected_memory_pattern, "expected_memory_pattern 为空"
    assert "<Attacker Instruction>" not in c.payload, \
        "payload 中仍存在未替换的占位符"
    print(f"  示例 case_id: {c.case_id}")
    print(f"  示例 attack_class: {c.attack_class}")
    print(f"  示例 domain: {c.domain}")
    print(f"  示例 memory_pattern: {c.expected_memory_pattern!r}")
    print("  [PASS]")


def test_agentdojo_adapter():
    print("测试 AgentDojoAdapter...")
    adapter = AgentDojoAdapter("data/agentdojo")
    summary = adapter.summary()
    print(f"  总用例数: {summary['total']}")
    print(f"  攻击类型: {list(summary['by_attack_class'].keys())}")
    print(f"  套件: {list(summary['by_suite'].keys())}")
    assert summary["total"] > 0, "没有加载到 AgentDojo 测试用例"
    assert len(summary["by_suite"]) >= 2, "套件数量不足"

    # 检查字段完整性
    cases = adapter.get_cases(limit=1)
    assert len(cases) == 1
    c = cases[0]
    assert c.payload, "payload 为空"
    assert c.task_description, "task_description 为空"
    assert c.target_instruction, "target_instruction 为空"
    assert c.expected_memory_pattern, "expected_memory_pattern 为空"
    assert "[Tool Output" in c.payload, "payload 未包装为工具返回值"
    print(f"  示例 case_id: {c.case_id}")
    print(f"  示例 attack_class: {c.attack_class}")
    print(f"  示例 domain: {c.domain}")
    print(f"  示例 memory_pattern: {c.expected_memory_pattern!r}")
    print("  [PASS]")


def test_filler_bank():
    print("测试 FillerBank...")
    bank = FillerBank("data/filler")
    print(f"  填充内容数: {len(bank.fillers)}")
    padding = bank.build_context_padding(5000, "random", "document")
    tokens = estimate_tokens(padding)
    print(f"  5000 token 目标 -> 实际 {tokens} tokens")
    print("  [PASS]")


def test_context_load_config():
    print("测试 ContextLoadConfig...")
    config = ContextLoadConfig(
        target_load_ratio=0.5,
        context_window_size=128000,
        base_context_tokens=5000,
    )
    print(f"  目标负载率: 50%")
    print(f"  基础 token: 5000")
    print(f"  需要填充: {config.filler_tokens} tokens")
    assert config.filler_tokens > 0
    print("  [PASS]")


def test_evaluator():
    print("测试 Evaluator...")
    from src.evaluator import Evaluator
    from src.agent_runner import AgentRunResult

    evaluator = Evaluator()
    # 模拟结果
    for i in range(10):
        r = AgentRunResult(
            case_id=f"policy_email_{i:03d}",
            load_ratio=0.3,
            actual_tokens=40000,
            attack_class="policy_conformant",
            signal_strength="weak",
            asr_success=(i % 3 == 0),
            rsr_success=(i % 6 == 0),
        )
        evaluator.add_result(r)

    metrics = evaluator.compute_by_load_ratio()
    assert len(metrics) == 1
    m = metrics[0]
    print(f"  用例数: {m.num_cases}")
    print(f"  ASR: {m.asr:.2%}")
    print(f"  RSR: {m.rsr:.2%}")
    print("  [PASS]")


def main():
    print("=" * 50)
    print("快速测试")
    print("=" * 50)

    test_mpbench_adapter()
    test_injecagent_adapter()
    test_agentdojo_adapter()
    test_filler_bank()
    test_context_load_config()
    test_evaluator()

    print("\n" + "=" * 50)
    print("所有测试通过！")
    print("=" * 50)
    print("\n下一步:")
    print("  1. 配置 config/experiment.json 中的 API 地址和模型")
    print("  2. 运行 python scripts/run_experiment.py")
    print("  3. 运行 python scripts/analyze_results.py --results <结果文件>")


if __name__ == "__main__":
    main()
