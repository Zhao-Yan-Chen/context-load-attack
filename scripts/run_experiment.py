#!/usr/bin/env python3
"""
run_experiment.py
=================
运行上下文负载 vs 攻击成功率实验。

用法:
    python scripts/run_experiment.py --config config/experiment.json
    python scripts/run_experiment.py --config config/experiment.json --attack-classes policy_conformant false_precedent
    python scripts/run_experiment.py --config config/experiment.json --load-ratios 0.1 0.5 0.9 --num-repeats 5
"""

import argparse
import json
import sys
from pathlib import Path

# 让 src 可导入
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.experiment import ExperimentConfig, run_from_config


def main():
    parser = argparse.ArgumentParser(description="上下文负载 vs 攻击成功率 实验")
    parser.add_argument("--config", type=str, default="config/experiment.json",
                        help="实验配置文件路径")
    parser.add_argument("--load-ratios", type=float, nargs="+", default=None,
                        help="覆盖配置中的负载率列表")
    parser.add_argument("--attack-classes", type=str, nargs="+", default=None,
                        help="指定攻击类型")
    parser.add_argument("--domains", type=str, nargs="+", default=None,
                        help="指定任务域")
    parser.add_argument("--signal-strength", type=str, choices=["strong", "weak"],
                        default=None, help="指定信号强度")
    parser.add_argument("--num-repeats", type=int, default=None,
                        help="每个用例的重复次数")
    parser.add_argument("--num-cases", type=int, default=None,
                        help="每个分组的用例数限制")
    parser.add_argument("--run-name", type=str, default=None,
                        help="实验运行名称")

    args = parser.parse_args()

    # 加载配置
    with open(args.config, "r", encoding="utf-8") as f:
        config_data = json.load(f)

    # 命令行覆盖
    if args.load_ratios:
        config_data["load_ratios"] = args.load_ratios
    if args.attack_classes:
        config_data["attack_classes"] = args.attack_classes
    if args.domains:
        config_data["domains"] = args.domains
    if args.signal_strength:
        config_data["signal_strength"] = args.signal_strength
    if args.num_repeats:
        config_data["num_repeats"] = args.num_repeats
    if args.num_cases:
        config_data["num_cases_per_group"] = args.num_cases
    if args.run_name:
        config_data["run_name"] = args.run_name

    # 保存实际使用的配置
    run_config_path = Path(config_data.get("output_dir", "results")) / \
                      f"{config_data.get('run_name', 'exp')}_config.json"
    run_config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(run_config_path, "w", encoding="utf-8") as f:
        json.dump(config_data, f, ensure_ascii=False, indent=2)
    print(f"[INFO] 配置已保存: {run_config_path}")

    # 运行实验
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

    from src.experiment import Experiment
    experiment = Experiment(config)
    experiment.run()


if __name__ == "__main__":
    main()
