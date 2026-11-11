#!/usr/bin/env python3
"""
analyze_results.py
==================
分析实验结果，生成图表。

用法:
    python scripts/analyze_results.py --results results/context_load_experiment_20260101_120000.json
    python scripts/analyze_results.py --results results/context_load_experiment_20260101_120000.json --output figures/
"""

import argparse
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


def load_results(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def plot_asr_vs_load(data: dict, output_dir: Path):
    """绘制 ASR 随负载率变化的曲线"""
    overall = data["overall"]
    load_ratios = [m["load_ratio"] for m in overall]
    asrs = [m["asr"] for m in overall]
    rsrs = [m["rsr"] for m in overall]

    fig, ax = plt.subplots(figsize=(10, 6))

    ax.plot(load_ratios, asrs, "o-", label="ASR (Attack Success Rate)",
            color="#e74c3c", linewidth=2, markersize=8)
    ax.plot(load_ratios, rsrs, "s-", label="RSR (Retrieval Success Rate)",
            color="#3498db", linewidth=2, markersize=8)

    ax.set_xlabel("Context Load Ratio", fontsize=13)
    ax.set_ylabel("Rate", fontsize=13)
    ax.set_title("Attack Success Rate vs Context Window Load", fontsize=15)
    ax.legend(fontsize=11)
    ax.set_ylim(0, 1.05)
    ax.set_xlim(min(load_ratios) - 0.05, max(load_ratios) + 0.05)
    ax.grid(True, alpha=0.3)

    # 标注数值
    for x, y in zip(load_ratios, asrs):
        ax.annotate(f"{y:.1%}", (x, y), textcoords="offset points",
                    xytext=(0, 12), ha="center", fontsize=9)

    plt.tight_layout()
    fig.savefig(output_dir / "asr_vs_load.png", dpi=150)
    plt.close(fig)
    print(f"[OK] 已生成: asr_vs_load.png")


def plot_by_signal_strength(data: dict, output_dir: Path):
    """按信号强度分组绘制"""
    by_signal = data.get("by_signal_strength", {})

    fig, ax = plt.subplots(figsize=(10, 6))
    colors = {"strong": "#e67e22", "weak": "#9b59b6"}

    for signal, metrics_list in by_signal.items():
        load_ratios = [m["load_ratio"] for m in metrics_list]
        asrs = [m["asr"] for m in metrics_list]
        ax.plot(load_ratios, asrs, "o-", label=f"{signal} signal ASR",
                color=colors.get(signal, "#333"), linewidth=2, markersize=8)

    ax.set_xlabel("Context Load Ratio", fontsize=13)
    ax.set_ylabel("ASR", fontsize=13)
    ax.set_title("ASR vs Context Load: Strong vs Weak Signal Attacks", fontsize=15)
    ax.legend(fontsize=11)
    ax.set_ylim(0, 1.05)
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    fig.savefig(output_dir / "asr_by_signal.png", dpi=150)
    plt.close(fig)
    print(f"[OK] 已生成: asr_by_signal.png")


def plot_by_attack_class(data: dict, output_dir: Path):
    """按攻击类型分组绘制"""
    by_class = data.get("by_attack_class", {})

    fig, ax = plt.subplots(figsize=(12, 7))
    colors = plt.cm.Set3(np.linspace(0, 1, len(by_class)))

    for (attack_class, metrics_list), color in zip(by_class.items(), colors):
        load_ratios = [m["load_ratio"] for m in metrics_list]
        asrs = [m["asr"] for m in metrics_list]
        ax.plot(load_ratios, asrs, "o-", label=attack_class,
                color=color, linewidth=2, markersize=6)

    ax.set_xlabel("Context Load Ratio", fontsize=13)
    ax.set_ylabel("ASR", fontsize=13)
    ax.set_title("ASR vs Context Load by Attack Class", fontsize=15)
    ax.legend(fontsize=9, loc="best")
    ax.set_ylim(0, 1.05)
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    fig.savefig(output_dir / "asr_by_attack_class.png", dpi=150)
    plt.close(fig)
    print(f"[OK] 已生成: asr_by_attack_class.png")


def print_summary(data: dict):
    """打印分析摘要"""
    print("\n" + "=" * 60)
    print("结果分析摘要")
    print("=" * 60)

    overall = data["overall"]
    if not overall:
        print("无数据")
        return

    asrs = [m["asr"] for m in overall]
    load_ratios = [m["load_ratio"] for m in overall]

    min_idx = np.argmin(asrs)
    max_idx = np.argmax(asrs)

    print(f"\n整体 ASR 范围: {min(asrs):.2%} ~ {max(asrs):.2%}")
    print(f"最低 ASR: {asrs[min_idx]:.2%} (负载率 {load_ratios[min_idx]:.0%})")
    print(f"最高 ASR: {asrs[max_idx]:.2%} (负载率 {load_ratios[max_idx]:.0%})")

    # 计算相关性
    if len(asrs) >= 3:
        corr = np.corrcoef(load_ratios, asrs)[0, 1]
        print(f"负载率与 ASR 的 Pearson 相关系数: {corr:.3f}")
        if corr > 0.3:
            print("→ ASR 随负载率上升（上下文越长越容易被攻击）")
        elif corr < -0.3:
            print("→ ASR 随负载率下降")
        else:
            print("→ ASR 与负载率无明显线性相关")

    # 按信号强度
    by_signal = data.get("by_signal_strength", {})
    if by_signal:
        print(f"\n按信号强度:")
        for signal, metrics_list in by_signal.items():
            asrs_s = [m["asr"] for m in metrics_list]
            print(f"  {signal}: {min(asrs_s):.2%} ~ {max(asrs_s):.2%}")


def main():
    parser = argparse.ArgumentParser(description="分析实验结果")
    parser.add_argument("--results", type=str, required=True,
                        help="实验结果 JSON 文件路径")
    parser.add_argument("--output", type=str, default="figures",
                        help="图表输出目录")

    args = parser.parse_args()

    data = load_results(args.results)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    plot_asr_vs_load(data, output_dir)
    plot_by_signal_strength(data, output_dir)
    plot_by_attack_class(data, output_dir)
    print_summary(data)

    print(f"\n[INFO] 所有图表已保存到: {output_dir}")


if __name__ == "__main__":
    main()
