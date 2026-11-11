# Context Load Attack (CLA)

> 研究上下文窗口负载率对 LLM Agent 记忆投毒/提示注入攻击成功率的影响。

## 研究假设

**同一个攻击手段、同一个模型，在不同上下文窗口占用率下，攻击成功率可能显著不同。**

- **上下文占用少** → 模型"注意力"充足，容易分辨恶意内容，攻击成功率低
- **上下文占用多** → 模型"降智"，注意力被稀释，容易被攻击，攻击成功率高

### 这个假设为什么重要

1. **动摇现有评测结论**：现有 IPI/记忆投毒 benchmark（AgentDojo、InjecAgent、MPBench）都没有控制上下文负载率这个变量。如果 ASR 随负载率变化，那么现有结论可能只在特定负载率下成立。

2. **揭示攻击的时间窗口**：攻击者可以选择在 Agent 上下文最满的时候发起攻击（比如长时间任务后、压缩触发前），提高成功率。

3. **指导防御设计**：如果高负载是攻击的放大器，那么防御可以针对性地在高负载时加强校验。

### 与 MPBench 的关系

本项目基于 MPBench（[arXiv:2606.04329](https://arxiv.org/abs/2606.04329)）的攻击分类和评测范式，但加入了**上下文负载率**这一新的自变量。

MPBench 证明了：
- 记忆投毒只需一次成功写入即可持久影响 Agent
- 现有 IPI 防御对弱信号记忆投毒失效（TPR 最高仅 67.67%）
- 防御必须前移到写入路径

本项目进一步探究：**这些结论在不同上下文负载率下是否稳定？**

## 项目结构

```
context-load-attack/
├── README.md
├── requirements.txt
├── config/
│   ├── experiment.json          # 实验配置
│   └── models.yaml              # 模型配置
├── src/
│   ├── __init__.py
│   ├── context_loader.py        # 上下文负载控制（核心）
│   ├── mpbench_adapter.py       # MPBench 数据加载
│   ├── injecagent_adapter.py    # InjecAgent 数据加载（替代数据集）
│   ├── agent_runner.py          # Agent 运行器
│   ├── evaluator.py             # ASR/RSR 计算
│   └── experiment.py            # 实验编排
├── data/
│   ├── reconstructed/           # 重建的 MPBench 测试用例
│   │   ├── explicit_command.json
│   │   ├── conditional_command.json
│   │   ├── salience_compaction.json
│   │   ├── policy_conformant.json
│   │   ├── false_precedent.json
│   │   └── skill_procedure.json
│   ├── injecagent/              # InjecAgent 数据集（已内置）
│   │   ├── user_cases.jsonl
│   │   ├── attacker_cases_dh.jsonl
│   │   └── attacker_cases_ds.jsonl
│   └── filler/                  # 良性填充内容（控制负载率）
│       ├── documents.json
│       └── code.json
├── scripts/
│   ├── run_experiment.py        # 运行实验
│   ├── analyze_results.py       # 结果分析与图表
│   ├── reconstruct_mpbench.py   # 生成更多测试用例
│   └── quick_test.py            # 框架快速测试
└── results/                     # 实验结果输出
```

## 核心方法

### 1. 上下文负载控制

通过向 Agent 上下文中注入**良性填充内容**（技术文档、代码片段等），将上下文占用率控制在目标水平：

```
目标负载率 = (基础上下文 + 填充内容) / 上下文窗口大小
```

填充内容的要求：
- **良性**：不包含攻击载荷或指令
- **语义相关**：与任务域相关，避免被模型视为异常
- **可计量**：精确控制 token 数

### 2. 实验设计（控制变量法）

| 变量 | 取值 |
|------|------|
| **自变量** | 上下文负载率：0.1, 0.3, 0.5, 0.7, 0.9 |
| **因变量** | ASR（攻击成功率）、RSR（检索成功率） |
| **控制变量** | 同一攻击用例、同一模型、同一 Agent 系统 |

### 3. 两阶段评测（遵循 MPBench 范式）

- **写入阶段**：攻击载荷 + 负载填充 → Agent 处理 → 检查记忆是否被污染
- **检索阶段**：新会话 → 相关查询 → 检查 Agent 响应是否反映中毒指令

### 4. 攻击类型覆盖

| 攻击类型 | 信号强度 | 覆盖通道 |
|----------|----------|----------|
| Explicit Command Insertion | 强 | C1 |
| Conditional Command Insertion | 强 | C1 |
| Salience-Driven Compaction | 强 | C3 |
| Policy-Conformant Fact Injection | 弱 | C2 |
| False Precedent Insertion | 弱 | C2 |
| Skill-Procedure Insertion | 弱 | C4 |

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 运行框架测试

```bash
python scripts/quick_test.py
```

### 3. 配置实验

编辑 `config/experiment.json`，设置：
- `data_source`：数据源（`injecagent` 或 `mpbench`）
- `data_dir`：数据目录
- `agent_config.api_base`：LLM API 地址
- `agent_config.model`：模型名称
- `agent_config.api_key`：API Key
- `load_ratios`：要测试的负载率列表
- `num_repeats`：每个用例的重复次数（建议 ≥ 3）

#### 切换数据源

```json
// 使用 InjecAgent（默认，已内置数据）
{
  "data_source": "injecagent",
  "data_dir": "data/injecagent"
}

// 使用重建的 MPBench 测试用例
{
  "data_source": "mpbench",
  "data_dir": "data/reconstructed"
}
```

### 4. 运行实验

```bash
# 使用默认配置
python scripts/run_experiment.py --config config/experiment.json

# 只测试弱信号攻击
python scripts/run_experiment.py --config config/experiment.json --signal-strength weak

# 只测试特定攻击类型
python scripts/run_experiment.py --config config/experiment.json --attack-classes policy_conformant false_precedent

# 自定义负载率和重复次数
python scripts/run_experiment.py --config config/experiment.json --load-ratios 0.1 0.5 0.9 --num-repeats 5
```

### 5. 分析结果

```bash
python scripts/analyze_results.py --results results/<结果文件>.json --output figures/
```

生成的图表：
- `asr_vs_load.png`：ASR/RSR 随负载率变化
- `asr_by_signal.png`：强信号 vs 弱信号攻击对比
- `asr_by_attack_class.png`：按攻击类型分组

### 6. 生成更多测试用例

```bash
python scripts/reconstruct_mpbench.py
```

## 数据集说明

本项目支持多种数据源，通过 `config/experiment.json` 中的 `data_source` 字段切换。

### InjecAgent（默认推荐）

[InjecAgent](https://github.com/iliaschalkidis/injec-agent) 是首个针对 LLM Agent 的
Indirect Prompt Injection (IPI) 基准测试，包含 17 个用户场景、30 个 Direct Harm 攻击
和 32 个 Data Stealing 攻击，可组合生成 1054 个测试用例。

数据已内置在 `data/injecagent/` 目录中，无需额外下载。

**与 MPBench 的差异**：
| 维度 | MPBench | InjecAgent |
|------|---------|------------|
| 攻击范式 | 记忆投毒（写入+检索两阶段） | 间接提示注入（工具返回值注入） |
| 攻击类型 | 6 类（强/弱信号） | Direct Harm / Data Stealing |
| 数据状态 | 未开源 | 已开源，已内置 |
| 适用场景 | 记忆持久化投毒 | 单次会话指令劫持 |

`src/injecagent_adapter.py` 将 InjecAgent 用例转换为统一的 `MPBenchCase` 格式，
确保实验框架无需改动即可运行。

### 重建的 MPBench 测试用例

由于 MPBench 官方数据集尚未公开发布，`data/reconstructed/` 中包含根据论文描述重建的
6 类攻击测试用例（124 条）。

当官方数据发布后：

1. 将数据放入 `data/mpbench/` 目录
2. 修改 `config/experiment.json` 中的 `data_source` 为 `mpbench`，`data_dir` 为 `data/mpbench`
3. 确保数据格式与 `src/mpbench_adapter.py` 中的 `MPBenchCase` 一致

### 其他可选数据集

以下开源数据集也可作为替代（需自行编写适配器）：
- **AgentDojo**（github.com/ethz-spylab/agentdojo）：97 任务、629 安全用例，动态环境
- **BIPIA**：首个 IPI 专用基准，250 个攻击者目标，5 种场景
- **AutoDojo**（github.com/xhOwenMa/AutoDojo）：生成式 PI 防御基准

## 支持的 Agent 系统

### 通用 LLM Agent（默认）

通过 OpenAI 兼容 API 调用任意 LLM。适用于大多数场景。

### OpenClaw

通过 CLI 调用 [OpenClaw](https://github.com/openclaw/openclaw)。

配置 `config/experiment.json`：
```json
{
  "agent_config": {
    "agent_type": "openclaw",
    "openclaw_path": "openclaw",
    "openclaw_config": "config/openclaw.yaml"
  }
}
```

## 预期发现（假设）

如果假设成立，实验结果应呈现：

1. **ASR 随负载率单调上升**：负载率越高，攻击成功率越高
2. **弱信号攻击更敏感**：弱信号攻击的 ASR 上升幅度大于强信号攻击（因为弱信号更依赖模型的注意力分辨能力）
3. **存在临界点**：在某个负载率以上，ASR 急剧上升（注意力崩溃）
4. **RSR 滞后于 ASR**：检索成功率的上升可能滞后于写入成功率

## 研究意义

### 对攻击方
- 揭示了"选择攻击时机"的重要性
- 高负载场景（长时间任务、压缩触发前）是攻击的黄金窗口

### 对防御方
- 在高负载时加强校验（如增加人工确认、降级记忆写入）
- 监控上下文负载率，超过阈值时触发额外安全检查
- 评测防御时必须控制负载率，否则结论不可靠

### 对评测基准
- 现有 benchmark 应加入负载率维度
- 攻击成功率应报告为负载率的函数，而非单一数值

## 局限性

1. **数据集替代**：MPBench 官方数据未开源，默认使用 InjecAgent 替代。InjecAgent 侧重
   间接提示注入（工具返回值劫持），与 MPBench 的记忆投毒范式存在差异，结论需谨慎外推。
2. **重建数据**：`data/reconstructed/` 中的 MPBench 用例为根据论文描述重建，非官方数据
3. **token 估算**：使用简单的字符/token 换算，非精确 tokenizer（可通过安装 tiktoken 改进）
4. **判定方式**：默认使用子串匹配判定 ASR/RSR，非 LLM judge（可扩展）
5. **单模型**：默认配置使用单一模型，跨模型验证需手动配置

## 引用

如果使用本项目，请引用：

```bibtex
@article{mpbench2026,
  title={From Untrusted Input to Trusted Memory: A Systematic Study of Memory Poisoning Attacks in LLM Agents},
  author={Dash, Pritam and Ge, Tongyu and Jain, Aditi and Shah, Tanmay and Shang, Zhiwei},
  journal={arXiv preprint arXiv:2606.04329},
  year={2026}
}

@inproceedings{injecagent2024,
  title={InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents},
  author={Qi, Zhuo and Chalkidis, Ilias and Singh, Amrit and others},
  booktitle={Proceedings of the 2024 Conference on Empirical Methods in Natural Language Processing (EMNLP)},
  year={2024}
}
```

## 许可证

MIT License
