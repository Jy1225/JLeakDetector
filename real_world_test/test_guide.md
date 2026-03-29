# 真实项目 / Juliet 测试指南

> 本文档按仓库当前**实际实现**整理，只保留当前默认实验中真正使用的项目与流程。  
> 当前默认真实项目实验对象：
>
> - `triplea`
> - `fitnesse`
>
> 当前已实现的自动实验脚本：
>
> - 真实项目：`real_world_test/run_real_world_experiments.py`
> - Juliet：`real_world_test/run_juliet_experiments.py`

---

## 0. 环境准备

### 0.1 安装通用工具

```bash
sudo apt update
sudo apt install -y git curl unzip zip ant maven build-essential
```

### 0.2 准备 JDK

当前建议准备两套 JDK：

- **JDK 8 + JavaFX**：用于 `triplea`
- **JDK 8**：用于 `fitnesse`

建议环境变量：

```bash
export JDK8_FX_HOME=/path/to/jdk8-with-javafx
export JDK8_HOME=/path/to/jdk8
```

建议再定义两个切换函数：

```bash
use_jdk8fx() {
  export JAVA_HOME="$JDK8_FX_HOME"
  export PATH="$JAVA_HOME/bin:$PATH"
  hash -r
  java -version
  javac -version
}

use_jdk8() {
  export JAVA_HOME="$JDK8_HOME"
  export PATH="$JAVA_HOME/bin:$PATH"
  hash -r
  java -version
  javac -version
}
```

### 0.3 创建统一工作目录

```bash
export RW_ROOT=~/Desktop/real_world_repos
mkdir -p "$RW_ROOT"
cd "$RW_ROOT"
```

---

## 1. 当前自动实验入口

当前 `real_world_test/experiment_config.json` 的默认状态是：

- `model_name = qwen-plus`
- `real_world.projects = [triplea, fitnesse]`
- `juliet.enabled = false`

### 1.1 运行真实项目自动实验

```bash
cd ~/Desktop/JLeakDetector
python3 real_world_test/run_real_world_experiments.py --config real_world_test/experiment_config.json
```

### 1.2 运行 Juliet 自动实验

如果要跑 Juliet，请先把 `real_world_test/experiment_config.json` 中的：

```json
"juliet": {
  "enabled": true
}
```

然后执行：

```bash
cd ~/Desktop/JLeakDetector
python3 real_world_test/run_juliet_experiments.py --config real_world_test/experiment_config.json
```

---

## 2. 当前保留的项目总表

| 项目 | 仓库地址 | parent commit（真实 buggy） | fixed commit | 推荐 JDK | 推荐构建命令 | 当前用途 |
|---|---|---|---|---|---|---|
| triplea-game/triplea | `https://github.com/triplea-game/triplea.git` | `abb3661486d07f7f1b0cd4f00c694c3869b53110` | `598cfd23d4c7e654541e5377e7f2ca1dc9c5ef49` | JDK 8 + JavaFX | `./gradlew classes` | 当前默认自动实验项目 |
| unclebob/fitnesse | `https://github.com/unclebob/fitnesse.git` | `2b8cce7c23b8804b71ed41c418a7a056f7feb780` | `ffd57b67b4703d1672480d5251f307def18f628f` | JDK 8 | `./gradlew classes` | 当前默认自动实验项目 |

---

## 3. TripleA

### 3.1 clone + checkout parent commit

```bash
cd "$RW_ROOT"
git clone https://github.com/triplea-game/triplea.git
cd triplea
git checkout abb3661486d07f7f1b0cd4f00c694c3869b53110
```

### 3.2 build

```bash
use_jdk8fx
./gradlew --version
./gradlew classes --no-daemon --stacktrace
```

### 3.3 主要输出目录

```bash
build/classes/java/main
```

### 3.4 如需切到 fixed commit 对照

```bash
git checkout 598cfd23d4c7e654541e5377e7f2ca1dc9c5ef49
./gradlew classes --no-daemon --stacktrace
```

### 3.5 常见问题

#### 报错：`Could not determine java version from '11.x'` 或 `17.x`
原因：Gradle 太老，不兼容高版本 JDK。  
处理：切回 **JDK 8**。

```bash
use_jdk8fx
```

#### 报错：`package javafx.* does not exist`
原因：当前 JDK 8 不带 JavaFX。  
处理：换成**带 JavaFX 的 JDK 8**。

#### 报错：发布相关任务失败（`install4j` / assets）
处理：只跑：

```bash
./gradlew classes
```

---

## 4. FitNesse

### 4.1 clone + checkout parent commit

```bash
cd "$RW_ROOT"
git clone https://github.com/unclebob/fitnesse.git
cd fitnesse
git checkout 2b8cce7c23b8804b71ed41c418a7a056f7feb780
```

### 4.2 build

```bash
use_jdk8
./gradlew classes --no-daemon --stacktrace
```

### 4.3 主要输出目录

常见目录：

```bash
build/classes/java/main
build/classes/main
```

可统一检查：

```bash
find build -type d \( -path '*/classes/java/main' -o -path '*/classes/main' -o -path '*/classes' \)
```

### 4.4 如需切到 fixed commit 对照

```bash
git checkout ffd57b67b4703d1672480d5251f307def18f628f
./gradlew classes --no-daemon --stacktrace
```

### 4.5 常见问题

#### 报错：Gradle wrapper 下载失败 / 网络超时
处理：重试；必要时配置代理或镜像。

#### 报错：旧 Gradle 对高版本 JDK 不兼容
处理：优先使用 **JDK 8**。

```bash
use_jdk8
```

#### 报错：测试任务或额外质量检查失败
处理：只跑：

```bash
./gradlew classes
```

---

## 5. RepoAudit 实际运行方式

### 5.1 统一准备

```bash
export REPOAUDIT_DIR=~/Desktop/JLeakDetector
export RW_ROOT=~/Desktop/real_world_repos

cd "$REPOAUDIT_DIR/src"

export MODEL=qwen-plus
export REPOAUDIT_LANGUAGE=Java
export ENABLE_SOOT_PREFILTER=true
export AUTO_GENERATE_SOOT_FACTS=true
export SOOT_TIMEOUT_SEC=600
export SOOT_TIMEOUT_MS=500
export REPOAUDIT_CALL_DEPTH=15
export REPOAUDIT_MAX_NEURAL_WORKERS=16
```

建议每切换一个项目前先清理一次：

```bash
unset SOOT_CLASS_DIR
unset SOOT_CLASSPATH
unset SOOT_FACTS_PATH
unset SOOT_FACTS_MODE
unset SOOT_COMPILE_BEFORE
```

如果 bridge 模式下遇到内存不足，可先加：

```bash
export JAVA_TOOL_OPTIONS="-Xms1g -Xmx8g"
```

跑完后查看最新结果目录：

```bash
ls -1dt ../result/dfbscan/$MODEL/MLK/Java/<项目目录名>/* | head -n 1
```

### 5.2 常见输出文件

每次结果目录中常见文件包括：

- `detect_info.json`
- `detect_info_by_file.json`
- `detect_info_raw.json`
- `detect_info_issue_stats.json`
- `review_units.xlsx`
- `run_metrics_raw.json`
- `experiment_run_meta.json`
- `real_world_metrics.json`（真实项目：每次 run 自动生成，和 `detect_info.json` 同级）
- `juliet_metrics.json`（Juliet：每次 run 自动生成，和 `detect_info.json` 同级）
- `transfer_info.json`

---

## 6. 当前自动输出说明

### 6.1 真实项目

当前 `run_real_world_experiments.py` 会在**每次单个结果目录**下自动生成：

```bash
<result_dir>/real_world_metrics.json
```

例如：

```bash
result/dfbscan/deepseek-chat/MLK/Java/fitnesse/2026-03-27-13-22-01-0/real_world_metrics.json
```

该文件是**单次 run 的真实项目指标汇总**，包含：

- `benchmark_hit_rate`
- `Top-k% Recall`
- `MRR`
- `raw_report_count`
- `issue_count`
- `reduction_ratio`
- `inspection_burden`
- 时间 / token 成本

### 6.2 Juliet

当前 `run_juliet_experiments.py` 会在**每次 toy 结果目录**下自动生成：

```bash
<result_dir>/juliet_metrics.json
```

例如：

```bash
result/dfbscan/qwen-plus/MLK/Java/toy/2026-03-28-15-46-21-0/juliet_metrics.json
```

Juliet 当前按 **bug-unit** 口径评估：

- 使用 `detect_info_raw.json`
- 使用 `juliet_dataset.xlsx` 中每个 `key_variable` 作为一个真实资源泄露点

其中关键字段包括：

- `benchmark_total_bug_hint`
- `tp_bug_count`
- `fn_bug_count`
- `tp_bug_rate`
- `tp_raw_report_count`
- `fp_raw_report_count`

---

## 7. TripleA：推荐用 Soot bridge

### 7.1 重新确认编译产物

```bash
use_jdk8fx
cd "$RW_ROOT/triplea"
./gradlew classes --no-daemon --stacktrace
```

### 7.2 导出 TripleA 的 compile classpath

```bash
cat >/tmp/print_triplea_cp.init.gradle <<'EOF'
gradle.rootProject {
  afterEvaluate {
    tasks.create(name: "printMainCompileClasspath") {
      doLast {
        println sourceSets.main.compileClasspath.asPath
      }
    }
  }
}
EOF
```

执行：

```bash
cd "$RW_ROOT/triplea"
./gradlew -q -I /tmp/print_triplea_cp.init.gradle printMainCompileClasspath | tail -n 1 > /tmp/triplea.cp
cat /tmp/triplea.cp
```

### 7.3 运行 RepoAudit（bridge）

```bash
cd "$REPOAUDIT_DIR/src"
use_jdk8fx

export PROJECT_PATH="$RW_ROOT/triplea"
export SOOT_CLASS_DIR="$PROJECT_PATH/build/classes/java/main"
export SOOT_CLASSPATH="$(tr -d '\r' </tmp/triplea.cp):$SOOT_CLASS_DIR"
export SOOT_FACTS_PATH="$PROJECT_PATH/.repoaudit/soot_facts.json"
export SOOT_FACTS_MODE=bridge
export SOOT_COMPILE_BEFORE=false

bash run_repoaudit.sh "$PROJECT_PATH" MLK
```

### 7.4 查看结果

```bash
LATEST_RESULT=$(ls -1dt ../result/dfbscan/$MODEL/MLK/Java/triplea/* | head -n 1)
echo "$LATEST_RESULT"
ls "$LATEST_RESULT"
```

### 7.5 常见失败处理

#### 情况 1：`printMainCompileClasspath` 执行失败
可临时降级为：

```bash
export SOOT_CLASSPATH="$SOOT_CLASS_DIR"
```

#### 情况 2：bridge 生成 `soot_facts.json` 时 OOM
先加大 JVM 堆：

```bash
export JAVA_TOOL_OPTIONS="-Xms1g -Xmx8g"
```

如果仍不稳，可临时回退到：

```bash
unset SOOT_CLASS_DIR
unset SOOT_CLASSPATH
export SOOT_FACTS_MODE=ts-fallback
export SOOT_COMPILE_BEFORE=false
bash run_repoaudit.sh "$PROJECT_PATH" MLK
```

---

## 8. FitNesse：推荐用 Soot bridge

### 8.1 重新确认编译

```bash
use_jdk8
cd "$RW_ROOT/fitnesse"
./gradlew classes --no-daemon --stacktrace
```

### 8.2 生成 Soot facts（bridge）

推荐直接用仓库中的脚本：

```bash
cd "$REPOAUDIT_DIR"
use_jdk8
bash real_world_test/generate_soot_fitnesse.sh "$RW_ROOT/fitnesse"
```

默认输出：

```bash
$RW_ROOT/fitnesse/.repoaudit/soot_facts.json
```

### 8.3 运行 RepoAudit（bridge）

```bash
cd "$REPOAUDIT_DIR/src"
use_jdk8

export PROJECT_PATH="$RW_ROOT/fitnesse"
export SOOT_FACTS_PATH="$PROJECT_PATH/.repoaudit/soot_facts.json"
export AUTO_GENERATE_SOOT_FACTS=false
export SOOT_FACTS_MODE=bridge
export SOOT_COMPILE_BEFORE=false

bash run_repoaudit.sh "$PROJECT_PATH" MLK
```

### 8.4 查看结果

```bash
LATEST_RESULT=$(ls -1dt ../result/dfbscan/$MODEL/MLK/Java/fitnesse/* | head -n 1)
echo "$LATEST_RESULT"
ls "$LATEST_RESULT"
```

### 8.5 常见失败处理

#### 情况 1：bridge 找不到 class 输出目录
可先检查：

```bash
find build -type d \( -path '*/classes/java/main' -o -path '*/classes/main' -o -path '*/classes' \)
```

#### 情况 2：只想先快速跑完整流程
可临时退回：

```bash
unset SOOT_CLASS_DIR
unset SOOT_CLASSPATH
export SOOT_FACTS_MODE=ts-fallback
export SOOT_COMPILE_BEFORE=false
bash run_repoaudit.sh "$PROJECT_PATH" MLK
```

---

## 9. 建议的实际实验顺序

当前只保留两个真实项目时，建议顺序是：

1. `triplea`
2. `fitnesse`

原因：

- `triplea` 对 JavaFX 和旧 Gradle 更敏感，建议先把环境稳定下来
- `fitnesse` 结构更简单，适合在 triplea 跑通后快速补齐结果

---

## 10. 建议记录的信息

每跑完一次项目，建议记录：

- 使用的 JDK 版本
- 是否启用 Soot / issue-first
- 是否一次构建成功
- 失败报错关键词
- 最终 class 输出路径
- 结果目录路径
- 是否成功生成：
  - `review_units.xlsx`
  - `run_metrics_raw.json`
  - `real_world_metrics.json` / `juliet_metrics.json`

这样后面写实验部分会省很多时间。
