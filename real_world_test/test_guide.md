# 真实项目测试：5 个项目的 clone / checkout parent commit / build 命令清单

> 适用场景：为 **RepoAudit / Soot / 静态分析** 准备可用的 `.class` 文件。  
> 默认环境：**Ubuntu / WSL / Linux shell**。如果你在 Windows 原生环境下操作，强烈建议放到 WSL 里执行。  
> 说明：这里优先给出“**最小可编译**”命令，即优先获得 `classes` / `compile` 结果，而不是完整打包/发布。

---

## 0. 先统一准备环境

### 0.1 安装通用工具

```bash
sudo apt update
sudo apt install -y git curl unzip zip ant maven build-essential
```

### 0.2 准备 JDK

这 5 个项目里，**至少建议准备两套 JDK**：

- **JDK 8 + JavaFX**：给 `triplea-game/triplea`
- **JDK 8**：给 `unclebob/fitnesse`
- 其他项目（Lucene / Vaadin / CoreNLP）优先尝试 **JDK 8**

> 注意：TripleA 最稳的是 **带 JavaFX 的 JDK 8**。  
> 普通 OpenJDK 8 在某些 Linux 发行版上**不带 JavaFX**，会导致 `javafx.* does not exist`。

建议先定义环境变量（请把路径改成你自己机器上的实际路径）：

```bash
export JDK8_FX_HOME=/path/to/jdk8-with-javafx
export JDK8_HOME=/path/to/jdk8
```

再定义几个切换函数：

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

## 1. 项目总表

| 项目 | 仓库地址 | parent commit（真实 buggy） | fixed commit（Excel 的 commit url） | 推荐 JDK | 推荐构建命令 |
|---|---|---|---|---|---|
| triplea-game/triplea | `https://github.com/triplea-game/triplea.git` | `abb3661486d07f7f1b0cd4f00c694c3869b53110` | `598cfd23d4c7e654541e5377e7f2ca1dc9c5ef49` | JDK 8 + JavaFX | `./gradlew classes` |
| apache/lucene | `https://github.com/apache/lucene.git` | `98f7ab5137e056bedb924ed88d88505ad8b0f15e` | `b6c6d5e9ffb2f5d8a8b06ad6269de5d17b312b5f` | JDK 8 | `ant compile` |
| unclebob/fitnesse | `https://github.com/unclebob/fitnesse.git` | `2b8cce7c23b8804b71ed41c418a7a056f7feb780` | `ffd57b67b4703d1672480d5251f307def18f628f` | JDK 8 | `./gradlew classes` |
| vaadin/framework | `https://github.com/vaadin/framework.git` | `53701564b197d1d30bd3dbc2f4e6a8d01b01b25a` | `6b8f9779fbc8c81d1dff2ac139bd41535018aa78` | JDK 8 | `mvn -DskipTests -Dmaven.javadoc.skip=true compile` |
| stanfordnlp/CoreNLP | `https://github.com/stanfordnlp/CoreNLP.git` | `28a10fca03e8f6c0f6aaaa39fc7817d574fb014b` | `0a061469ec491ae4512d98233ca15e76caafe20b` | JDK 8 | `mvn -DskipTests compile` |

---

## 2. TripleA

### 2.1 clone + checkout parent commit

```bash
cd "$RW_ROOT"
git clone https://github.com/triplea-game/triplea.git
cd triplea
git checkout abb3661486d07f7f1b0cd4f00c694c3869b53110
```

### 2.2 build（推荐先拿 class 文件，不做发布）

```bash
use_jdk8fx
./gradlew --version
./gradlew classes --no-daemon --stacktrace
```

### 2.3 主要输出目录

```bash
build/classes/java/main
```

### 2.4 如需切到 fixed commit 对照

```bash
git checkout 598cfd23d4c7e654541e5377e7f2ca1dc9c5ef49
./gradlew classes --no-daemon --stacktrace
```

### 2.5 常见报错与处理

#### 报错 1：`Could not determine java version from '11.x'` 或 `17.x`
**原因**：Gradle 4.1 太老，不支持新 JDK。  
**处理**：必须切回 **JDK 8**。

```bash
use_jdk8fx
./gradlew --version
```

#### 报错 2：`package javafx.* does not exist`
**原因**：你当前用的 JDK 8 不带 JavaFX。  
**处理**：换成 **带 JavaFX 的 JDK 8**（例如 Liberica Full JDK 8 / ZuluFX 8）。

#### 报错 3：依赖下载失败（`jcenter()` / Gradle 插件下载失败）
**原因**：历史仓库依赖老仓库，网络或仓库可用性不稳定。  
**处理**：
1. 先重试一次；
2. 确认你的终端能访问外网；
3. 必要时配置代理；
4. 如果仍失败，在实验记录中注明“历史依赖仓库不可用”。

#### 报错 4：发布相关任务失败（`install4j` / assets）
**原因**：你执行了发布链路。  
**处理**：只执行：

```bash
./gradlew classes
```

不要先跑 `release`、`generateInstallers` 之类任务。

---

## 3. Apache Lucene

> 这个历史版本实际上还是 **Lucene/Solr 单仓库** 的结构，官方 README 明确写的是 `ant compile`。

### 3.1 clone + checkout parent commit

```bash
cd "$RW_ROOT"
git clone https://github.com/apache/lucene.git
cd lucene
git checkout 98f7ab5137e056bedb924ed88d88505ad8b0f15e
```

### 3.2 build

```bash
use_jdk8
ant compile
```

如果第一次就提示 Ivy 不可用，先执行：

```bash
ant ivy-bootstrap
ant compile
```

### 3.3 主要输出位置

Lucene/Solr 是多模块 Ant 工程，编译产物不会只有一个目录。通常在：

```bash
lucene/build/
solr/build/
```

建议编译完后自己查一遍：

```bash
find lucene solr -type d | grep '/classes$\|/classes/java\|/classes/test'
```

### 3.4 如需切到 fixed commit 对照

```bash
git checkout b6c6d5e9ffb2f5d8a8b06ad6269de5d17b312b5f
ant compile
```

### 3.5 常见报错与处理

#### 报错 1：`Minimum supported Java version is 1.8`
**原因**：JDK 太老。  
**处理**：切到 JDK 8 或更高，但建议直接用 JDK 8。

```bash
use_jdk8
```

#### 报错 2：`Ivy is not available`
**处理**：先运行：

```bash
ant ivy-bootstrap
```

然后再跑：

```bash
ant compile
```

#### 报错 3：Ant 版本过低
如果日志出现类似：
- `Minimum supported ANT version is 1.8.2`

处理：升级 Ant。

```bash
ant -version
sudo apt install -y ant
```

#### 报错 4：完整 `ant compile` 太慢
如果你只是先验证环境，可以先尝试更小目标：

```bash
ant compile-core
```

但正式实验前仍建议跑一次完整 `ant compile`。

---

## 4. FitNesse

> 这个项目是单仓 Gradle 工程，相比多仓联动构建项目明显更容易复现。  
> 对你现在的真实项目实验目标来说，优先拿到 `build/classes` 下的 `.class` 即可。

### 4.1 clone + checkout parent commit

```bash
cd "$RW_ROOT"
git clone https://github.com/unclebob/fitnesse.git
cd fitnesse
git checkout 2b8cce7c23b8804b71ed41c418a7a056f7feb780
```

### 4.2 build（推荐最小编译）

```bash
use_jdk8
./gradlew classes --no-daemon --stacktrace
```

如果你希望额外产出 jar，也可以执行：

```bash
./gradlew jar --no-daemon --stacktrace
```

### 4.3 主要输出位置

历史 Gradle 项目常见输出目录有两种，建议都检查：

```bash
build/classes/java/main
build/classes/main
```

统一检查命令：

```bash
find build -type d \( -path '*/classes/java/main' -o -path '*/classes/main' -o -path '*/classes' \)
```

### 4.4 如需切到 fixed commit 对照

```bash
git checkout ffd57b67b4703d1672480d5251f307def18f628f
./gradlew classes --no-daemon --stacktrace
```

### 4.5 常见报错与处理

#### 报错 1：Gradle wrapper 下载失败 / 网络超时
**处理**：重试；必要时配置代理或镜像。

#### 报错 2：旧 Gradle 对高版本 JDK 不兼容
**处理**：优先坚持使用 **JDK 8**。

```bash
use_jdk8
```

#### 报错 3：测试任务或额外质量检查失败
**处理**：你当前只是为了拿 `.class`，优先使用：

```bash
./gradlew classes
```

不要先追求完整 `build` / `test` / `release`。

---

## 5. Vaadin Framework

> 这是老牌 Maven 多模块 Web/UI 项目。官方 README 给出的构建方式是 `mvn install`。  
> 但如果你的目标只是拿 `.class`，建议先用 `compile`，并跳过测试。

### 5.1 clone + checkout parent commit

```bash
cd "$RW_ROOT"
git clone https://github.com/vaadin/framework.git
cd framework
git checkout 53701564b197d1d30bd3dbc2f4e6a8d01b01b25a
```

### 5.2 build（优先最小编译）

```bash
use_jdk8
mvn -DskipTests -Dmaven.javadoc.skip=true compile
```

如果你后面确认 `compile` 不够，再尝试：

```bash
mvn -DskipTests -Dmaven.javadoc.skip=true install
```

### 5.3 主要输出位置

Maven 多模块项目，类文件通常分散在各模块：

```bash
find . -path '*/target/classes' -type d
```

### 5.4 如需切到 fixed commit 对照

```bash
git checkout 6b8f9779fbc8c81d1dff2ac139bd41535018aa78
mvn -DskipTests -Dmaven.javadoc.skip=true compile
```

### 5.5 常见报错与处理

#### 报错 1：`Source option 1.8 is no longer supported` 或 JDK 版本不兼容
**处理**：切到 JDK 8。

```bash
use_jdk8
```

#### 报错 2：测试相关依赖太重 / UI 测试拖慢
**处理**：先明确跳过测试：

```bash
mvn -DskipTests -Dmaven.javadoc.skip=true compile
```

#### 报错 3：`phantomjs-maven-plugin` / Jetty / GWT 相关插件失败
**原因**：这是 UI/前端链路历史依赖。  
**处理建议**：
1. 先坚持用 `compile`，不要直接 `install`；
2. 如果失败发生在测试或打包阶段，继续加跳过参数；
3. 如果连 `compile` 都失败，再记录具体模块名称，考虑只编译核心模块。

#### 报错 4：下载依赖慢或超时
**处理**：
- 重试一次；
- 配置 Maven 镜像；
- 确认 `~/.m2/settings.xml` 正常。

---

## 6. Stanford CoreNLP

> 这个项目相对友好：官方 README 同时提供了 **Ant** 和 **Maven** 两套构建方式。  
> 为了后续静态分析，推荐直接用 Maven `compile`，避免 `package` 阶段因为模型 jar 产生额外问题。

### 6.1 clone + checkout parent commit

```bash
cd "$RW_ROOT"
git clone https://github.com/stanfordnlp/CoreNLP.git
cd CoreNLP
git checkout 28a10fca03e8f6c0f6aaaa39fc7817d574fb014b
```

### 6.2 build（推荐 Maven）

```bash
use_jdk8
mvn -DskipTests compile
```

如果你更想用官方 README 里的 Ant 路径，也可以：

```bash
ant
```

但为了统一和稳定，我更建议你优先走 Maven。

### 6.3 主要输出目录

```bash
target/classes
```

### 6.4 如需切到 fixed commit 对照

```bash
git checkout 0a061469ec491ae4512d98233ca15e76caafe20b
mvn -DskipTests compile
```

### 6.5 常见报错与处理

#### 报错 1：`mvn package` 阶段找不到 models jar
**原因**：这个历史 `pom.xml` 在 `package` 阶段会尝试附加本地模型 jar。  
**处理**：如果你只是为了拿 class 文件，直接用：

```bash
mvn -DskipTests compile
```

不要先跑 `package`。

#### 报错 2：依赖下载失败
**处理**：重试；或配置 Maven 镜像。

#### 报错 3：Ant 路径下构建成功但缺运行模型
**说明**：这不影响你做静态分析。  
RepoAudit / Soot 只关心可编译 class，不要求你把 NLP 模型也准备齐。

---

## 7. 一个建议的实际执行顺序

为了尽快推进实验，建议按下面顺序做：

1. `apache/lucene`
2. `stanfordnlp/CoreNLP`
3. `vaadin/framework`
4. `triplea-game/triplea`
5. `unclebob/fitnesse`

原因：
- Lucene / CoreNLP 最容易先跑通；
- Vaadin 中等；
- TripleA 更容易被 JavaFX / 旧 Gradle 环境细节绊住；FitNesse 则相对轻量。

---

## 8. 如果你只想先验证“构建是否成功”

每个项目都可以用下面的最小检查方式：

### TripleA
```bash
find build/classes/java/main -type f | head
```

### Lucene
```bash
find lucene solr -type f | grep '\.class$' | head
```

### FitNesse
```bash
find build -type f | grep "\.class$" | head
```

### Vaadin
```bash
find . -path '*/target/classes/*.class' | head
```

### CoreNLP
```bash
find target/classes -type f | head
```

---

## 9. 给你一个统一的记录建议

每跑完一个项目，建议立刻记录：

- 使用的 JDK 版本
- 是否需要额外依赖
- 是否一次编译成功
- 失败报错的关键词
- 最终 class 输出路径

这样你后面写论文实验部分时，会非常省时间。

---

## 10. RepoAudit 实际运行命令清单

> 本节默认你已经按照前文完成了 **clone / checkout parent commit / build**。  
> 默认执行环境仍然是 **Ubuntu / WSL / Linux shell**。  
> 下面的命令分成两类：
>
> - **推荐稳定方案**：优先保证真实项目能顺利跑完 RepoAudit；
> - **Soot bridge 方案**：尽量让 Soot 吃到真实 `.class + classpath`，但对项目构建完整性要求更高。
>
> 另外请先确认：**你的 LLM API Key / Base URL / 模型配置已经按当前仓库配置好**，否则 RepoAudit 会在调用模型时失败。

### 10.1 统一准备

先进入 RepoAudit 运行目录，并设置一组统一环境变量：

```bash
export REPOAUDIT_DIR=~/Desktop/JLeakDetector
export RW_ROOT=~/Desktop/real_world_repos

cd "$REPOAUDIT_DIR/src"

export MODEL=deepseek-chat
export REPOAUDIT_LANGUAGE=Java
export ENABLE_SOOT_PREFILTER=true
export AUTO_GENERATE_SOOT_FACTS=true
export SOOT_TIMEOUT_SEC=600
export SOOT_TIMEOUT_MS=500
export REPOAUDIT_CALL_DEPTH=15
export REPOAUDIT_MAX_NEURAL_WORKERS=16
```

建议每切换一个项目前，先清一下上一个项目残留的 Soot 变量：

```bash
unset SOOT_CLASS_DIR
unset SOOT_CLASSPATH
unset SOOT_FACTS_PATH
unset SOOT_FACTS_MODE
unset SOOT_COMPILE_BEFORE
```

如果后面在 **bridge 模式** 下遇到 `OutOfMemoryError`，可先额外加：

```bash
export JAVA_TOOL_OPTIONS="-Xms1g -Xmx8g"
```

跑完后查看最新结果目录的通用命令：

```bash
ls -1dt ../result/dfbscan/$MODEL/MLK/Java/<项目目录名>/* | head -n 1
```

常见输出文件包括：

- `detect_info.json`
- `detect_info_by_file.json`
- `detect_info_raw.json`
- `detect_info_issue_stats.json`
- `transfer_info.json`

---

### 10.2 TripleA：推荐用 Soot bridge

> 这是 5 个项目里**最值得认真喂给 Soot** 的一个，但前提是你已经用 **JDK 8 + JavaFX** 成功构建过 `build/classes/java/main`。

#### 10.2.1 重新确认编译产物

```bash
use_jdk8fx
cd "$RW_ROOT/triplea"
./gradlew classes --no-daemon --stacktrace
```

#### 10.2.2 导出 TripleA 的 compile classpath

新建一个临时 `init.gradle`，让 Gradle 把 `sourceSets.main.compileClasspath` 打出来：

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

#### 10.2.3 运行 RepoAudit（bridge）

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

#### 10.2.4 查看结果

```bash
LATEST_RESULT=$(ls -1dt ../result/dfbscan/$MODEL/MLK/Java/triplea/* | head -n 1)
echo "$LATEST_RESULT"
ls "$LATEST_RESULT"
```

#### 10.2.5 常见失败处理

**情况 1：`printMainCompileClasspath` 执行失败**  
先确认前面的 `./gradlew classes` 已成功；若仍失败，可以临时降级为：

```bash
export SOOT_CLASSPATH="$SOOT_CLASS_DIR"
```

这能让 bridge 先跑起来，但第三方依赖更容易变成 phantom class。

**情况 2：bridge 生成 `soot_facts.json` 时 OOM**  
先加大 JVM 堆：

```bash
export JAVA_TOOL_OPTIONS="-Xms1g -Xmx8g"
```

如果还是不稳，再临时回退到：

```bash
unset SOOT_CLASS_DIR
unset SOOT_CLASSPATH
export SOOT_FACTS_MODE=ts-fallback
export SOOT_COMPILE_BEFORE=false
bash run_repoaudit.sh "$PROJECT_PATH" MLK
```

---

### 10.3 Apache Lucene：整仓推荐 ts-fallback

> Lucene 这个历史版本本质上是 **Lucene/Solr 多模块单仓**。  
> 如果你是“整仓扫描”，最稳的方式是先用 `ts-fallback`。  
> 如果你后面特别想让 Soot 更充分介入，建议按模块拆开跑，而不是直接对整个仓库强推 bridge。

#### 10.3.1 重新确认编译

```bash
use_jdk8
cd "$RW_ROOT/lucene"
ant ivy-bootstrap || true
ant compile
```

#### 10.3.2 运行 RepoAudit（推荐稳定方案）

```bash
cd "$REPOAUDIT_DIR/src"
use_jdk8

unset SOOT_CLASS_DIR
unset SOOT_CLASSPATH

export PROJECT_PATH="$RW_ROOT/lucene"
export SOOT_FACTS_PATH="$PROJECT_PATH/.repoaudit/soot_facts.json"
export SOOT_FACTS_MODE=ts-fallback
export SOOT_COMPILE_BEFORE=false

bash run_repoaudit.sh "$PROJECT_PATH" MLK
```

#### 10.3.3 查看结果

```bash
LATEST_RESULT=$(ls -1dt ../result/dfbscan/$MODEL/MLK/Java/lucene/* | head -n 1)
echo "$LATEST_RESULT"
ls "$LATEST_RESULT"
```

#### 10.3.4 如果你后面坚持让 Soot bridge 发挥更多作用

推荐思路不是“整仓一次吃掉”，而是：

1. 先选一个子模块，例如 `lucene/core`；
2. 单独确保这个模块的 class 输出目录和依赖 classpath；
3. 再把 `PROJECT_PATH` 改成该模块路径单独跑。

否则整仓 bridge 的 class 输出目录是分散的，`SOOT_CLASS_DIR` 很难一次性正确覆盖。

---

### 10.4 FitNesse：推荐用 Soot bridge

> FitNesse 是单仓 Gradle 项目，结构比多仓联动构建项目简单得多。  
> 如果你已经成功执行 `./gradlew classes`，那么它很适合直接走 **bridge**。

#### 10.4.1 重新确认编译

```bash
use_jdk8
cd "$RW_ROOT/fitnesse"
./gradlew classes --no-daemon --stacktrace
```

#### 10.4.2 生成 Soot facts（bridge）

推荐直接用 `real_world_test/generate_soot_fitnesse.sh`：

```bash
cd "$REPOAUDIT_DIR"
use_jdk8
bash real_world_test/generate_soot_fitnesse.sh "$RW_ROOT/fitnesse"
```

默认生成：

```bash
$RW_ROOT/fitnesse/.repoaudit/soot_facts.json
```

#### 10.4.3 运行 RepoAudit（bridge）

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

#### 10.4.4 查看结果

```bash
LATEST_RESULT=$(ls -1dt ../result/dfbscan/$MODEL/MLK/Java/fitnesse/* | head -n 1)
echo "$LATEST_RESULT"
ls "$LATEST_RESULT"
```

#### 10.4.5 常见失败处理

**情况 1：bridge 找不到 class 输出目录**  
先执行：

```bash
find build -type d \( -path '*/classes/java/main' -o -path '*/classes/main' -o -path '*/classes' \)
```

**情况 2：你只想先快速跑完整实验**  
可以临时退回：

```bash
unset SOOT_CLASS_DIR
unset SOOT_CLASSPATH
export SOOT_FACTS_MODE=ts-fallback
export SOOT_COMPILE_BEFORE=false
bash run_repoaudit.sh "$PROJECT_PATH" MLK
```

---

### 10.5 Vaadin Framework：推荐 ts-fallback

> Vaadin 是典型的 **Maven 多模块** 项目。  
> 仓库根目录下有大量 `target/classes`，而 `run_repoaudit.sh` 当前只支持单个 `SOOT_CLASS_DIR`。  
> 所以对整个仓库的实际实验，建议优先选择 `ts-fallback`。

#### 10.5.1 重新确认编译

```bash
use_jdk8
cd "$RW_ROOT/framework"
mvn -DskipTests -Dmaven.javadoc.skip=true compile
```

#### 10.5.2 运行 RepoAudit（推荐稳定方案）

```bash
cd "$REPOAUDIT_DIR/src"
use_jdk8

unset SOOT_CLASS_DIR
unset SOOT_CLASSPATH

export PROJECT_PATH="$RW_ROOT/framework"
export SOOT_FACTS_PATH="$PROJECT_PATH/.repoaudit/soot_facts.json"
export SOOT_FACTS_MODE=ts-fallback
export SOOT_COMPILE_BEFORE=false

bash run_repoaudit.sh "$PROJECT_PATH" MLK
```

#### 10.5.3 查看结果

```bash
LATEST_RESULT=$(ls -1dt ../result/dfbscan/$MODEL/MLK/Java/framework/* | head -n 1)
echo "$LATEST_RESULT"
ls "$LATEST_RESULT"
```

#### 10.5.4 如果后面你想深入做单模块 bridge

推荐做法：

1. 先定位真正包含 bug 的 Maven 模块；
2. 只对该模块目录运行 RepoAudit；
3. 使用：

```bash
mvn -q -DskipTests dependency:build-classpath -Dmdep.outputFile=/tmp/vaadin_module.cp
```

配合该模块自己的 `target/classes` 去构造 `SOOT_CLASS_DIR` 和 `SOOT_CLASSPATH`。

---

### 10.6 Stanford CoreNLP：推荐用 Soot bridge

> CoreNLP 是这 5 个项目里另一个很适合走 **bridge** 的项目：  
> Maven 单仓主干清晰，`target/classes` 也比较直接。

#### 10.6.1 重新确认编译

```bash
use_jdk8
cd "$RW_ROOT/CoreNLP"
mvn -DskipTests compile
```

#### 10.6.2 导出 Maven 依赖 classpath

```bash
cd "$RW_ROOT/CoreNLP"
mvn -q -DskipTests dependency:build-classpath -Dmdep.outputFile=/tmp/corenlp.cp
cat /tmp/corenlp.cp
```

#### 10.6.3 运行 RepoAudit（bridge）

```bash
cd "$REPOAUDIT_DIR/src"
use_jdk8

export PROJECT_PATH="$RW_ROOT/CoreNLP"
export SOOT_CLASS_DIR="$PROJECT_PATH/target/classes"
export SOOT_CLASSPATH="$(tr -d '\r' </tmp/corenlp.cp):$SOOT_CLASS_DIR"
export SOOT_FACTS_PATH="$PROJECT_PATH/.repoaudit/soot_facts.json"
export SOOT_FACTS_MODE=bridge
export SOOT_COMPILE_BEFORE=false

bash run_repoaudit.sh "$PROJECT_PATH" MLK
```

#### 10.6.4 查看结果

```bash
LATEST_RESULT=$(ls -1dt ../result/dfbscan/$MODEL/MLK/Java/CoreNLP/* | head -n 1)
echo "$LATEST_RESULT"
ls "$LATEST_RESULT"
```

#### 10.6.5 常见失败处理

**情况 1：`dependency:build-classpath` 失败**  
通常是 Maven 网络问题，先重试一次；再不行就先切镜像。

**情况 2：bridge OOM**  
与 TripleA 一样，先加：

```bash
export JAVA_TOOL_OPTIONS="-Xms1g -Xmx8g"
```

**情况 3：只想先快速跑完整实验，不想卡在 bridge 上**  
直接临时改成：

```bash
unset SOOT_CLASS_DIR
unset SOOT_CLASSPATH
export SOOT_FACTS_MODE=ts-fallback
export SOOT_COMPILE_BEFORE=false
bash run_repoaudit.sh "$PROJECT_PATH" MLK
```

---

### 10.7 fixed commit 的跑法

如果你想对照 `fixed commit`，流程完全一样，只需要先在项目目录切换到 fixed commit：

```bash
git checkout <fixed_commit_hash>
```

然后：

1. 重新 build；
2. 重新生成 classpath（如果你走的是 bridge）；
3. 重新执行同一套 `bash run_repoaudit.sh ... MLK`。

为了避免结果混淆，建议每次切 commit 后都删除旧的：

```bash
rm -rf .repoaudit
```

并单独记录当前 commit hash：

```bash
git rev-parse HEAD
```

---

### 10.8 我建议你的实际实验策略

如果你接下来要正式做论文实验，我建议按下面策略推进：

1. **TripleA**：优先用 `bridge`
2. **CoreNLP**：优先用 `bridge`
3. **Lucene**：先用 `ts-fallback` 跑整仓
4. **FitNesse**：优先用 `bridge`
5. **Vaadin**：先用 `ts-fallback` 跑整仓

这样做的好处是：

- 你能先得到 **5 个真实项目都可复现的完整结果**；
- 同时还能保留 **至少 2 个项目的强 Soot 参与版本**；
- 后面如果你要做 RQ4（模块消融），再去挑 TripleA / CoreNLP 深挖 bridge 与非 bridge 差异，会更高效。

---

## 11. 多模块项目的 soot bridge 脚本使用说明

> 这一节对应 `real_world_test` 目录下我新加的 4 个脚本：
>
> - `merge_soot_facts.py`
> - `generate_merge_soot_lucene.sh`
> - `generate_soot_fitnesse.sh`
> - `generate_merge_soot_vaadin.sh`
>
> 适用场景：你希望 **Lucene / FitNesse / Vaadin** 这 3 个多模块项目也能真正使用 **soot bridge**，而不是退回 `ts-fallback`。

### 11.1 为什么需要这组脚本

Lucene / Vaadin 的共同问题是：

- **不是单模块**
- `.class` 输出目录不止一个
- `run_repoaudit.sh` 当前只接受一个 `SOOT_CLASS_DIR`
- `BridgeMain` 当前一次也只处理一个 `--input-dir`

FitNesse 则不同：

- 它是单仓单模块 Gradle 项目
- 只需要自动找到主 class 输出目录，然后直接运行 bridge

所以这组脚本的工作流分成两类：

1. **Lucene / Vaadin**：逐模块生成 module-level soot facts，再合并
2. **FitNesse**：直接 bridge，生成单文件 facts

也就是说，这组脚本的工作流是：

```text
build project
    ↓
find every module class dir
    ↓
run soot bridge
    ↓
run RepoAudit with AUTO_GENERATE_SOOT_FACTS=false
```

---

### 11.2 通用前置条件

先确保以下条件满足：

#### 11.2.1 已完成项目构建

- Lucene：`ant compile`
- FitNesse：`./gradlew classes`
- Vaadin：`mvn -DskipTests -Dmaven.javadoc.skip=true compile`

#### 11.2.2 soot bridge jar 已存在

默认脚本会找：

```bash
$REPOAUDIT_DIR/tools/soot_bridge/target/soot-bridge-all.jar
```

你可以先检查：

```bash
ls ~/Desktop/JLeakDetector/tools/soot_bridge/target/soot-bridge-all.jar
```

#### 11.2.3 Python / Java / Maven 或 Ant 可用

建议先确认：

```bash
python3 --version
java -version
javac -version
```

Vaadin 还要额外确认：

```bash
mvn -version
```

---

### 11.3 通用输出说明

每个项目脚本执行后，通常会生成：

#### 模块级 facts

位于：

```bash
<project>/.repoaudit/<xxx>_bridge/modules/*.json
```

#### 合并后的 facts

位于：

```bash
<project>/.repoaudit/soot_facts_merged.json
```

#### 额外辅助文件

- `module_manifest.tsv`：记录每个模块的 class 目录、输出 json 路径
- `failed_modules.log`：记录 bridge 失败的模块

这两个文件很有用，后面写论文实验记录时建议保留。

---

### 11.4 Lucene 脚本：`generate_merge_soot_lucene.sh`

#### 11.4.1 用途

针对 **apache/lucene 历史 Lucene/Solr 单仓多模块结构**：

- 自动搜索多个 `build/.../classes`
- 收集仓库内部 `.jar`
- 逐模块运行 bridge
- 合并为一个 `soot_facts_merged.json`

#### 11.4.2 前置步骤

先构建：

```bash
use_jdk8
cd "$RW_ROOT/lucene"
ant ivy-bootstrap || true
ant compile
```

#### 11.4.3 执行方式

```bash
cd ~/Desktop/JLeakDetector
bash real_world_test/generate_merge_soot_lucene.sh ~/Desktop/real_world_repos/lucene
```

#### 11.4.4 常用可选参数

如果你想限制只跑某一部分模块，可以用：

```bash
MODULE_FILTER=lucene/core bash real_world_test/generate_merge_soot_lucene.sh ~/Desktop/real_world_repos/lucene
```

如果你想限制 bridge 每次分析的方法数，用来防止个别模块过重：

```bash
BRIDGE_MAX_METHODS=3000 bash real_world_test/generate_merge_soot_lucene.sh ~/Desktop/real_world_repos/lucene
```

如果你想调大堆内存：

```bash
HEAP_OPTS="-Xms1g -Xmx8g" bash real_world_test/generate_merge_soot_lucene.sh ~/Desktop/real_world_repos/lucene
```

#### 11.4.5 结果位置

```bash
~/Desktop/real_world_repos/lucene/.repoaudit/soot_facts_merged.json
```

#### 11.4.6 后续跑 RepoAudit

```bash
cd ~/Desktop/JLeakDetector/src

export ENABLE_SOOT_PREFILTER=true
export AUTO_GENERATE_SOOT_FACTS=false
export SOOT_FACTS_PATH=~/Desktop/real_world_repos/lucene/.repoaudit/soot_facts_merged.json

bash run_repoaudit.sh ~/Desktop/real_world_repos/lucene MLK
```

---

### 11.5 FitNesse 脚本：`generate_soot_fitnesse.sh`

#### 11.5.1 用途

针对 **unclebob/fitnesse 单仓 Gradle 结构**：

- 自动识别 `build/classes/java/main` 或 `build/classes/main`
- 直接用 bridge 生成单文件 `soot_facts.json`
- 不需要做 merge

#### 11.5.2 前置要求

先完成编译：

```bash
cd "$RW_ROOT/fitnesse"
./gradlew classes --no-daemon --stacktrace
```

#### 11.5.3 执行方式

```bash
bash real_world_test/generate_soot_fitnesse.sh ~/Desktop/real_world_repos/fitnesse
```

#### 11.5.4 常用可选参数

如果你有额外 classpath：

```bash
EXTRA_CLASSPATH=/path/to/extra/classpath \
  bash real_world_test/generate_soot_fitnesse.sh ~/Desktop/real_world_repos/fitnesse
```

如果你想换输出路径：

```bash
SOOT_OUTPUT=~/Desktop/real_world_repos/fitnesse/.repoaudit/fitnesse_soot.json \
  bash real_world_test/generate_soot_fitnesse.sh ~/Desktop/real_world_repos/fitnesse
```

#### 11.5.5 结果位置

```bash
~/Desktop/real_world_repos/fitnesse/.repoaudit/soot_facts.json
```

#### 11.5.6 后续跑 RepoAudit

```bash
export SOOT_FACTS_PATH=~/Desktop/real_world_repos/fitnesse/.repoaudit/soot_facts.json
export AUTO_GENERATE_SOOT_FACTS=false
bash run_repoaudit.sh ~/Desktop/real_world_repos/fitnesse MLK
```

---

### 11.6 Vaadin 脚本：`generate_merge_soot_vaadin.sh`

#### 11.6.1 用途

针对 **Maven 多模块项目 vaadin/framework**：

- 自动搜索所有模块的 `target/classes`
- 为每个模块单独执行 `mvn dependency:build-classpath`
- 把“模块依赖 classpath + 仓库内 class 目录”一起喂给 bridge
- 合并为一个 merged facts

#### 11.6.2 前置步骤

先构建：

```bash
use_jdk8
cd "$RW_ROOT/framework"
mvn -DskipTests -Dmaven.javadoc.skip=true compile
```

#### 11.6.3 执行方式

```bash
cd ~/Desktop/JLeakDetector
bash real_world_test/generate_merge_soot_vaadin.sh ~/Desktop/real_world_repos/framework
```

#### 11.6.4 常用可选参数

只跑某个模块：

```bash
MODULE_FILTER=server bash real_world_test/generate_merge_soot_vaadin.sh ~/Desktop/real_world_repos/framework
```

调大堆：

```bash
HEAP_OPTS="-Xms1g -Xmx8g" bash real_world_test/generate_merge_soot_vaadin.sh ~/Desktop/real_world_repos/framework
```

指定 Maven 命令：

```bash
MAVEN_BIN=/path/to/mvn bash real_world_test/generate_merge_soot_vaadin.sh ~/Desktop/real_world_repos/framework
```

#### 11.6.5 结果位置

```bash
~/Desktop/real_world_repos/framework/.repoaudit/soot_facts_merged.json
```

#### 11.6.6 后续跑 RepoAudit

```bash
cd ~/Desktop/JLeakDetector/src

export ENABLE_SOOT_PREFILTER=true
export AUTO_GENERATE_SOOT_FACTS=false
export SOOT_FACTS_PATH=~/Desktop/real_world_repos/framework/.repoaudit/soot_facts_merged.json

bash run_repoaudit.sh ~/Desktop/real_world_repos/framework MLK
```

---

### 11.7 通用合并脚本：`merge_soot_facts.py`

通常你不需要手工单独运行它，因为上面 3 个 `.sh` 脚本最后都会自动调用它。

但如果你后面自己又额外生成了几个模块 facts，也可以手动合并：

```bash
python3 real_world_test/merge_soot_facts.py \
  --output /tmp/merged_soot_facts.json \
  /tmp/module_a.json \
  /tmp/module_b.json \
  /tmp/module_c.json
```

如果你希望重复的 `function_uid` 采用“后者覆盖前者”，可以加：

```bash
python3 real_world_test/merge_soot_facts.py \
  --prefer-last \
  --output /tmp/merged_soot_facts.json \
  /tmp/module_a.json \
  /tmp/module_b.json
```

---

### 11.8 建议的实际执行顺序

如果你现在要推进真实项目实验，我建议这样做：

1. 先分别构建好 Lucene / FitNesse / Vaadin
2. 分别运行 3 个 bridge 脚本，先拿到 `soot_facts_merged.json`
3. 对每个项目执行：

```bash
export ENABLE_SOOT_PREFILTER=true
export AUTO_GENERATE_SOOT_FACTS=false
export SOOT_FACTS_PATH=<merged_soot_facts.json>
bash run_repoaudit.sh <project_path> MLK
```

4. 最后保存：
   - `soot_facts_merged.json`
   - `module_manifest.tsv`
   - `failed_modules.log`
   - RepoAudit 结果目录

这样你后面无论写 RQ1、RQ3 还是 RQ4，都会更容易复现实验。

