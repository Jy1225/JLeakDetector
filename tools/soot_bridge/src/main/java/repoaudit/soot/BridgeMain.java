package repoaudit.soot;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import soot.Body;
import soot.G;
import soot.Local;
import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.AssignStmt;
import soot.jimple.ArrayRef;
import soot.jimple.BinopExpr;
import soot.jimple.CastExpr;
import soot.jimple.ConditionExpr;
import soot.jimple.DoubleConstant;
import soot.jimple.FieldRef;
import soot.jimple.FloatConstant;
import soot.jimple.IdentityStmt;
import soot.jimple.IfStmt;
import soot.jimple.IntConstant;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.LongConstant;
import soot.jimple.NewExpr;
import soot.jimple.NullConstant;
import soot.jimple.ReturnStmt;
import soot.jimple.Stmt;
import soot.jimple.ThrowStmt;
import soot.options.Options;
import soot.tagkit.LineNumberTag;
import soot.tagkit.SourceFileTag;
import soot.tagkit.SourceLnPosTag;
import soot.tagkit.Tag;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.BriefBlockGraph;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.ExceptionalUnitGraph;

import java.util.ArrayDeque;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class BridgeMain {
    private static final Object NULL_CONST_MARKER = new Object();
    private static final Set<String> CLOSE_METHOD_NAMES = buildCloseMethodNames();
    private static final Set<String> FACTORY_METHOD_NAMES = buildFactoryMethodNames();
    private static final Set<String> TEMP_RESOURCE_FACTORY_METHOD_NAMES = buildTempResourceFactoryMethodNames();
    private static final Set<String> ACQUIRE_METHOD_NAMES = buildAcquireMethodNames();
    private static final Set<String> RESOURCE_TYPE_WHITELIST = buildResourceTypeWhitelist();
    private static final String[] RESOURCE_SUFFIXES = new String[]{
            "Stream",
            "Reader",
            "Writer",
            "Channel",
            "Socket",
            "Connection",
            "Statement",
            "ResultSet",
            "Session",
            "FileSystem",
            "Lock",
            "Semaphore",
            "Selector",
            "Executor",
            "ThreadPool"
    };

    private BridgeMain() {
    }

    private static final class SourceSite {
        private final int line;
        private final Unit unit;
        private final Local local;

        private SourceSite(int line, Unit unit, Local local) {
            this.line = line;
            this.unit = unit;
            this.local = local;
        }
    }

    private static final class OpenState {
        private boolean created;
        private boolean mayOpen;
        private boolean escaped;
        private int escapeSiteLine = -1;
        private final Set<Local> aliases = new HashSet<Local>();

        private OpenState copy() {
            OpenState copied = new OpenState();
            copied.created = this.created;
            copied.mayOpen = this.mayOpen;
            copied.escaped = this.escaped;
            copied.escapeSiteLine = this.escapeSiteLine;
            copied.aliases.addAll(this.aliases);
            return copied;
        }

        private boolean sameAs(OpenState other) {
            if (other == null) {
                return false;
            }
            return this.created == other.created
                    && this.mayOpen == other.mayOpen
                    && this.escaped == other.escaped
                    && this.escapeSiteLine == other.escapeSiteLine
                    && this.aliases.equals(other.aliases);
        }
    }

    private static final class SourceGuaranteeResult {
        private final boolean guaranteed;
        private final String reason;
        private final String proofKind;
        private final int firstOpenExitLine;
        private final int escapeSiteLine;
        private final int aliasCountOnFailure;
        private final int closeWitnessCount;

        private SourceGuaranteeResult(
                boolean guaranteed,
                String reason,
                String proofKind,
                int firstOpenExitLine,
                int escapeSiteLine,
                int aliasCountOnFailure,
                int closeWitnessCount
        ) {
            this.guaranteed = guaranteed;
            this.reason = reason;
            this.proofKind = proofKind;
            this.firstOpenExitLine = firstOpenExitLine;
            this.escapeSiteLine = escapeSiteLine;
            this.aliasCountOnFailure = aliasCountOnFailure;
            this.closeWitnessCount = closeWitnessCount;
        }
    }

    private static final class MustCloseFacts {
        private final List<Integer> mustCloseSourceLines = new ArrayList<Integer>();
        private final Map<String, Boolean> sourceCloseGuarantee = new LinkedHashMap<String, Boolean>();
        private final Map<String, String> mustCloseReason = new LinkedHashMap<String, String>();
        private final Map<String, String> sourceProofKind = new LinkedHashMap<String, String>();
        private final Map<String, Integer> firstOpenExitLine = new LinkedHashMap<String, Integer>();
        private final Map<String, Integer> escapeSiteLine = new LinkedHashMap<String, Integer>();
        private final Map<String, Integer> aliasCountOnFailure = new LinkedHashMap<String, Integer>();
        private final Map<String, Integer> closeWitnessCount = new LinkedHashMap<String, Integer>();
        private boolean allSourcesHardClosed;
        private String methodProofKind = "none";
    }

    private static final class BranchReachability {
        private boolean trueFeasible;
        private boolean falseFeasible;
        private boolean trueConflict;
        private boolean falseConflict;
    }

    private static final class ParsedComparison {
        private final String localName;
        private final double constant;
        private final String operator;

        private ParsedComparison(String localName, double constant, String operator) {
            this.localName = localName;
            this.constant = constant;
            this.operator = operator;
        }
    }

    private static final class RangeConstraint {
        private Double lower;
        private boolean lowerInclusive;
        private Double upper;
        private boolean upperInclusive;
        private final Set<Double> notEquals = new HashSet<Double>();

        private RangeConstraint copy() {
            RangeConstraint copied = new RangeConstraint();
            copied.lower = this.lower;
            copied.lowerInclusive = this.lowerInclusive;
            copied.upper = this.upper;
            copied.upperInclusive = this.upperInclusive;
            copied.notEquals.addAll(this.notEquals);
            return copied;
        }
    }

    private static final class ConstraintState {
        private final Map<String, RangeConstraint> rangesByLocal = new HashMap<String, RangeConstraint>();

        private ConstraintState copy() {
            ConstraintState copied = new ConstraintState();
            for (Map.Entry<String, RangeConstraint> entry : this.rangesByLocal.entrySet()) {
                copied.rangesByLocal.put(entry.getKey(), entry.getValue().copy());
            }
            return copied;
        }

        private String fingerprint() {
            List<String> keys = new ArrayList<String>(this.rangesByLocal.keySet());
            Collections.sort(keys);
            StringBuilder builder = new StringBuilder();
            for (String key : keys) {
                RangeConstraint range = this.rangesByLocal.get(key);
                if (range == null) {
                    continue;
                }
                builder.append(key).append(":");
                builder.append(range.lower == null ? "-inf" : range.lower.toString());
                builder.append(range.lowerInclusive ? "[" : "(");
                builder.append(",");
                builder.append(range.upper == null ? "+inf" : range.upper.toString());
                builder.append(range.upperInclusive ? "]" : ")");
                if (!range.notEquals.isEmpty()) {
                    List<Double> neqValues = new ArrayList<Double>(range.notEquals);
                    Collections.sort(neqValues);
                    builder.append("!=").append(neqValues.toString());
                }
                builder.append(";");
            }
            return builder.toString();
        }
    }

    private static final class BranchWorkItem {
        private final Unit unit;
        private final ConstraintState state;

        private BranchWorkItem(Unit unit, ConstraintState state) {
            this.unit = unit;
            this.state = state;
        }
    }

    public static void main(String[] args) throws Exception {
        Config config = Config.fromArgs(args);
        if (config.inputDir.isEmpty() || config.outputPath.isEmpty()) {
            throw new IllegalArgumentException("--input-dir and --output are required");
        }
        run(config);
    }

    private static void run(Config config) throws IOException {
        initSoot(config);

        Map<String, Object> methods = new LinkedHashMap<String, Object>();
        int methodCount = 0;
        for (SootClass sootClass : Scene.v().getApplicationClasses()) {
            for (SootMethod sootMethod : sootClass.getMethods()) {
                if (!sootMethod.isConcrete()) {
                    continue;
                }
                if (methodCount >= config.maxMethods) {
                    break;
                }

                Body body;
                try {
                    body = sootMethod.retrieveActiveBody();
                } catch (Exception err) {
                    continue;
                }
                String functionUid = buildFunctionUid(sootClass, sootMethod);
                methods.put(functionUid, buildMethodFacts(sootClass, sootMethod, body, functionUid));
                methodCount += 1;
            }
        }

        Map<String, Object> root = new LinkedHashMap<String, Object>();
        root.put("generator", "soot-bridge");
        root.put("generated_at", System.currentTimeMillis());
        root.put("line_mode", "absolute");
        root.put("methods", methods);

        File outputFile = new File(config.outputPath);
        File parent = outputFile.getParentFile();
        if (parent != null && !parent.exists()) {
            if (!parent.mkdirs() && !parent.exists()) {
                throw new IOException("failed to create output directory: " + parent);
            }
        }

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        FileWriter writer = new FileWriter(outputFile);
        try {
            gson.toJson(root, writer);
        } finally {
            writer.close();
        }
    }

    private static void initSoot(Config config) {
        G.reset();
        Options.v().set_prepend_classpath(true);
        Options.v().set_soot_classpath(config.classpath);
        Options.v().set_allow_phantom_refs(config.allowPhantomRefs);
        Options.v().set_whole_program(config.wholeProgram);
        Options.v().set_keep_line_number(config.keepLineNumber);
        Options.v().set_output_format(Options.output_format_none);
        Options.v().set_src_prec(Options.src_prec_only_class);
        Options.v().set_process_dir(Collections.singletonList(config.inputDir));
        Options.v().setPhaseOption("jb", "use-original-names:true");
        if ("spark".equals(config.callGraphEngine)) {
            Options.v().setPhaseOption("cg.spark", "enabled:true");
        } else if ("cha".equals(config.callGraphEngine)) {
            Options.v().setPhaseOption("cg.cha", "enabled:true");
        }
        Scene.v().loadNecessaryClasses();
        PackManager.v().runPacks();
    }

    private static Map<String, Object> buildMethodFacts(
            SootClass sootClass,
            SootMethod sootMethod,
            Body body,
            String functionUid
    ) {
        List<SourceSite> sourceSites = collectSourceSites(body);
        MustCloseFacts mustCloseFacts = collectMustCloseFacts(body, sourceSites);

        Map<String, Object> facts = new LinkedHashMap<String, Object>();
        facts.put("function_uid", functionUid);
        facts.put("file", inferSourceFile(sootClass));
        facts.put("class_name", normalizeOwnerClass(sootClass.getName()));
        facts.put("method_name", sootMethod.getName());
        facts.put("param_types", normalizeParamTypes(sootMethod.getParameterTypes()));
        facts.put("if_nodes", collectIfNodes(body));
        facts.put("close_sites", collectCloseSites(body));
        facts.put("source_lines", collectSourceLines(sourceSites));
        facts.put("must_close_source_lines", mustCloseFacts.mustCloseSourceLines);
        facts.put("source_close_guarantee", mustCloseFacts.sourceCloseGuarantee);
        facts.put("must_close_reason", mustCloseFacts.mustCloseReason);
        facts.put("source_proof_kind", mustCloseFacts.sourceProofKind);
        facts.put("first_open_exit_line", mustCloseFacts.firstOpenExitLine);
        facts.put("escape_site_line", mustCloseFacts.escapeSiteLine);
        facts.put("alias_count_on_failure", mustCloseFacts.aliasCountOnFailure);
        facts.put("close_witness_count", mustCloseFacts.closeWitnessCount);
        facts.put("all_sources_hard_closed", Boolean.valueOf(mustCloseFacts.allSourcesHardClosed));
        facts.put("method_proof_kind", mustCloseFacts.methodProofKind);
        facts.put("generator", "soot-bridge");
        return facts;
    }

    private static List<Map<String, Object>> collectIfNodes(Body body) {
        List<Map<String, Object>> ifNodes = new ArrayList<Map<String, Object>>();
        Map<Unit, Map<Local, Object>> constantInStates = computeConstantInStates(body);
        IdentityHashMap<IfStmt, BranchReachability> branchReachability = analyzeBranchReachability(body);
        BriefBlockGraph blockGraph = new BriefBlockGraph(body);
        IdentityHashMap<Unit, Block> unitToBlock = new IdentityHashMap<Unit, Block>();
        IdentityHashMap<Block, int[]> blockScope = new IdentityHashMap<Block, int[]>();

        for (Block block : blockGraph.getBlocks()) {
            int[] scope = computeBlockScope(block);
            blockScope.put(block, scope);
            for (Unit unit : block) {
                unitToBlock.put(unit, block);
            }
        }

        for (Unit unit : body.getUnits()) {
            if (!(unit instanceof IfStmt)) {
                continue;
            }
            IfStmt ifStmt = (IfStmt) unit;
            int line = getUnitLine(unit);
            int[] trueScope = new int[]{0, 0};
            int[] falseScope = new int[]{0, 0};

            Block trueBlock = unitToBlock.get(ifStmt.getTarget());
            if (trueBlock != null && blockScope.containsKey(trueBlock)) {
                trueScope = blockScope.get(trueBlock);
            }
            Unit fallthrough = body.getUnits().getSuccOf(unit);
            if (fallthrough != null) {
                Block falseBlock = unitToBlock.get(fallthrough);
                if (falseBlock != null && blockScope.containsKey(falseBlock)) {
                    falseScope = blockScope.get(falseBlock);
                }
            }

            Map<Local, Object> localConstants = constantInStates.get(unit);
            Boolean constantCond = evaluateConstantCondition(ifStmt.getCondition(), localConstants);
            BranchReachability branchSummary = branchReachability.get(ifStmt);

            boolean trueUnreachableByConst = constantCond != null && !constantCond.booleanValue();
            boolean falseUnreachableByConst = constantCond != null && constantCond.booleanValue();
            boolean trueUnreachableByPath = branchSummary != null
                    && !branchSummary.trueFeasible
                    && branchSummary.trueConflict;
            boolean falseUnreachableByPath = branchSummary != null
                    && !branchSummary.falseFeasible
                    && branchSummary.falseConflict;

            boolean trueUnreachable = trueUnreachableByConst || trueUnreachableByPath;
            boolean falseUnreachable = falseUnreachableByConst || falseUnreachableByPath;
            String trueReason = buildUnreachableReason(trueUnreachableByConst, trueUnreachableByPath);
            String falseReason = buildUnreachableReason(falseUnreachableByConst, falseUnreachableByPath);

            Map<String, Object> node = new LinkedHashMap<String, Object>();
            node.put("line", line);
            node.put("condition", ifStmt.getCondition().toString());
            node.put("true_scope", toList(trueScope));
            node.put("false_scope", toList(falseScope));
            node.put("true_unreachable", Boolean.valueOf(trueUnreachable));
            node.put("false_unreachable", Boolean.valueOf(falseUnreachable));
            node.put("true_unreachable_reason", trueReason);
            node.put("false_unreachable_reason", falseReason);
            node.put("unreachable_reason", combineUnreachableReasons(trueReason, falseReason));
            node.put("proof_kind", (trueUnreachable || falseUnreachable) ? "hard" : "none");
            ifNodes.add(node);
        }

        Collections.sort(ifNodes, new Comparator<Map<String, Object>>() {
            @Override
            public int compare(Map<String, Object> left, Map<String, Object> right) {
                Integer l = (Integer) left.get("line");
                Integer r = (Integer) right.get("line");
                return l.compareTo(r);
            }
        });
        return ifNodes;
    }

    private static List<Map<String, Object>> collectCloseSites(Body body) {
        List<Map<String, Object>> closeSites = new ArrayList<Map<String, Object>>();
        for (Unit unit : body.getUnits()) {
            InvokeExpr invokeExpr = extractInvokeExpr(unit);
            if (invokeExpr == null) {
                continue;
            }
            String callee = invokeExpr.getMethod().getName().toLowerCase(Locale.ROOT);
            if (!CLOSE_METHOD_NAMES.contains(callee)) {
                continue;
            }
            int line = getUnitLine(unit);
            if (line <= 0) {
                continue;
            }
            Map<String, Object> site = new LinkedHashMap<String, Object>();
            site.put("line", line);
            site.put("invoke", invokeExpr.getMethodRef().getSignature());
            closeSites.add(site);
        }
        Collections.sort(closeSites, new Comparator<Map<String, Object>>() {
            @Override
            public int compare(Map<String, Object> left, Map<String, Object> right) {
                Integer l = (Integer) left.get("line");
                Integer r = (Integer) right.get("line");
                return l.compareTo(r);
            }
        });
        return closeSites;
    }

    private static List<SourceSite> collectSourceSites(Body body) {
        List<SourceSite> sites = new ArrayList<SourceSite>();
        Set<String> seen = new HashSet<String>();
        for (Unit unit : body.getUnits()) {
            int line = getUnitLine(unit);
            if (line <= 0) {
                continue;
            }

            if (unit instanceof AssignStmt) {
                AssignStmt assignStmt = (AssignStmt) unit;
                Value rightOp = assignStmt.getRightOp();
                Local leftLocal = toLocal(assignStmt.getLeftOp());

                if (rightOp instanceof NewExpr) {
                    String typeName = normalizeType(((NewExpr) rightOp).getBaseType().toString());
                    if (isResourceType(typeName)) {
                        if (addSourceSite(sites, seen, line, unit, leftLocal)) {
                            continue;
                        }
                    }
                }

                if (rightOp instanceof InvokeExpr) {
                    if (isFactoryResourceInvoke((InvokeExpr) rightOp)) {
                        addSourceSite(sites, seen, line, unit, leftLocal);
                    }
                }
                continue;
            }

            InvokeExpr invokeExpr = extractInvokeExpr(unit);
            if (invokeExpr == null) {
                continue;
            }
            if (isFactoryResourceInvoke(invokeExpr)) {
                addSourceSite(sites, seen, line, unit, null);
                continue;
            }
            if (isAcquireResourceInvoke(invokeExpr)) {
                Local sourceAlias = null;
                if (invokeExpr instanceof InstanceInvokeExpr) {
                    sourceAlias = toLocal(((InstanceInvokeExpr) invokeExpr).getBase());
                }
                addSourceSite(sites, seen, line, unit, sourceAlias);
            }
        }
        return sites;
    }

    private static List<Integer> collectSourceLines(List<SourceSite> sourceSites) {
        Set<Integer> lines = new HashSet<Integer>();
        for (SourceSite sourceSite : sourceSites) {
            if (sourceSite.line <= 0) {
                continue;
            }
            lines.add(Integer.valueOf(sourceSite.line));
        }

        List<Integer> result = new ArrayList<Integer>(lines);
        Collections.sort(result);
        return result;
    }

    private static MustCloseFacts collectMustCloseFacts(
            Body body,
            List<SourceSite> sourceSites
    ) {
        MustCloseFacts facts = new MustCloseFacts();
        Set<Integer> guaranteedLines = new HashSet<Integer>();
        ExceptionalUnitGraph graph = new ExceptionalUnitGraph(body);
        int analyzedSourceCount = 0;
        boolean allHardGuaranteed = true;

        for (SourceSite sourceSite : sourceSites) {
            if (sourceSite.line <= 0) {
                continue;
            }
            analyzedSourceCount += 1;
            String lineKey = Integer.toString(sourceSite.line);
            SourceGuaranteeResult result;
            if (sourceSite.local == null) {
                result = new SourceGuaranteeResult(
                        false,
                        "source_has_no_local_alias",
                        "none",
                        -1,
                        -1,
                        0,
                        0
                );
            } else {
                result = analyzeSourceGuarantee(graph, sourceSite);
            }

            facts.sourceCloseGuarantee.put(lineKey, Boolean.valueOf(result.guaranteed));
            facts.mustCloseReason.put(lineKey, result.reason);
            facts.sourceProofKind.put(lineKey, result.proofKind);
            facts.firstOpenExitLine.put(lineKey, Integer.valueOf(result.firstOpenExitLine));
            facts.escapeSiteLine.put(lineKey, Integer.valueOf(result.escapeSiteLine));
            facts.aliasCountOnFailure.put(lineKey, Integer.valueOf(result.aliasCountOnFailure));
            facts.closeWitnessCount.put(lineKey, Integer.valueOf(result.closeWitnessCount));
            if (result.guaranteed) {
                guaranteedLines.add(Integer.valueOf(sourceSite.line));
            }
            if (!result.guaranteed || !"hard".equalsIgnoreCase(result.proofKind)) {
                allHardGuaranteed = false;
            }
        }

        facts.mustCloseSourceLines.addAll(guaranteedLines);
        Collections.sort(facts.mustCloseSourceLines);
        facts.allSourcesHardClosed = analyzedSourceCount > 0 && allHardGuaranteed;
        facts.methodProofKind = facts.allSourcesHardClosed ? "hard" : "none";
        return facts;
    }

    private static SourceGuaranteeResult analyzeSourceGuarantee(
            ExceptionalUnitGraph graph,
            SourceSite sourceSite
    ) {
        IdentityHashMap<Unit, OpenState> outStates = new IdentityHashMap<Unit, OpenState>();
        Deque<Unit> worklist = new ArrayDeque<Unit>();
        Set<Unit> inQueue = new HashSet<Unit>();

        for (Unit unit : graph.getBody().getUnits()) {
            worklist.addLast(unit);
            inQueue.add(unit);
            outStates.put(unit, new OpenState());
        }

        while (!worklist.isEmpty()) {
            Unit unit = worklist.removeFirst();
            inQueue.remove(unit);

            OpenState inState = mergeOpenState(graph, outStates, unit, sourceSite);
            OpenState newOutState = transferOpenState(unit, inState, sourceSite);
            OpenState oldOutState = outStates.get(unit);
            if (oldOutState != null && oldOutState.sameAs(newOutState)) {
                continue;
            }
            outStates.put(unit, newOutState);
            for (Unit succ : graph.getSuccsOf(unit)) {
                if (inQueue.add(succ)) {
                    worklist.addLast(succ);
                }
            }
        }

        boolean seenCreatedOnExit = false;
        boolean openAtExit = false;
        boolean escaped = false;
        int firstOpenExitLine = -1;
        int escapeSiteLine = -1;
        int aliasCountOnFailure = 0;
        for (Unit tail : graph.getTails()) {
            OpenState exitState = outStates.get(tail);
            if (exitState == null || !exitState.created) {
                continue;
            }
            seenCreatedOnExit = true;
            if (exitState.mayOpen) {
                openAtExit = true;
                int tailLine = getUnitLine(tail);
                if (tailLine > 0 && (firstOpenExitLine <= 0 || tailLine < firstOpenExitLine)) {
                    firstOpenExitLine = tailLine;
                }
                aliasCountOnFailure = Math.max(aliasCountOnFailure, exitState.aliases.size());
            }
            if (exitState.escaped) {
                escaped = true;
                if (exitState.escapeSiteLine > 0 && (escapeSiteLine <= 0 || exitState.escapeSiteLine < escapeSiteLine)) {
                    escapeSiteLine = exitState.escapeSiteLine;
                }
                aliasCountOnFailure = Math.max(aliasCountOnFailure, exitState.aliases.size());
            }
        }
        int closeWitnessCount = countAliasCloseWitnesses(graph, outStates, sourceSite);

        if (!seenCreatedOnExit) {
            return new SourceGuaranteeResult(
                    false,
                    "source_not_reaching_method_exit",
                    "none",
                    firstOpenExitLine,
                    escapeSiteLine,
                    aliasCountOnFailure,
                    closeWitnessCount
            );
        }
        if (escaped) {
            return new SourceGuaranteeResult(
                    false,
                    "alias_escaped_before_close",
                    "none",
                    firstOpenExitLine,
                    escapeSiteLine,
                    aliasCountOnFailure,
                    closeWitnessCount
            );
        }
        if (openAtExit) {
            return new SourceGuaranteeResult(
                    false,
                    closeWitnessCount >= 2
                            ? "open_resource_on_exit_path_with_multi_close_witness"
                            : "open_resource_on_exit_path",
                    closeWitnessCount >= 2 ? "heuristic" : "none",
                    firstOpenExitLine,
                    escapeSiteLine,
                    aliasCountOnFailure,
                    closeWitnessCount
            );
        }
        if (closeWitnessCount <= 0) {
            return new SourceGuaranteeResult(
                    false,
                    "hard_proof_missing_close_witness",
                    "none",
                    firstOpenExitLine,
                    escapeSiteLine,
                    aliasCountOnFailure,
                    closeWitnessCount
            );
        }
        return new SourceGuaranteeResult(
                true,
                "all_exit_paths_closed_for_alias",
                "hard",
                firstOpenExitLine,
                escapeSiteLine,
                0,
                closeWitnessCount
        );
    }

    private static OpenState mergeOpenState(
            ExceptionalUnitGraph graph,
            IdentityHashMap<Unit, OpenState> outStates,
            Unit unit,
            SourceSite sourceSite
    ) {
        OpenState merged = new OpenState();
        List<Unit> predecessors = graph.getPredsOf(unit);
        if (predecessors.isEmpty()) {
            return merged;
        }

        Set<Unit> exceptionalPreds = new HashSet<Unit>(invokeGraphUnitListMethod(graph, "getExceptionalPredsOf", unit));
        boolean sourceMayThrow = sourceSite != null && sourceSiteMayThrow(sourceSite);
        for (Unit pred : predecessors) {
            OpenState predOut = outStates.get(pred);
            if (predOut == null) {
                continue;
            }
            OpenState incoming = predOut.copy();
            if (sourceMayThrow && pred == sourceSite.unit && exceptionalPreds.contains(pred)) {
                // Source assignment may throw before the resource object is bound.
                incoming.created = false;
                incoming.mayOpen = false;
                incoming.escaped = false;
                incoming.escapeSiteLine = -1;
                incoming.aliases.clear();
            }
            merged.created = merged.created || incoming.created;
            merged.mayOpen = merged.mayOpen || incoming.mayOpen;
            merged.escaped = merged.escaped || incoming.escaped;
            if (incoming.escapeSiteLine > 0 && (merged.escapeSiteLine <= 0 || incoming.escapeSiteLine < merged.escapeSiteLine)) {
                merged.escapeSiteLine = incoming.escapeSiteLine;
            }
            merged.aliases.addAll(incoming.aliases);
        }
        return merged;
    }

    private static OpenState transferOpenState(
            Unit unit,
            OpenState inState,
            SourceSite sourceSite
    ) {
        OpenState outState = inState.copy();
        boolean isSourceUnit = unit == sourceSite.unit;

        if (isSourceUnit) {
            outState.created = true;
            outState.mayOpen = true;
            outState.aliases.clear();
            outState.aliases.add(sourceSite.local);
        }

        if (!outState.created) {
            return outState;
        }

        if (unit instanceof AssignStmt) {
            if (isSourceUnit) {
                // Keep source alias seeded from the source statement itself.
            } else {
                applyAliasTransfer((AssignStmt) unit, outState, getUnitLine(unit));
            }
        } else if (unit instanceof IdentityStmt) {
            Value leftOp = ((IdentityStmt) unit).getLeftOp();
            Local leftLocal = toLocal(leftOp);
            if (leftLocal != null) {
                outState.aliases.remove(leftLocal);
            }
        } else {
            for (ValueBox defBox : unit.getDefBoxes()) {
                Local definedLocal = toLocal(defBox.getValue());
                if (definedLocal != null) {
                    outState.aliases.remove(definedLocal);
                }
            }
        }

        InvokeExpr invokeExpr = extractInvokeExpr(unit);
        if (invokeExpr != null) {
            Local wrappedAlias = resolveWrappedResourceAlias(invokeExpr, outState.aliases);
            if (wrappedAlias != null) {
                outState.aliases.add(wrappedAlias);
            }
            if (isCloseInvokeOnAliases(invokeExpr, outState.aliases)) {
                outState.mayOpen = false;
                outState.aliases.clear();
            } else if (wrappedAlias == null && isAliasEscapedByInvoke(invokeExpr, outState.aliases)) {
                markEscaped(outState, getUnitLine(unit));
            }
        }

        if (unit instanceof ReturnStmt) {
            ReturnStmt returnStmt = (ReturnStmt) unit;
            if (valueReferencesAliases(returnStmt.getOp(), outState.aliases)) {
                markEscaped(outState, getUnitLine(unit));
            }
        } else if (unit instanceof ThrowStmt) {
            ThrowStmt throwStmt = (ThrowStmt) unit;
            if (valueReferencesAliases(throwStmt.getOp(), outState.aliases)) {
                markEscaped(outState, getUnitLine(unit));
            }
        }

        if (outState.escaped) {
            outState.mayOpen = true;
        }

        return outState;
    }

    private static void applyAliasTransfer(AssignStmt assignStmt, OpenState state, int unitLine) {
        Value leftOp = assignStmt.getLeftOp();
        Value rightOp = assignStmt.getRightOp();
        boolean rightAlias = valueReferencesAliases(rightOp, state.aliases);

        Local leftLocal = toLocal(leftOp);
        if (leftLocal != null) {
            if (rightAlias) {
                state.aliases.add(leftLocal);
            } else {
                state.aliases.remove(leftLocal);
            }
            return;
        }

        if (rightAlias) {
            markEscaped(state, unitLine);
        }
    }

    private static void markEscaped(OpenState state, int line) {
        state.escaped = true;
        if (line > 0 && (state.escapeSiteLine <= 0 || line < state.escapeSiteLine)) {
            state.escapeSiteLine = line;
        }
    }

    private static Local resolveWrappedResourceAlias(InvokeExpr invokeExpr, Set<Local> aliases) {
        if (!(invokeExpr instanceof InstanceInvokeExpr)) {
            return null;
        }
        if (!"<init>".equals(invokeExpr.getMethod().getName())) {
            return null;
        }
        boolean argHitsAlias = false;
        for (Value arg : invokeExpr.getArgs()) {
            if (valueReferencesAliases(arg, aliases)) {
                argHitsAlias = true;
                break;
            }
        }
        if (!argHitsAlias) {
            return null;
        }
        Local baseLocal = toLocal(((InstanceInvokeExpr) invokeExpr).getBase());
        if (baseLocal == null) {
            return null;
        }
        String baseType = normalizeType(baseLocal.getType().toString());
        if (!isResourceType(baseType)) {
            return null;
        }
        return baseLocal;
    }

    private static int countAliasCloseWitnesses(
            ExceptionalUnitGraph graph,
            IdentityHashMap<Unit, OpenState> outStates,
            SourceSite sourceSite
    ) {
        int closeWitnesses = 0;
        for (Unit unit : graph.getBody().getUnits()) {
            OpenState inState = mergeOpenState(graph, outStates, unit, sourceSite);
            if (inState == null || !inState.created || inState.aliases.isEmpty()) {
                continue;
            }
            InvokeExpr invokeExpr = extractInvokeExpr(unit);
            if (invokeExpr == null) {
                continue;
            }
            if (isCloseInvokeOnAliases(invokeExpr, inState.aliases)) {
                closeWitnesses += 1;
            }
        }
        return closeWitnesses;
    }

    private static boolean sourceSiteMayThrow(SourceSite sourceSite) {
        if (sourceSite == null || sourceSite.unit == null) {
            return false;
        }
        Unit unit = sourceSite.unit;
        if (unit instanceof AssignStmt) {
            Value rightOp = ((AssignStmt) unit).getRightOp();
            return rightOp instanceof InvokeExpr || rightOp instanceof NewExpr;
        }
        return extractInvokeExpr(unit) != null;
    }

    @SuppressWarnings("unchecked")
    private static List<Unit> invokeGraphUnitListMethod(
            ExceptionalUnitGraph graph,
            String methodName,
            Unit unit
    ) {
        try {
            Method method = graph.getClass().getMethod(methodName, Unit.class);
            Object value = method.invoke(graph, unit);
            if (value instanceof List<?>) {
                return (List<Unit>) value;
            }
        } catch (Exception ignored) {
            // Fall back to the generic predecessor list when this API is unavailable.
        }
        return Collections.emptyList();
    }

    private static boolean isCloseInvokeOnAliases(InvokeExpr invokeExpr, Set<Local> aliases) {
        if (!(invokeExpr instanceof InstanceInvokeExpr)) {
            return false;
        }
        String methodName = invokeExpr.getMethod().getName().toLowerCase(Locale.ROOT);
        if (!CLOSE_METHOD_NAMES.contains(methodName)) {
            return false;
        }
        Value base = ((InstanceInvokeExpr) invokeExpr).getBase();
        return valueReferencesAliases(base, aliases);
    }

    private static boolean isAliasEscapedByInvoke(InvokeExpr invokeExpr, Set<Local> aliases) {
        for (Value arg : invokeExpr.getArgs()) {
            if (valueReferencesAliases(arg, aliases)) {
                return true;
            }
        }
        return false;
    }

    private static boolean valueReferencesAliases(Value value, Set<Local> aliases) {
        if (value == null || aliases.isEmpty()) {
            return false;
        }
        if (value instanceof Local) {
            return aliases.contains((Local) value);
        }
        if (value instanceof CastExpr) {
            return valueReferencesAliases(((CastExpr) value).getOp(), aliases);
        }
        if (value instanceof ArrayRef) {
            return valueReferencesAliases(((ArrayRef) value).getBase(), aliases);
        }
        if (value instanceof FieldRef) {
            if (value instanceof soot.jimple.InstanceFieldRef) {
                return valueReferencesAliases(((soot.jimple.InstanceFieldRef) value).getBase(), aliases);
            }
            return false;
        }
        if (value instanceof BinopExpr) {
            BinopExpr binopExpr = (BinopExpr) value;
            return valueReferencesAliases(binopExpr.getOp1(), aliases)
                    || valueReferencesAliases(binopExpr.getOp2(), aliases);
        }
        return false;
    }

    private static Map<Unit, Map<Local, Object>> computeConstantInStates(Body body) {
        ExceptionalUnitGraph graph = new ExceptionalUnitGraph(body);
        IdentityHashMap<Unit, Map<Local, Object>> inStates = new IdentityHashMap<Unit, Map<Local, Object>>();
        IdentityHashMap<Unit, Map<Local, Object>> outStates = new IdentityHashMap<Unit, Map<Local, Object>>();
        Deque<Unit> worklist = new ArrayDeque<Unit>();
        Set<Unit> inQueue = new HashSet<Unit>();

        for (Unit unit : body.getUnits()) {
            inStates.put(unit, new HashMap<Local, Object>());
            outStates.put(unit, new HashMap<Local, Object>());
            worklist.addLast(unit);
            inQueue.add(unit);
        }

        while (!worklist.isEmpty()) {
            Unit unit = worklist.removeFirst();
            inQueue.remove(unit);

            Map<Local, Object> mergedIn = mergeConstantState(graph, outStates, unit);
            inStates.put(unit, mergedIn);

            Map<Local, Object> newOut = transferConstantState(unit, mergedIn);
            Map<Local, Object> oldOut = outStates.get(unit);
            if (mapsEqual(oldOut, newOut)) {
                continue;
            }
            outStates.put(unit, newOut);
            for (Unit succ : graph.getSuccsOf(unit)) {
                if (inQueue.add(succ)) {
                    worklist.addLast(succ);
                }
            }
        }

        return inStates;
    }

    private static IdentityHashMap<IfStmt, BranchReachability> analyzeBranchReachability(Body body) {
        BriefUnitGraph graph = new BriefUnitGraph(body);
        IdentityHashMap<IfStmt, BranchReachability> summaries = new IdentityHashMap<IfStmt, BranchReachability>();
        Deque<BranchWorkItem> worklist = new ArrayDeque<BranchWorkItem>();
        Set<String> seen = new HashSet<String>();

        for (Unit head : graph.getHeads()) {
            worklist.addLast(new BranchWorkItem(head, new ConstraintState()));
        }

        while (!worklist.isEmpty()) {
            BranchWorkItem current = worklist.removeFirst();
            Unit unit = current.unit;
            ConstraintState state = current.state;
            String key = System.identityHashCode(unit) + "|" + state.fingerprint();
            if (!seen.add(key)) {
                continue;
            }

            if (unit instanceof IfStmt) {
                IfStmt ifStmt = (IfStmt) unit;
                BranchReachability summary = summaries.get(ifStmt);
                if (summary == null) {
                    summary = new BranchReachability();
                    summaries.put(ifStmt, summary);
                }
                ParsedComparison parsed = parseComparisonFromCondition(ifStmt.getCondition());
                Unit trueSucc = ifStmt.getTarget();
                Unit falseSucc = resolveFalseSuccessor(graph, ifStmt);

                if (parsed == null) {
                    summary.trueFeasible = true;
                    summary.falseFeasible = true;
                    if (trueSucc != null) {
                        worklist.addLast(new BranchWorkItem(trueSucc, state.copy()));
                    }
                    if (falseSucc != null) {
                        worklist.addLast(new BranchWorkItem(falseSucc, state.copy()));
                    }
                    continue;
                }

                ConstraintState trueState = state.copy();
                boolean trueSat = applyComparisonConstraint(trueState, parsed);
                if (trueSat) {
                    summary.trueFeasible = true;
                    if (trueSucc != null) {
                        worklist.addLast(new BranchWorkItem(trueSucc, trueState));
                    }
                } else {
                    summary.trueConflict = true;
                }

                ConstraintState falseState = state.copy();
                ParsedComparison negated = new ParsedComparison(
                        parsed.localName,
                        parsed.constant,
                        negateComparisonOperator(parsed.operator)
                );
                boolean falseSat = applyComparisonConstraint(falseState, negated);
                if (falseSat) {
                    summary.falseFeasible = true;
                    if (falseSucc != null) {
                        worklist.addLast(new BranchWorkItem(falseSucc, falseState));
                    }
                } else {
                    summary.falseConflict = true;
                }
                continue;
            }

            for (Unit successor : graph.getSuccsOf(unit)) {
                worklist.addLast(new BranchWorkItem(successor, state.copy()));
            }
        }
        return summaries;
    }

    private static Unit resolveFalseSuccessor(BriefUnitGraph graph, IfStmt ifStmt) {
        Unit trueSucc = ifStmt.getTarget();
        for (Unit successor : graph.getSuccsOf(ifStmt)) {
            if (successor != trueSucc) {
                return successor;
            }
        }
        return null;
    }

    private static ParsedComparison parseComparisonFromCondition(Value conditionValue) {
        if (!(conditionValue instanceof ConditionExpr)) {
            return null;
        }
        ConditionExpr conditionExpr = (ConditionExpr) conditionValue;
        String operator = toComparisonOperator(conditionExpr);
        if (operator == null) {
            return null;
        }

        Value left = conditionExpr.getOp1();
        Value right = conditionExpr.getOp2();
        Local local = toLocal(left);
        Object constant = resolveConstantValue(right, Collections.<Local, Object>emptyMap());
        boolean reversed = false;

        if (local == null || !(constant instanceof Number)) {
            local = toLocal(right);
            constant = resolveConstantValue(left, Collections.<Local, Object>emptyMap());
            reversed = true;
        }
        if (local == null || !(constant instanceof Number)) {
            return null;
        }

        if (reversed) {
            operator = reverseComparisonOperator(operator);
        }
        return new ParsedComparison(local.getName(), ((Number) constant).doubleValue(), operator);
    }

    private static String toComparisonOperator(ConditionExpr conditionExpr) {
        if (conditionExpr instanceof soot.jimple.GtExpr) {
            return ">";
        }
        if (conditionExpr instanceof soot.jimple.GeExpr) {
            return ">=";
        }
        if (conditionExpr instanceof soot.jimple.LtExpr) {
            return "<";
        }
        if (conditionExpr instanceof soot.jimple.LeExpr) {
            return "<=";
        }
        if (conditionExpr instanceof soot.jimple.EqExpr) {
            return "==";
        }
        if (conditionExpr instanceof soot.jimple.NeExpr) {
            return "!=";
        }
        return null;
    }

    private static String reverseComparisonOperator(String operator) {
        if (">".equals(operator)) {
            return "<";
        }
        if (">=".equals(operator)) {
            return "<=";
        }
        if ("<".equals(operator)) {
            return ">";
        }
        if ("<=".equals(operator)) {
            return ">=";
        }
        return operator;
    }

    private static String negateComparisonOperator(String operator) {
        if (">".equals(operator)) {
            return "<=";
        }
        if (">=".equals(operator)) {
            return "<";
        }
        if ("<".equals(operator)) {
            return ">=";
        }
        if ("<=".equals(operator)) {
            return ">";
        }
        if ("==".equals(operator)) {
            return "!=";
        }
        if ("!=".equals(operator)) {
            return "==";
        }
        return operator;
    }

    private static boolean applyComparisonConstraint(ConstraintState state, ParsedComparison parsed) {
        RangeConstraint range = state.rangesByLocal.get(parsed.localName);
        if (range == null) {
            range = new RangeConstraint();
            state.rangesByLocal.put(parsed.localName, range);
        }

        if (">".equals(parsed.operator)) {
            applyLowerBound(range, parsed.constant, false);
        } else if (">=".equals(parsed.operator)) {
            applyLowerBound(range, parsed.constant, true);
        } else if ("<".equals(parsed.operator)) {
            applyUpperBound(range, parsed.constant, false);
        } else if ("<=".equals(parsed.operator)) {
            applyUpperBound(range, parsed.constant, true);
        } else if ("==".equals(parsed.operator)) {
            applyLowerBound(range, parsed.constant, true);
            applyUpperBound(range, parsed.constant, true);
        } else if ("!=".equals(parsed.operator)) {
            range.notEquals.add(Double.valueOf(parsed.constant));
        }

        return isRangeSatisfiable(range);
    }

    private static void applyLowerBound(RangeConstraint range, double value, boolean inclusive) {
        if (range.lower == null) {
            range.lower = Double.valueOf(value);
            range.lowerInclusive = inclusive;
            return;
        }

        int cmp = Double.compare(value, range.lower.doubleValue());
        if (cmp > 0) {
            range.lower = Double.valueOf(value);
            range.lowerInclusive = inclusive;
        } else if (cmp == 0) {
            range.lowerInclusive = range.lowerInclusive && inclusive;
        }
    }

    private static void applyUpperBound(RangeConstraint range, double value, boolean inclusive) {
        if (range.upper == null) {
            range.upper = Double.valueOf(value);
            range.upperInclusive = inclusive;
            return;
        }

        int cmp = Double.compare(value, range.upper.doubleValue());
        if (cmp < 0) {
            range.upper = Double.valueOf(value);
            range.upperInclusive = inclusive;
        } else if (cmp == 0) {
            range.upperInclusive = range.upperInclusive && inclusive;
        }
    }

    private static boolean isRangeSatisfiable(RangeConstraint range) {
        if (range.lower != null && range.upper != null) {
            int cmp = Double.compare(range.lower.doubleValue(), range.upper.doubleValue());
            if (cmp > 0) {
                return false;
            }
            if (cmp == 0) {
                if (!(range.lowerInclusive && range.upperInclusive)) {
                    return false;
                }
                return !range.notEquals.contains(range.lower);
            }
        }
        return true;
    }

    private static String buildUnreachableReason(boolean byConst, boolean byPath) {
        if (byConst) {
            return "constant_condition_conflict";
        }
        if (byPath) {
            return "path_constraint_conflict";
        }
        return "";
    }

    private static String combineUnreachableReasons(String trueReason, String falseReason) {
        if (!trueReason.isEmpty() && !falseReason.isEmpty()) {
            if (trueReason.equals(falseReason)) {
                return trueReason;
            }
            return trueReason + ";" + falseReason;
        }
        if (!trueReason.isEmpty()) {
            return trueReason;
        }
        if (!falseReason.isEmpty()) {
            return falseReason;
        }
        return "";
    }

    private static Map<Local, Object> mergeConstantState(
            ExceptionalUnitGraph graph,
            IdentityHashMap<Unit, Map<Local, Object>> outStates,
            Unit unit
    ) {
        List<Unit> predecessors = graph.getPredsOf(unit);
        if (predecessors.isEmpty()) {
            return new HashMap<Local, Object>();
        }

        Map<Local, Object> merged = null;
        for (Unit predecessor : predecessors) {
            Map<Local, Object> predOut = outStates.get(predecessor);
            if (predOut == null) {
                predOut = Collections.emptyMap();
            }
            if (merged == null) {
                merged = new HashMap<Local, Object>(predOut);
                continue;
            }

            List<Local> keys = new ArrayList<Local>(merged.keySet());
            for (Local key : keys) {
                if (!predOut.containsKey(key)) {
                    merged.remove(key);
                    continue;
                }
                Object oldValue = merged.get(key);
                Object newValue = predOut.get(key);
                if (!constantValuesEqual(oldValue, newValue)) {
                    merged.remove(key);
                }
            }
        }

        if (merged == null) {
            return new HashMap<Local, Object>();
        }
        return merged;
    }

    private static Map<Local, Object> transferConstantState(Unit unit, Map<Local, Object> inState) {
        Map<Local, Object> outState = new HashMap<Local, Object>(inState);

        if (unit instanceof AssignStmt) {
            AssignStmt assignStmt = (AssignStmt) unit;
            Local leftLocal = toLocal(assignStmt.getLeftOp());
            if (leftLocal != null) {
                Object value = resolveConstantValue(assignStmt.getRightOp(), inState);
                if (value == null) {
                    outState.remove(leftLocal);
                } else {
                    outState.put(leftLocal, value);
                }
            }
            return outState;
        }

        if (unit instanceof IdentityStmt) {
            Local leftLocal = toLocal(((IdentityStmt) unit).getLeftOp());
            if (leftLocal != null) {
                outState.remove(leftLocal);
            }
            return outState;
        }

        for (ValueBox defBox : unit.getDefBoxes()) {
            Local local = toLocal(defBox.getValue());
            if (local != null) {
                outState.remove(local);
            }
        }
        return outState;
    }

    private static boolean mapsEqual(Map<Local, Object> left, Map<Local, Object> right) {
        if (left == null || right == null) {
            return left == right;
        }
        if (left.size() != right.size()) {
            return false;
        }
        for (Map.Entry<Local, Object> entry : left.entrySet()) {
            if (!right.containsKey(entry.getKey())) {
                return false;
            }
            if (!constantValuesEqual(entry.getValue(), right.get(entry.getKey()))) {
                return false;
            }
        }
        return true;
    }

    private static boolean constantValuesEqual(Object left, Object right) {
        return left == right || (left != null && left.equals(right));
    }

    private static Object resolveConstantValue(Value value, Map<Local, Object> constantEnv) {
        if (value == null) {
            return null;
        }
        if (value instanceof soot.jimple.Constant) {
            return convertConstant((soot.jimple.Constant) value);
        }
        if (value instanceof Local) {
            if (constantEnv == null) {
                return null;
            }
            return constantEnv.get((Local) value);
        }
        if (value instanceof CastExpr) {
            return resolveConstantValue(((CastExpr) value).getOp(), constantEnv);
        }
        if (value instanceof BinopExpr) {
            return resolveBinopConstant((BinopExpr) value, constantEnv);
        }
        return null;
    }

    private static Object resolveBinopConstant(BinopExpr expr, Map<Local, Object> constantEnv) {
        Object left = resolveConstantValue(expr.getOp1(), constantEnv);
        Object right = resolveConstantValue(expr.getOp2(), constantEnv);
        if (!(left instanceof Number) || !(right instanceof Number)) {
            return null;
        }

        String symbol = expr.getSymbol();
        if (symbol == null) {
            return null;
        }
        symbol = symbol.trim();

        double lv = ((Number) left).doubleValue();
        double rv = ((Number) right).doubleValue();
        long li = ((Number) left).longValue();
        long ri = ((Number) right).longValue();

        if ("+".equals(symbol)) {
            return Double.valueOf(lv + rv);
        }
        if ("-".equals(symbol)) {
            return Double.valueOf(lv - rv);
        }
        if ("*".equals(symbol)) {
            return Double.valueOf(lv * rv);
        }
        if ("/".equals(symbol)) {
            if (rv == 0.0d) {
                return null;
            }
            return Double.valueOf(lv / rv);
        }
        if ("%".equals(symbol)) {
            if (rv == 0.0d) {
                return null;
            }
            return Double.valueOf(lv % rv);
        }
        if ("&".equals(symbol)) {
            return Long.valueOf(li & ri);
        }
        if ("|".equals(symbol)) {
            return Long.valueOf(li | ri);
        }
        if ("^".equals(symbol)) {
            return Long.valueOf(li ^ ri);
        }
        if ("<<".equals(symbol)) {
            return Long.valueOf(li << ((int) ri));
        }
        if (">>".equals(symbol)) {
            return Long.valueOf(li >> ((int) ri));
        }
        if (">>>".equals(symbol)) {
            return Long.valueOf(li >>> ((int) ri));
        }
        return null;
    }

    private static boolean addSourceSite(
            List<SourceSite> sites,
            Set<String> seen,
            int line,
            Unit unit,
            Local local
    ) {
        String localName = local == null ? "<none>" : local.getName();
        String key = line + ":" + unit.hashCode() + ":" + localName;
        if (!seen.add(key)) {
            return false;
        }
        sites.add(new SourceSite(line, unit, local));
        return true;
    }

    private static Local toLocal(Value value) {
        if (value instanceof Local) {
            return (Local) value;
        }
        return null;
    }

    private static boolean isFactoryResourceInvoke(InvokeExpr invokeExpr) {
        String methodName = invokeExpr.getMethod().getName();
        if (!FACTORY_METHOD_NAMES.contains(methodName)) {
            return false;
        }
        if (TEMP_RESOURCE_FACTORY_METHOD_NAMES.contains(methodName)) {
            return true;
        }
        String returnType = normalizeType(invokeExpr.getMethod().getReturnType().toString());
        return isResourceType(returnType);
    }

    private static boolean isAcquireResourceInvoke(InvokeExpr invokeExpr) {
        String methodName = invokeExpr.getMethod().getName();
        if (!ACQUIRE_METHOD_NAMES.contains(methodName)) {
            return false;
        }
        if (!(invokeExpr instanceof InstanceInvokeExpr)) {
            return false;
        }
        Value base = ((InstanceInvokeExpr) invokeExpr).getBase();
        String baseType = normalizeType(base.getType().toString());
        return isResourceType(baseType);
    }

    private static InvokeExpr extractInvokeExpr(Unit unit) {
        if (!(unit instanceof Stmt)) {
            return null;
        }
        Stmt stmt = (Stmt) unit;
        if (!stmt.containsInvokeExpr()) {
            return null;
        }
        return stmt.getInvokeExpr();
    }

    private static int[] computeBlockScope(Block block) {
        int minLine = Integer.MAX_VALUE;
        int maxLine = -1;
        for (Unit unit : block) {
            int line = getUnitLine(unit);
            if (line <= 0) {
                continue;
            }
            minLine = Math.min(minLine, line);
            maxLine = Math.max(maxLine, line);
        }
        if (minLine == Integer.MAX_VALUE) {
            return new int[]{0, 0};
        }
        return new int[]{minLine, maxLine};
    }

    private static int getUnitLine(Unit unit) {
        int line = unit.getJavaSourceStartLineNumber();
        if (line > 0) {
            return line;
        }
        Tag posTag = unit.getTag("SourceLnPosTag");
        if (posTag instanceof SourceLnPosTag) {
            int startLn = ((SourceLnPosTag) posTag).startLn();
            if (startLn > 0) {
                return startLn;
            }
        }
        Tag lineTag = unit.getTag("LineNumberTag");
        if (lineTag instanceof LineNumberTag) {
            return ((LineNumberTag) lineTag).getLineNumber();
        }
        return -1;
    }

    private static Boolean evaluateConstantCondition(Value conditionValue) {
        return evaluateConstantCondition(conditionValue, Collections.<Local, Object>emptyMap());
    }

    private static Boolean evaluateConstantCondition(
            Value conditionValue,
            Map<Local, Object> constantEnv
    ) {
        if (!(conditionValue instanceof ConditionExpr)) {
            return null;
        }
        ConditionExpr conditionExpr = (ConditionExpr) conditionValue;

        Object left = resolveConstantValue(conditionExpr.getOp1(), constantEnv);
        Object right = resolveConstantValue(conditionExpr.getOp2(), constantEnv);
        if (left == null || right == null) {
            return null;
        }

        boolean leftNull = isNullConstantValue(left);
        boolean rightNull = isNullConstantValue(right);
        if (leftNull || rightNull) {
            if (conditionExpr instanceof soot.jimple.EqExpr) {
                return Boolean.valueOf(leftNull && rightNull);
            }
            if (conditionExpr instanceof soot.jimple.NeExpr) {
                return Boolean.valueOf(!(leftNull && rightNull));
            }
            return null;
        }

        if (!(left instanceof Number) || !(right instanceof Number)) {
            return null;
        }
        double lv = ((Number) left).doubleValue();
        double rv = ((Number) right).doubleValue();
        if (conditionExpr instanceof soot.jimple.EqExpr) {
            return Boolean.valueOf(lv == rv);
        }
        if (conditionExpr instanceof soot.jimple.NeExpr) {
            return Boolean.valueOf(lv != rv);
        }
        if (conditionExpr instanceof soot.jimple.GeExpr) {
            return Boolean.valueOf(lv >= rv);
        }
        if (conditionExpr instanceof soot.jimple.GtExpr) {
            return Boolean.valueOf(lv > rv);
        }
        if (conditionExpr instanceof soot.jimple.LeExpr) {
            return Boolean.valueOf(lv <= rv);
        }
        if (conditionExpr instanceof soot.jimple.LtExpr) {
            return Boolean.valueOf(lv < rv);
        }
        return null;
    }

    private static boolean isNullConstantValue(Object value) {
        return value == NULL_CONST_MARKER;
    }

    private static Object convertConstant(soot.jimple.Constant constant) {
        if (constant instanceof IntConstant) {
            return Integer.valueOf(((IntConstant) constant).value);
        }
        if (constant instanceof LongConstant) {
            return Long.valueOf(((LongConstant) constant).value);
        }
        if (constant instanceof FloatConstant) {
            return Float.valueOf(((FloatConstant) constant).value);
        }
        if (constant instanceof DoubleConstant) {
            return Double.valueOf(((DoubleConstant) constant).value);
        }
        if (constant instanceof NullConstant) {
            return NULL_CONST_MARKER;
        }
        return null;
    }

    private static String buildFunctionUid(SootClass sootClass, SootMethod sootMethod) {
        String owner = normalizeOwnerClass(sootClass.getName());
        StringBuilder builder = new StringBuilder();
        builder.append(owner).append(".").append(sootMethod.getName()).append("(");
        List<String> params = normalizeParamTypes(sootMethod.getParameterTypes());
        for (int i = 0; i < params.size(); i++) {
            if (i > 0) {
                builder.append(",");
            }
            builder.append(params.get(i));
        }
        builder.append(")");
        return builder.toString();
    }

    private static String inferSourceFile(SootClass sootClass) {
        String owner = normalizeOwnerClass(sootClass.getName());
        String packagePath = "";
        int idx = owner.lastIndexOf(".");
        if (idx >= 0) {
            packagePath = owner.substring(0, idx).replace(".", "/") + "/";
        }
        Tag sourceTag = sootClass.getTag("SourceFileTag");
        if (sourceTag instanceof SourceFileTag) {
            String sourceFile = ((SourceFileTag) sourceTag).getSourceFile();
            if (sourceFile != null && !sourceFile.isEmpty()) {
                return packagePath + sourceFile;
            }
        }
        return owner.replace(".", "/") + ".java";
    }

    private static List<String> normalizeParamTypes(List<Type> paramTypes) {
        List<String> result = new ArrayList<String>();
        for (Type type : paramTypes) {
            result.add(normalizeType(type.toString()));
        }
        return result;
    }

    private static String normalizeOwnerClass(String owner) {
        return owner.replace("$", ".");
    }

    private static String normalizeType(String typeName) {
        String normalized = typeName == null ? "" : typeName.trim();
        if (normalized.isEmpty()) {
            return normalized;
        }
        normalized = normalized.replaceAll("<.*?>", "");
        normalized = normalized.replace("[]", "");
        normalized = normalized.replaceAll("\\s+", "");
        if (normalized.contains(".")) {
            normalized = normalized.substring(normalized.lastIndexOf(".") + 1);
        }
        return normalized;
    }

    private static boolean isResourceType(String typeName) {
        if (typeName == null || typeName.isEmpty()) {
            return false;
        }
        if (RESOURCE_TYPE_WHITELIST.contains(typeName)) {
            return true;
        }
        for (String suffix : RESOURCE_SUFFIXES) {
            if (typeName.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }

    private static List<Integer> toList(int[] scope) {
        List<Integer> result = new ArrayList<Integer>(2);
        result.add(Integer.valueOf(scope[0]));
        result.add(Integer.valueOf(scope[1]));
        return result;
    }

    private static Set<String> buildCloseMethodNames() {
        Set<String> set = new HashSet<String>();
        Collections.addAll(
                set,
                "close",
                "abort",
                "disconnect",
                "shutdown",
                "shutdownnow",
                "unlock",
                "tryunlock",
                "release",
                "delete",
                "deleteifexists",
                "deleteonexit",
                "stop"
        );
        return set;
    }

    private static Set<String> buildFactoryMethodNames() {
        Set<String> set = new HashSet<String>();
        Collections.addAll(
                set,
                "open",
                "openStream",
                "getInputStream",
                "getErrorStream",
                "getOutputStream",
                "getChannel",
                "newChannel",
                "newInputStream",
                "newOutputStream",
                "newBufferedReader",
                "newBufferedWriter",
                "newByteChannel",
                "newDirectoryStream",
                "newFileSystem",
                "list",
                "walk",
                "find",
                "lines",
                "getConnection",
                "getDBConnection",
                "createStatement",
                "prepareStatement",
                "prepareCall",
                "executeQuery",
                "getResultSet",
                "getGeneratedKeys",
                "createSocket",
                "accept",
                "getResourceAsStream",
                "openConnection",
                "newFixedThreadPool",
                "newCachedThreadPool",
                "newSingleThreadExecutor",
                "newSingleThreadScheduledExecutor",
                "newScheduledThreadPool",
                "newWorkStealingPool",
                "newVirtualThreadPerTaskExecutor",
                "newThreadPerTaskExecutor",
                "createTempFile",
                "createTempDirectory"
        );
        return set;
    }

    private static Set<String> buildTempResourceFactoryMethodNames() {
        Set<String> set = new HashSet<String>();
        Collections.addAll(set, "createTempFile", "createTempDirectory");
        return set;
    }

    private static Set<String> buildAcquireMethodNames() {
        Set<String> set = new HashSet<String>();
        Collections.addAll(set, "lock", "tryLock", "lockInterruptibly", "acquire", "acquireUninterruptibly");
        return set;
    }

    private static Set<String> buildResourceTypeWhitelist() {
        Set<String> set = new HashSet<String>();
        Collections.addAll(
                set,
                "AutoCloseable",
                "Closeable",
                "InputStream",
                "OutputStream",
                "FileInputStream",
                "FileOutputStream",
                "BufferedInputStream",
                "BufferedOutputStream",
                "DataInputStream",
                "DataOutputStream",
                "Reader",
                "Writer",
                "FileReader",
                "FileWriter",
                "InputStreamReader",
                "OutputStreamWriter",
                "BufferedReader",
                "BufferedWriter",
                "PrintStream",
                "PrintWriter",
                "RandomAccessFile",
                "ObjectInputStream",
                "ObjectOutputStream",
                "Socket",
                "ServerSocket",
                "DatagramSocket",
                "SocketChannel",
                "ServerSocketChannel",
                "DatagramChannel",
                "FileChannel",
                "AsynchronousFileChannel",
                "SeekableByteChannel",
                "DirectoryStream",
                "WatchService",
                "Selector",
                "Connection",
                "Statement",
                "PreparedStatement",
                "CallableStatement",
                "ResultSet",
                "DataSource",
                "JarFile",
                "JarInputStream",
                "JarOutputStream",
                "ZipFile",
                "ZipInputStream",
                "ZipOutputStream",
                "GZIPInputStream",
                "GZIPOutputStream",
                "Scanner",
                "URLConnection",
                "HttpURLConnection",
                "HttpsURLConnection",
                "ExecutorService",
                "ScheduledExecutorService",
                "ThreadPoolExecutor",
                "ForkJoinPool",
                "ReentrantLock",
                "ReadWriteLock",
                "ReentrantReadWriteLock",
                "Lock",
                "StampedLock",
                "Semaphore"
        );
        return set;
    }

    private static final class Config {
        private final String inputDir;
        private final String classpath;
        private final String outputPath;
        private final String callGraphEngine;
        private final boolean allowPhantomRefs;
        private final boolean wholeProgram;
        private final boolean keepLineNumber;
        private final int maxMethods;

        private Config(
                String inputDir,
                String classpath,
                String outputPath,
                String callGraphEngine,
                boolean allowPhantomRefs,
                boolean wholeProgram,
                boolean keepLineNumber,
                int maxMethods
        ) {
            this.inputDir = inputDir;
            this.classpath = classpath;
            this.outputPath = outputPath;
            this.callGraphEngine = callGraphEngine;
            this.allowPhantomRefs = allowPhantomRefs;
            this.wholeProgram = wholeProgram;
            this.keepLineNumber = keepLineNumber;
            this.maxMethods = maxMethods;
        }

        private static Config fromArgs(String[] args) {
            Map<String, String> options = parseArgs(args);
            String inputDir = options.getOrDefault("input-dir", "");
            String output = options.getOrDefault("output", "");
            String classpath = options.getOrDefault("classpath", inputDir);
            String cg = options.getOrDefault("cg", "spark").toLowerCase(Locale.ROOT);
            boolean allowPhantom = parseBool(options.get("allow-phantom-refs"), true);
            boolean wholeProgram = parseBool(options.get("whole-program"), true);
            boolean keepLine = parseBool(options.get("keep-line-number"), true);
            int maxMethods = parseInt(options.get("max-methods"), Integer.MAX_VALUE);
            return new Config(
                    inputDir,
                    classpath,
                    output,
                    cg,
                    allowPhantom,
                    wholeProgram,
                    keepLine,
                    maxMethods
            );
        }

        private static Map<String, String> parseArgs(String[] args) {
            Map<String, String> options = new HashMap<String, String>();
            int idx = 0;
            while (idx < args.length) {
                String token = args[idx];
                if (!token.startsWith("--")) {
                    idx += 1;
                    continue;
                }
                String key = token.substring(2);
                String value = "true";
                if (idx + 1 < args.length && !args[idx + 1].startsWith("--")) {
                    value = args[idx + 1];
                    idx += 1;
                }
                options.put(key, value);
                idx += 1;
            }
            return options;
        }

        private static boolean parseBool(String value, boolean defaultValue) {
            if (value == null) {
                return defaultValue;
            }
            String normalized = value.trim().toLowerCase(Locale.ROOT);
            if ("true".equals(normalized) || "1".equals(normalized) || "yes".equals(normalized)) {
                return true;
            }
            if ("false".equals(normalized) || "0".equals(normalized) || "no".equals(normalized)) {
                return false;
            }
            return defaultValue;
        }

        private static int parseInt(String value, int defaultValue) {
            if (value == null) {
                return defaultValue;
            }
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException err) {
                return defaultValue;
            }
        }
    }
}
