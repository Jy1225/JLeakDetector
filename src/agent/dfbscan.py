import json
import os
import re
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Set, Tuple, cast
from tqdm import tqdm

from agent.agent import *
from agent.java_mlk_issue_graph import (
    IssueGraphBuilder,
    IssueComponent,
    SourceInstance,
)
from agent.java_mlk_component_pipeline import ComponentWitnessSelector

from tstool.dfbscan_extractor.Java.Java_MLK_extractor import Java_MLK_Extractor
from tstool.validator.java_resource_ownership_validator import JavaResourceOwnershipValidator
from tstool.validator.java_resource_semantics import (
    RESOURCE_KIND_AUTOCLOSEABLE,
    RESOURCE_KIND_LOCK,
    RESOURCE_KIND_TEMP_RESOURCE,
    GUARANTEE_NONE,
    GUARANTEE_NORMAL_ONLY,
    GUARANTEE_ALL_EXIT_PATHS,
    RELEASE_CONTEXT_UNKNOWN,
    RELEASE_CONTEXT_NORMAL,
    RELEASE_CONTEXT_FINALLY,
    RELEASE_CONTEXT_TWR,
    build_intra_resource_rules,
    build_path_resource_rules,
    classify_resource_kind,
    decode_guarantee_level_marker,
    decode_release_context_marker,
    decode_resource_kind_marker,
    encode_guarantee_level_marker,
    encode_release_context_marker,
    encode_resource_kind_marker,
    is_all_exit_guaranteed,
    is_servlet_context,
    normalize_guarantee_level,
    normalize_release_context,
    normalize_resource_kind,
    should_trigger_strict_recheck,
)
from tstool.validator.java_soot_prefilter import (
    JavaSootPrefilter,
    SootPrefilterConfig,
    SootPrefilterStats,
)
from tstool.validator.java_z3_path_prefilter import (
    JavaZ3PathPrefilter,
    Z3PrefilterConfig,
    Z3PrefilterStats,
)
from tstool.analyzer.TS_analyzer import *
from tstool.analyzer.Java_TS_analyzer import *

from tstool.dfbscan_extractor.dfbscan_extractor import *
from tstool.dfbscan_extractor.Java.Java_NPD_extractor import *

from llmtool.LLM_utils import *
from llmtool.dfbscan.intra_dataflow_analyzer import *
from llmtool.dfbscan.path_validator import *

from memory.semantic.dfbscan_state import *
from memory.syntactic.function import *
from memory.syntactic.value import *

from ui.logger import *

BASE_PATH = Path(__file__).resolve().parents[2]


class DFBScanAgent(Agent):
    JAVA_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    JAVA_ASSIGNMENT_SKIP_KEYWORDS = {
        "if",
        "for",
        "while",
        "switch",
        "case",
        "catch",
        "return",
        "new",
        "this",
        "super",
        "null",
        "true",
        "false",
    }

    def __init__(
        self,
        bug_type: str,
        is_reachable: bool,
        project_path: str,
        language: str,
        ts_analyzer: TSAnalyzer,
        model_name: str,
        temperature: float,
        call_depth: int,
        max_neural_workers: int = 30,
        enable_soot_prefilter: bool = False,
        soot_shadow_mode: bool = True,
        soot_facts_path: str = "",
        soot_timeout_ms: int = 200,
        enable_z3_prefilter: bool = False,
        z3_shadow_mode: bool = True,
        z3_timeout_ms: int = 200,
        z3_min_parsed_constraints: int = 2,
        agent_id: int = 0,
    ) -> None:
        self.scan_started_at = time.perf_counter()
        self.bug_type = bug_type
        self.is_reachable = is_reachable

        self.project_path = project_path
        self.project_name = project_path.split("/")[-1]
        self.language = language if language not in {"C", "Cpp"} else "Cpp"
        self.ts_analyzer = ts_analyzer

        self.model_name = model_name
        self.temperature = temperature

        self.call_depth = call_depth
        self.max_neural_workers = max_neural_workers
        self.MAX_QUERY_NUM = 5
        self.enable_soot_prefilter = enable_soot_prefilter
        self.soot_shadow_mode = soot_shadow_mode
        self.soot_facts_path = soot_facts_path
        self.soot_timeout_ms = soot_timeout_ms
        self.enable_z3_prefilter = enable_z3_prefilter
        self.z3_shadow_mode = z3_shadow_mode
        self.z3_timeout_ms = z3_timeout_ms
        self.z3_min_parsed_constraints = z3_min_parsed_constraints

        self.lock = threading.Lock()

        with self.lock:
            self.log_dir_path = f"{BASE_PATH}/log/dfbscan/{self.model_name}/{self.bug_type}/{self.language}/{self.project_name}/{time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime())}-{agent_id}"
            self.res_dir_path = f"{BASE_PATH}/result/dfbscan/{self.model_name}/{self.bug_type}/{self.language}/{self.project_name}/{time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime())}-{agent_id}"
            os.makedirs(self.log_dir_path, exist_ok=True)
            self.logger = Logger(self.log_dir_path + "/" + "dfbscan.log")

            os.makedirs(self.res_dir_path, exist_ok=True)

        # LLM tools used by DFBScanAgent
        self.intra_dfa = IntraDataFlowAnalyzer(
            self.model_name,
            self.temperature,
            self.language,
            self.bug_type,
            self.MAX_QUERY_NUM,
            self.logger,
        )
        self.path_validator = PathValidator(
            self.model_name,
            self.temperature,
            self.language,
            self.bug_type,
            self.MAX_QUERY_NUM,
            self.logger,
        )
        self.extractor = self.__obtain_extractor()
        self.java_mlk_validator = (
            JavaResourceOwnershipValidator(self.ts_analyzer)
            if self.language == "Java" and self.bug_type == "MLK"
            else None
        )
        self.java_soot_prefilter = (
            JavaSootPrefilter(
                self.ts_analyzer,
                SootPrefilterConfig(
                    enabled=self.enable_soot_prefilter,
                    shadow_mode=self.soot_shadow_mode,
                    facts_path=self.soot_facts_path,
                    timeout_ms=self.soot_timeout_ms,
                ),
            )
            if self.language == "Java" and self.bug_type == "MLK"
            else None
        )
        self.soot_prefilter_stats = SootPrefilterStats()
        self.soot_prefilter_source_skipped = 0
        self.soot_source_gate_events = []
        self.java_z3_prefilter = (
            JavaZ3PathPrefilter(
                self.ts_analyzer,
                Z3PrefilterConfig(
                    enabled=self.enable_z3_prefilter,
                    timeout_ms=self.z3_timeout_ms,
                    shadow_mode=self.z3_shadow_mode,
                ),
            )
            if self.language == "Java" and self.bug_type == "MLK"
            else None
        )
        self.z3_prefilter_stats = Z3PrefilterStats()
        self.java_mlk_transfer_records: Dict[str, List[Dict[str, object]]] = {}
        self.java_mlk_issue_first = (
            os.environ.get("REPOAUDIT_JAVA_MLK_ISSUE_FIRST", "true")
            .strip()
            .lower()
            == "true"
        )
        try:
            self.java_mlk_max_witness_per_component = int(
                os.environ.get("REPOAUDIT_JAVA_MLK_MAX_WITNESS_PER_COMPONENT", "2")
            )
        except ValueError:
            self.java_mlk_max_witness_per_component = 2
        self.java_mlk_max_witness_per_component = max(
            1, min(5, self.java_mlk_max_witness_per_component)
        )
        self.java_mlk_family_link_mode = os.environ.get(
            "REPOAUDIT_JAVA_MLK_FAMILY_LINK_MODE", "aggressive"
        ).strip().lower()
        if self.java_mlk_family_link_mode not in {"conservative", "aggressive"}:
            self.java_mlk_family_link_mode = "conservative"
        self.java_mlk_source_confidence_min = os.environ.get(
            "REPOAUDIT_JAVA_MLK_SOURCE_CONFIDENCE_MIN", "low"
        ).strip().lower()
        if self.java_mlk_source_confidence_min not in {"low", "medium", "high"}:
            self.java_mlk_source_confidence_min = "low"
        self.java_mlk_issue_merge_hops = 2
        self.java_mlk_report_signatures: Set[Tuple[object, ...]] = set()
        self.java_mlk_source_coverage_stats: Dict[str, object] = {}

        self.src_values, self.sink_values = self.extractor.extract_all()
        self.java_mlk_source_obligation_keys: Dict[str, str] = {}
        self.java_mlk_source_obligation_family_keys: Dict[str, str] = {}
        self.java_mlk_source_obligation_component_keys: Dict[str, str] = {}
        self.java_mlk_source_instances_by_key: Dict[str, SourceInstance] = {}
        self.java_mlk_source_component_id_by_key: Dict[str, int] = {}
        self.java_mlk_issue_components: List[IssueComponent] = []
        self.java_mlk_component_selection: Dict[int, List[Value]] = {}
        if self.language == "Java" and self.bug_type == "MLK":
            self.java_mlk_source_coverage_stats = (
                self.__build_java_mlk_source_coverage_stats(self.src_values)
            )
        if self.language == "Java" and self.bug_type == "MLK":
            self.java_mlk_source_obligation_keys = (
                self.__build_java_mlk_source_obligation_index(self.src_values)
            )
            self.java_mlk_source_obligation_family_keys = (
                self.__build_java_mlk_source_obligation_family_index(
                    self.src_values,
                    self.java_mlk_source_obligation_keys,
                )
            )
            self.java_mlk_source_obligation_component_keys = (
                self.__build_java_mlk_source_obligation_component_index(
                    self.src_values,
                    self.java_mlk_source_obligation_keys,
                )
            )
            obligation_count = len(set(self.java_mlk_source_obligation_keys.values()))
            obligation_family_count = len(
                set(self.java_mlk_source_obligation_family_keys.values())
            )
            obligation_component_count = len(
                set(self.java_mlk_source_obligation_component_keys.values())
            )
            self.logger.print_console(
                f"Java MLK obligations inferred: {obligation_count} from {len(self.src_values)} source(s)."
            )
            self.logger.print_console(
                f"Java MLK obligation families inferred: {obligation_family_count}"
            )
            self.logger.print_console(
                f"Java MLK obligation components inferred: {obligation_component_count}"
            )
            (
                self.java_mlk_source_instances_by_key,
                self.java_mlk_issue_components,
                self.java_mlk_component_selection,
            ) = self.__build_java_mlk_issue_components_pre_llm(self.src_values)
            self.java_mlk_source_component_id_by_key = {}
            for component in self.java_mlk_issue_components:
                for src_key in component.member_source_keys:
                    self.java_mlk_source_component_id_by_key[src_key] = (
                        component.component_id
                    )
            self.logger.print_console(
                "Java MLK issue-first pre-clustering:",
                f"components={len(self.java_mlk_issue_components)}",
                f"selected_sources={sum(len(v) for v in self.java_mlk_component_selection.values())}",
            )
            if len(self.java_mlk_source_coverage_stats) > 0:
                self.logger.print_console(
                    "Java MLK source coverage:",
                    f"files_with_sources={self.java_mlk_source_coverage_stats.get('files_with_sources', 0)}",
                    f"total_java_files={self.java_mlk_source_coverage_stats.get('total_java_files', 0)}",
                )
        self.state = DFBScanState(self.src_values, self.sink_values)
        return

    def __obtain_extractor(self) -> DFBScanExtractor:
        if self.language == "Cpp":
            if self.bug_type == "MLK":
                return Cpp_MLK_Extractor(self.ts_analyzer)
            elif self.bug_type == "NPD":
                return Cpp_NPD_Extractor(self.ts_analyzer)
            elif self.bug_type == "UAF":
                return Cpp_UAF_Extractor(self.ts_analyzer)
        elif self.language == "Java":
            if self.bug_type == "MLK":
                return Java_MLK_Extractor(self.ts_analyzer)
            elif self.bug_type == "NPD":
                return Java_NPD_Extractor(self.ts_analyzer)
        elif self.language == "Python":
            if self.bug_type == "NPD":
                return Python_NPD_Extractor(self.ts_analyzer)
        elif self.language == "Go":
            if self.bug_type == "NPD":
                return Go_NPD_Extractor(self.ts_analyzer)
        raise NotImplementedError(
            f"Unsupported bug type: {self.bug_type} in {self.language}"
        )

    def __update_worklist(
        self,
        input: IntraDataFlowAnalyzerInput,
        output: IntraDataFlowAnalyzerOutput,
        call_context: CallContext,
        path_index: int,
    ) -> List[Tuple[Value, Function, CallContext]]:
        """
        Update the worklist based on the output of intra-procedural data-flow analysis.
        :param input: The input of intra-procedural data-flow analysis
        :param output: The output of intra-procedural data-flow analysis
        :param call_context: The call context of the current function
        :return: The updated worklist
        """
        delta_worklist = []  # The list of (value, function, call_context) tuples
        function_id = input.function.function_id
        function = self.ts_analyzer.function_env[function_id]

        for value in output.reachable_values[path_index]:
            if value.label == ValueLabel.ARG:
                if (
                    self.language == "Java"
                    and self.bug_type == "MLK"
                    and self.java_mlk_validator is not None
                    and self.java_mlk_validator.is_non_ownership_argument(
                        value, function
                    )
                ):
                    # Prune helper-style non-ownership argument propagation
                    # (e.g., tempFile.toString() -> IO.writeLine(value))
                    # to avoid exploding no-sink leaf paths in utility methods.
                    continue

                callee_functions = self.ts_analyzer.get_all_callee_functions(function)
                for callee_function in callee_functions:
                    is_called = False
                    call_sites = self.ts_analyzer.get_callsites_by_callee_function(
                        function, callee_function
                    )
                    call_site_line_number = -1
                    for call_site_node in call_sites:
                        file_content = self.ts_analyzer.code_in_files[
                            function.file_path
                        ]
                        call_site_lower_line_number = (
                            file_content[: call_site_node.start_byte].count("\n") + 1
                        )
                        call_site_upper_line_number = (
                            file_content[: call_site_node.end_byte].count("\n") + 1
                        )
                        arg_line_number_in_file = value.line_number
                        if (
                            call_site_lower_line_number <= arg_line_number_in_file
                            and arg_line_number_in_file <= call_site_upper_line_number
                        ):
                            is_called = True
                            call_site_line_number = call_site_lower_line_number
                    if not is_called:
                        continue

                    new_call_context = copy.deepcopy(call_context)
                    context_label = ContextLabel(
                        self.ts_analyzer.functionToFile[function.function_id],
                        call_site_line_number,
                        callee_function.function_id,
                        Parenthesis.LEFT_PAR,
                    )
                    is_CFL_reachable = new_call_context.add_and_check_context(
                        context_label
                    )
                    if not is_CFL_reachable:
                        continue

                    if callee_function.paras is not None:
                        for para in callee_function.paras:
                            if para.index == value.index:
                                delta_worklist.append(
                                    (para, callee_function, new_call_context)
                                )
                                self.state.update_external_value_match(
                                    (value, call_context),
                                    set({(para, new_call_context)}),
                                )

            if value.label == ValueLabel.PARA:
                # For Java MLK, PARA->ARG side-effect back propagation introduces
                # cyclic caller/callee hops (e.g., run->traceResource->run) and
                # leads to duplicate helper-only paths. MLK only needs ARG->PARA
                # forward propagation to judge close-leak.
                if self.language == "Java" and self.bug_type == "MLK":
                    continue

                # Consider side-effect.
                # Example: the parameter *p is used in the function: p->f = null;
                # We need to consider the side-effect of p.
                caller_functions = self.ts_analyzer.get_all_caller_functions(function)
                for caller_function in caller_functions:
                    new_call_context = copy.deepcopy(call_context)
                    top_unmatched_context_label = (
                        new_call_context.get_top_unmatched_context_label()
                    )

                    call_site_nodes = self.ts_analyzer.get_callsites_by_callee_function(
                        caller_function, function
                    )
                    for call_site_node in call_site_nodes:
                        caller_function_file_name = self.ts_analyzer.functionToFile[
                            caller_function.function_id
                        ]
                        file_content = self.ts_analyzer.code_in_files[
                            caller_function_file_name
                        ]
                        call_site_lower_line_number = (
                            file_content[: call_site_node.start_byte].count("\n") + 1
                        )

                        if top_unmatched_context_label is not None:
                            if (
                                top_unmatched_context_label.parenthesis
                                == Parenthesis.LEFT_PAR
                            ):
                                if (
                                    call_site_lower_line_number
                                    != top_unmatched_context_label.line_number
                                    or caller_function_file_name
                                    != top_unmatched_context_label.file_name
                                    or top_unmatched_context_label.function_id
                                    != function.function_id
                                ):
                                    continue

                        append_context_label = ContextLabel(
                            caller_function_file_name,
                            call_site_lower_line_number,
                            function.function_id,
                            Parenthesis.RIGHT_PAR,
                        )
                        new_call_context.add_and_check_context(append_context_label)

                        args = self.ts_analyzer.get_arguments_at_callsite(
                            caller_function, call_site_node
                        )
                        for arg in args:
                            if arg.index == value.index:
                                delta_worklist.append(
                                    (arg, caller_function, new_call_context)
                                )
                                self.state.update_external_value_match(
                                    (value, call_context),
                                    set({(arg, new_call_context)}),
                                )

            if value.label == ValueLabel.RET:
                caller_functions = self.ts_analyzer.get_all_caller_functions(function)
                for caller_function in caller_functions:
                    new_call_context = copy.deepcopy(call_context)
                    top_unmatched_context_label = (
                        new_call_context.get_top_unmatched_context_label()
                    )

                    call_site_nodes = self.ts_analyzer.get_callsites_by_callee_function(
                        caller_function, function
                    )
                    for call_site_node in call_site_nodes:
                        caller_function_file_name = self.ts_analyzer.functionToFile[
                            caller_function.function_id
                        ]
                        file_content = self.ts_analyzer.code_in_files[
                            caller_function_file_name
                        ]
                        call_site_lower_line_number = (
                            file_content[: call_site_node.start_byte].count("\n") + 1
                        )

                        if top_unmatched_context_label is not None:
                            if (
                                top_unmatched_context_label.parenthesis
                                == Parenthesis.LEFT_PAR
                            ):
                                if (
                                    call_site_lower_line_number
                                    != top_unmatched_context_label.line_number
                                    or caller_function_file_name
                                    != top_unmatched_context_label.file_name
                                    or top_unmatched_context_label.function_id
                                    != function.function_id
                                ):
                                    continue

                        append_context_label = ContextLabel(
                            caller_function_file_name,
                            call_site_lower_line_number,
                            function.function_id,
                            Parenthesis.RIGHT_PAR,
                        )
                        new_call_context.add_and_check_context(append_context_label)

                        output_value = self.ts_analyzer.get_output_value_at_callsite(
                            caller_function, call_site_node
                        )
                        delta_worklist.append(
                            (output_value, caller_function, new_call_context)
                        )
                        self.state.update_external_value_match(
                            (value, call_context),
                            set({(output_value, new_call_context)}),
                        )

            if value.label == ValueLabel.SINK:
                # No need to continue the exploration
                pass
        return delta_worklist

    def __collect_potential_buggy_paths(
        self,
        src_value: Value,
        current_value_with_context: Tuple[Value, CallContext],
        path_with_unknown_status: Optional[List[Value]] = None,
        visited_nodes: Optional[Set[Tuple[Value, CallContext]]] = None,
    ) -> None:
        """
        Recursively collect potential buggy paths based on the propagation details.

        This function updates the state with buggy paths if the propagation from the source
        meets the criteria based on the bug type (reachability). If the current_value_with_context
        is neither in reachable values nor in external value matches, it returns immediately.

        Args:
            src_value (Value):
                The source value from which the propagation starts.
            current_value_with_context (Tuple[Value, CallContext]):
                The current value along with its call context.
            path_with_unknown_status (List[Value], optional):
                The propagation path accumulated so far.
        """
        if path_with_unknown_status is None:
            path_with_unknown_status = []
        if visited_nodes is None:
            visited_nodes = set()
        if current_value_with_context in visited_nodes:
            # Guard recursive graph traversal from revisiting the same node in
            # one DFS chain (mutual recursion / cyclic external edges).
            return
        next_visited_nodes = set(visited_nodes)
        next_visited_nodes.add(current_value_with_context)

        reachable_values_snapshot = self.state.reachable_values_per_path
        source_executed_snapshot = self.state.source_executed_per_path
        release_context_snapshot = self.state.release_context_per_path
        guarantee_level_snapshot = self.state.guarantee_level_per_path
        external_match_snapshot = self.state.external_value_match

        # If no propagation information exists for the current value, stop further processing.
        if (
            current_value_with_context not in reachable_values_snapshot
            and current_value_with_context not in external_match_snapshot
        ):
            return

        # Process if the current value has reachable paths.
        if current_value_with_context in reachable_values_snapshot:
            reachable_values_paths: List[Set[Tuple[Value, CallContext]]] = (
                reachable_values_snapshot[current_value_with_context]
            )
            if self.language == "Java" and self.bug_type == "MLK":
                # Java-MLK must keep branch semantics. Process each path_set independently.
                seen_continue_edges = set()
                ignore_empty_non_executed_return_branch = (
                    self.__is_non_executed_return_branch(
                        current_value_with_context, reachable_values_paths
                    )
                )
                source_executed_paths = source_executed_snapshot.get(
                    current_value_with_context, []
                )
                release_context_paths = release_context_snapshot.get(
                    current_value_with_context, []
                )
                guarantee_level_paths = guarantee_level_snapshot.get(
                    current_value_with_context, []
                )
                src_resource_kind = self.__infer_java_mlk_resource_kind(src_value)
                for path_index, path_set in enumerate(reachable_values_paths):
                    source_executed = True
                    if path_index < len(source_executed_paths):
                        source_executed = source_executed_paths[path_index]
                    release_context = RELEASE_CONTEXT_UNKNOWN
                    if path_index < len(release_context_paths):
                        release_context = normalize_release_context(
                            release_context_paths[path_index]
                        )
                    guarantee_level = GUARANTEE_NONE
                    if path_index < len(guarantee_level_paths):
                        guarantee_level = normalize_guarantee_level(
                            guarantee_level_paths[path_index]
                        )
                    if not path_set:
                        if not source_executed:
                            # This branch does not execute the source. Do not treat it
                            # as a leak/no-propagation terminal.
                            continue
                        if self.__should_skip_java_temp_nonsrv_no_sink_branch(
                            src_value=src_value,
                            current_value_with_context=current_value_with_context,
                            path_index=path_index,
                            reachable_values_paths=reachable_values_paths,
                            release_context_paths=release_context_paths,
                            guarantee_level_paths=guarantee_level_paths,
                            resource_kind=src_resource_kind,
                        ):
                            self.logger.print_log(
                                "Skip Java MLK no-sink branch candidate",
                                "reason=temp_non_servlet_sibling_deleteOnExit_profile",
                                f"path_index={path_index}",
                                f"source={str(src_value)}",
                            )
                            continue
                        if ignore_empty_non_executed_return_branch:
                            continue
                        if not self.is_reachable:
                            has_sibling_continue = False
                            current_value, _ = current_value_with_context
                            if current_value.label in {ValueLabel.OUT, ValueLabel.PARA}:
                                has_sibling_continue = (
                                    self.__has_sibling_continue_external_edge(
                                        reachable_values_paths,
                                        external_match_snapshot,
                                    )
                                )
                            pure_empty_passthrough = (
                                has_sibling_continue
                                or
                                current_value_with_context in external_match_snapshot
                                or self.__has_sibling_continue_arg_for_para(
                                    current_value_with_context,
                                    reachable_values_snapshot,
                                    external_match_snapshot,
                                )
                            )
                            if not pure_empty_passthrough:
                                candidate_path = (
                                    self.__build_java_mlk_empty_branch_candidate_path(
                                        src_value,
                                        current_value_with_context,
                                        path_with_unknown_status,
                                        path_index,
                                        src_resource_kind,
                                        release_context,
                                        guarantee_level,
                                    )
                                )
                                self.state.update_potential_buggy_paths(
                                    src_value, candidate_path
                                )
                        continue

                    continue_edges: List[
                        Tuple[
                            Tuple[Value, CallContext],
                            Set[Tuple[Value, CallContext]],
                        ]
                    ] = []
                    terminal_edges: List[Tuple[Value, CallContext]] = []
                    sink_edges: List[Tuple[Value, CallContext]] = []

                    for value, ctx in path_set:
                        if value.label == ValueLabel.SINK:
                            sink_edges.append((value, ctx))
                            continue

                        if value.label in {
                            ValueLabel.PARA,
                            ValueLabel.RET,
                            ValueLabel.ARG,
                            ValueLabel.OUT,
                        }:
                            external_ends = external_match_snapshot.get((value, ctx))
                            if external_ends:
                                continue_edges.append(((value, ctx), external_ends))
                            else:
                                terminal_edges.append((value, ctx))

                    # Per-path-set priority:
                    # 1) Sink on this branch means this branch closes; do not continue this branch.
                    # 2) Continue edges.
                    # 3) Terminal edges (Case 1 / Case 2).
                    # 4) Empty/no-propagation branch already handled by the empty path_set block.
                    if sink_edges and not self.is_reachable:
                        refined_release_context, refined_guarantee_level = (
                            self.__refine_java_mlk_release_semantics(
                                src_value,
                                src_resource_kind,
                                sink_edges,
                                release_context,
                                guarantee_level,
                            )
                        )
                        if is_all_exit_guaranteed(refined_guarantee_level):
                            continue
                        seen_sink_values = set()
                        for sink_value, _ in sink_edges:
                            sink_key = str(sink_value)
                            if sink_key in seen_sink_values:
                                continue
                            seen_sink_values.add(sink_key)
                            candidate_path = (
                                self.__build_java_mlk_sink_branch_candidate_path(
                                    src_value,
                                    path_with_unknown_status,
                                    sink_value,
                                    path_index,
                                    src_resource_kind,
                                    refined_release_context,
                                    refined_guarantee_level,
                                )
                            )
                            self.state.update_potential_buggy_paths(
                                src_value, candidate_path
                            )
                        continue

                    if continue_edges:
                        for (value, ctx), external_ends in continue_edges:
                            for value_next, ctx_next in external_ends:
                                edge_key = ((value, ctx), (value_next, ctx_next))
                                if edge_key in seen_continue_edges:
                                    continue
                                seen_continue_edges.add(edge_key)
                                self.__collect_potential_buggy_paths(
                                    src_value,
                                    (value_next, ctx_next),
                                    path_with_unknown_status + [value, value_next],
                                    next_visited_nodes,
                                )
                        continue

                    if terminal_edges:
                        if current_value_with_context in external_match_snapshot:
                            continue
                        seen_terminals = set()
                        for terminal_value, terminal_ctx in terminal_edges:
                            terminal_key = (terminal_value, terminal_ctx)
                            if terminal_key in seen_terminals:
                                continue
                            seen_terminals.add(terminal_key)
                            transfer_kind, reason, transfer_rule = (
                                self.__classify_java_mlk_external_termination(
                                    terminal_value
                                )
                            )
                            if transfer_kind == "no_real_transfer":
                                candidate_path = (
                                    self.__build_java_mlk_terminal_branch_candidate_path(
                                        src_value,
                                        path_with_unknown_status,
                                        terminal_value,
                                        path_index,
                                        src_resource_kind,
                                        release_context,
                                        guarantee_level,
                                    )
                                )
                                self.state.update_potential_buggy_paths(
                                    src_value, candidate_path
                                )
                            else:
                                transfer_path = path_with_unknown_status + [terminal_value]
                                if src_value not in transfer_path:
                                    transfer_path = [src_value] + transfer_path
                                self.__record_java_mlk_transfer(
                                    src_value,
                                    transfer_path,
                                    reason,
                                    terminal_value=terminal_value,
                                    rule_hit=transfer_rule,
                                )
                        continue
            else:
                for path_set in reachable_values_paths:
                    if not path_set:
                        # For memory leak-style bug types we only update when the path is empty.
                        if not self.is_reachable:
                            self.state.update_potential_buggy_paths(
                                src_value, path_with_unknown_status + [src_value]
                            )
                        continue

                    # First pass: classify all values in this path_set.
                    continue_edges: List[
                        Tuple[
                            Tuple[Value, CallContext],
                            Set[Tuple[Value, CallContext]],
                        ]
                    ] = []
                    terminal_edges: List[Tuple[Value, CallContext]] = []
                    sink_edges: List[Tuple[Value, CallContext]] = []

                    for value, ctx in path_set:
                        if value.label == ValueLabel.SINK:
                            sink_edges.append((value, ctx))
                            continue

                        if value.label in {
                            ValueLabel.PARA,
                            ValueLabel.RET,
                            ValueLabel.ARG,
                            ValueLabel.OUT,
                        }:
                            external_ends = external_match_snapshot.get((value, ctx))
                            if external_ends:
                                continue_edges.append(((value, ctx), external_ends))
                            else:
                                terminal_edges.append((value, ctx))

                    # Second pass (priority):
                    #   1) Continue edges first.
                    #   2) Sink edges.
                    if continue_edges:
                        for (value, ctx), external_ends in continue_edges:
                            for value_next, ctx_next in external_ends:
                                self.__collect_potential_buggy_paths(
                                    src_value,
                                    (value_next, ctx_next),
                                    path_with_unknown_status + [value, value_next],
                                    next_visited_nodes,
                                )
                        continue

                    if sink_edges:
                        if self.is_reachable:
                            for sink_value, _ in sink_edges:
                                self.state.update_potential_buggy_paths(
                                    src_value, path_with_unknown_status + [sink_value]
                                )
                        continue

        # Process if the current value has external value matches.
        if current_value_with_context in external_match_snapshot:
            for value_next, ctx_next in external_match_snapshot[
                current_value_with_context
            ]:
                value, _ = current_value_with_context
                self.__collect_potential_buggy_paths(
                    src_value,
                    (value_next, ctx_next),
                    path_with_unknown_status + [value, value_next],
                    next_visited_nodes,
                )
        return

    def start_scan(self) -> None:
        self.logger.print_console("Start data-flow bug scanning in parallel...")
        self.logger.print_console(f"Max number of workers: {self.max_neural_workers}")
        if self.language == "Java" and self.bug_type == "MLK":
            self.logger.print_console(
                "Java MLK mode:",
                f"issue_first={self.java_mlk_issue_first}",
                f"max_witness={self.java_mlk_max_witness_per_component}",
                f"family_link={self.java_mlk_family_link_mode}",
                f"source_conf_min={self.java_mlk_source_confidence_min}",
            )
        src_values_to_process: List[Value] = list(self.src_values)
        if self.language == "Java" and self.bug_type == "MLK" and self.java_mlk_issue_first:
            selected_values: List[Value] = []
            for component in self.java_mlk_issue_components:
                selected_values.extend(
                    self.java_mlk_component_selection.get(component.component_id, [])
                )
            if len(selected_values) > 0:
                unique: Dict[str, Value] = {}
                for src_value in selected_values:
                    unique[str(src_value)] = src_value
                src_values_to_process = list(unique.values())
                self.logger.print_console(
                    "Java MLK issue-first source selection:",
                    f"raw_sources={len(self.src_values)}",
                    f"selected_sources={len(src_values_to_process)}",
                    f"components={len(self.java_mlk_issue_components)}",
                )

        # Total number of source values
        total_src_values = len(src_values_to_process)

        # Process each source value in parallel with a progress bar
        with tqdm(
            total=total_src_values, desc="Processing Source Values", unit="src"
        ) as pbar:
            with ThreadPoolExecutor(max_workers=self.max_neural_workers) as executor:
                futures = [
                    executor.submit(self.__process_src_value, src_value)
                    for src_value in src_values_to_process
                ]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        self.logger.print_log("Error processing source value:", e)
                    finally:
                        # Update the progress bar after each source value is processed
                        pbar.update(1)

        # Final summary
        total_bug_number = self.__write_detect_outputs()
        self.logger.print_console(
            f"{total_bug_number} bug(s) was/were detected in total."
        )
        self.logger.print_console(
            f"The bug report(s) has/have been dumped to {self.res_dir_path}/detect_info.json"
        )
        self.logger.print_console(
            f"File-level merged view has been dumped to {self.res_dir_path}/detect_info_by_file.json"
        )
        if self.language == "Java" and self.bug_type == "MLK":
            self.logger.print_console(
                f"Raw evidence view has been dumped to {self.res_dir_path}/detect_info_raw.json"
            )
        self.logger.print_console("The log files are as follows:")
        for log_file in self.get_log_files():
            self.logger.print_console(log_file)
        self.logger.print_console(
            f"Soot source-level skipped source(s): {self.soot_prefilter_source_skipped}"
        )
        self.__dump_java_mlk_source_coverage_stats()
        self.__dump_java_mlk_transfer_records()
        self.__dump_soot_source_gate_events()
        self.__dump_soot_prefilter_stats()
        self.__dump_z3_prefilter_stats()
        scan_total_sec = max(0.0, time.perf_counter() - self.scan_started_at)
        self.__dump_run_metrics(scan_total_sec)
        return

    def __process_src_value(self, src_value: Value) -> None:
        worklist = []
        src_function = self.ts_analyzer.get_function_from_localvalue(src_value)
        if src_function is None:
            return
        if self.__skip_source_by_java_soot_prefilter(src_value, src_function):
            return
        initial_context = CallContext(False)
        root_resource_kind = self.__infer_java_mlk_resource_kind(src_value)

        worklist.append((src_value, src_function, initial_context))
        queued_state_keys = {(src_value, initial_context)}
        processed_state_keys = set()
        while len(worklist) > 0:
            (start_value, start_function, call_context) = worklist.pop(0)
            current_state_key = (start_value, call_context)
            if current_state_key in processed_state_keys:
                continue
            processed_state_keys.add(current_state_key)
            if len(call_context.context) >= self.call_depth:
                continue

            # Construct the input for intra-procedural data-flow analysis
            sinks_in_function = self.extractor.extract_sinks(start_function)
            sink_values = [
                (sink.name, sink.line_number - start_function.start_line_number + 1)
                for sink in sinks_in_function
            ]

            call_statements = []
            for call_site_node in start_function.function_call_site_nodes:
                file_content = self.ts_analyzer.code_in_files[start_function.file_path]
                call_site_line_number = (
                    file_content[: call_site_node.start_byte].count("\n") + 1
                )
                call_site_name = file_content[
                    call_site_node.start_byte : call_site_node.end_byte
                ]
                call_statements.append((call_site_name, call_site_line_number))

            ret_values = [
                (ret.name, ret.line_number - start_function.start_line_number + 1)
                for ret in (
                    start_function.retvals if start_function.retvals is not None else []
                )
            ]
            df_input = IntraDataFlowAnalyzerInput(
                start_function,
                start_value,
                sink_values,
                call_statements,
                ret_values,
                resource_kind=root_resource_kind,
                resource_rules=self.__build_java_mlk_intra_rules(
                    root_resource_kind, src_value.file
                ),
            )

            # Invoke the intra-procedural data-flow analysis
            df_output = self.intra_dfa.invoke(df_input, IntraDataFlowAnalyzerOutput)

            if df_output is None:
                continue

            for path_index in range(len(df_output.reachable_values)):
                reachable_values_in_single_path = set([])
                for value in df_output.reachable_values[path_index]:
                    reachable_values_in_single_path.add((value, call_context))
                self.state.update_reachable_values_per_path(
                    (start_value, call_context), reachable_values_in_single_path
                )
                source_executed = True
                if path_index < len(df_output.source_executed_per_path):
                    source_executed = df_output.source_executed_per_path[path_index]
                self.state.update_source_executed_per_path(
                    (start_value, call_context), source_executed
                )
                path_line_numbers: List[int] = []
                if path_index < len(df_output.path_line_numbers_per_path):
                    path_line_numbers = df_output.path_line_numbers_per_path[path_index]
                self.state.update_path_line_numbers_per_path(
                    (start_value, call_context), path_line_numbers
                )
                release_context = RELEASE_CONTEXT_UNKNOWN
                if path_index < len(df_output.release_context_per_path):
                    release_context = normalize_release_context(
                        df_output.release_context_per_path[path_index]
                    )
                guarantee_level = GUARANTEE_NONE
                if path_index < len(df_output.guarantee_level_per_path):
                    guarantee_level = normalize_guarantee_level(
                        df_output.guarantee_level_per_path[path_index]
                    )
                self.state.update_release_context_per_path(
                    (start_value, call_context), release_context
                )
                self.state.update_guarantee_level_per_path(
                    (start_value, call_context), guarantee_level
                )

                delta_worklist = self.__update_worklist(
                    df_input, df_output, call_context, path_index
                )
                for next_value, next_function, next_context in delta_worklist:
                    if len(next_context.context) >= self.call_depth:
                        continue
                    next_state_key = (next_value, next_context)
                    if next_state_key in processed_state_keys:
                        continue
                    if next_state_key in queued_state_keys:
                        continue
                    worklist.append((next_value, next_function, next_context))
                    queued_state_keys.add(next_state_key)

        # Collect potential buggy paths
        self.__collect_potential_buggy_paths(src_value, (src_value, CallContext(False)))

        # If no potential buggy paths are found, return early
        if src_value not in self.state.potential_buggy_paths:
            return

        # Validate buggy paths and generate bug reports
        buggy_paths = self.__filter_redundant_java_mlk_paths(
            src_value, self.state.potential_buggy_paths[src_value]
        )
        seen_path_validator_signatures: Set[Tuple[object, ...]] = set()
        if self.language == "Java" and self.bug_type == "MLK" and len(buggy_paths) > 50:
            self.logger.print_log(
                "High Java MLK candidate-path volume",
                f"source={str(src_value)}",
                f"paths={len(buggy_paths)}",
            )
        pending_fallback_candidates: Dict[Tuple[object, ...], Dict[str, object]] = {}
        accepted_issue_signatures: Set[Tuple[object, ...]] = set()

        def _build_candidate_relevant_functions(
            candidate_path: List[Value],
            value_to_function: Dict[Value, Optional[Function]],
        ) -> Dict[int, Function]:
            relevant_functions: Dict[int, Function] = {}
            for value in candidate_path:
                function = value_to_function.get(value)
                if function is None:
                    function = self.ts_analyzer.get_function_from_localvalue(value)
                if function is not None:
                    relevant_functions[function.function_id] = function
            return relevant_functions

        def _try_emit_reachable_candidate(
            candidate_path: List[Value],
            value_to_function: Dict[Value, Optional[Function]],
            explanation: str,
            resource_kind: str,
            release_context: str,
            guarantee_level: str,
        ) -> Tuple[bool, Optional[Tuple[object, ...]]]:
            passed_post_validation, reason = self.__post_validate_java_mlk_with_objid(
                src_value, candidate_path, value_to_function
            )
            if not passed_post_validation:
                self.logger.print_log(
                    f"Skip candidate after Java MLK ownership validation: {reason}"
                )
                return False, None

            relevant_functions = _build_candidate_relevant_functions(
                candidate_path,
                value_to_function,
            )
            if not self.__should_keep_java_mlk_source_by_confidence(
                src_value, candidate_path
            ):
                self.logger.print_log(
                    "Skip Java MLK candidate due to source confidence gate:",
                    f"source={str(src_value)}",
                    f"min={self.java_mlk_source_confidence_min}",
                    f"actual={self.__infer_java_mlk_source_confidence(src_value)}",
                )
                return False, None

            issue_signature = self.__build_java_mlk_issue_signature(
                src_value,
                resource_kind=resource_kind,
                guarantee_level=guarantee_level,
            )
            accepted_issue_signatures.add(issue_signature)

            if not self.__register_java_mlk_report_signature(
                src_value,
                relevant_functions,
            ):
                return True, issue_signature

            bug_report = BugReport(
                self.bug_type,
                src_value,
                relevant_functions,
                explanation,
                metadata=self.__build_java_mlk_report_metadata(
                    src_value=src_value,
                    buggy_path=candidate_path,
                    relevant_functions=relevant_functions,
                    resource_kind=resource_kind,
                    release_context=release_context,
                    guarantee_level=guarantee_level,
                ),
            )
            self.state.update_bug_report(bug_report)
            self.__write_detect_outputs()
            return True, issue_signature

        for buggy_path_raw in buggy_paths:
            buggy_path = self.__compress_java_mlk_candidate_path(buggy_path_raw)
            values_to_functions = {
                value: self.ts_analyzer.get_function_from_localvalue(value)
                for value in buggy_path
            }

            functions: Set[Function] = set()
            for func in values_to_functions.values():
                if func is not None:
                    functions.add(func)

            if self.state.check_existence(src_value, functions):
                continue

            if self.__skip_by_java_soot_prefilter(
                src_value, buggy_path, values_to_functions
            ):
                continue

            if self.__skip_by_java_z3_prefilter(
                src_value, buggy_path, values_to_functions
            ):
                continue

            (
                path_resource_kind,
                path_release_context,
                path_guarantee_level,
                path_servlet_context,
            ) = self.__extract_java_mlk_path_semantics(src_value, buggy_path)
            if self.language == "Java" and self.bug_type == "MLK":
                pv_signature = self.__build_java_mlk_path_validator_signature(
                    buggy_path,
                    path_resource_kind,
                    path_release_context,
                    path_guarantee_level,
                    path_servlet_context,
                )
                if pv_signature in seen_path_validator_signatures:
                    continue
                seen_path_validator_signatures.add(pv_signature)
            path_semantic_rules = self.__build_java_mlk_path_rules(
                path_resource_kind, path_servlet_context
            )
            pv_input = PathValidatorInput(
                self.bug_type,
                buggy_path,
                values_to_functions,
                resource_kind=path_resource_kind,
                release_context=path_release_context,
                guarantee_level=path_guarantee_level,
                resource_semantic_rules=path_semantic_rules,
                servlet_context=path_servlet_context,
            )
            pv_output = self.path_validator.invoke(pv_input, PathValidatorOutput)

            if pv_output is None:
                continue

            should_strict_by_marker = (
                self.__has_java_mlk_no_sink_marker(buggy_path)
                and self.__is_java_mlk_close_biased_negative(pv_output.explanation_str)
            )
            should_strict_by_semantics = should_trigger_strict_recheck(
                path_release_context, path_guarantee_level
            )
            should_strict_by_explanation = self.__should_force_java_mlk_strict_recheck(
                buggy_path=buggy_path,
                pv_explanation=pv_output.explanation_str,
                release_context=path_release_context,
                guarantee_level=path_guarantee_level,
            )
            if (
                self.language == "Java"
                and self.bug_type == "MLK"
                and not pv_output.is_reachable
                and (
                    should_strict_by_marker
                    or should_strict_by_semantics
                    or should_strict_by_explanation
                )
            ):
                strict_reason = "weak-release-semantics"
                if should_strict_by_marker:
                    strict_reason = "marker-close-bias"
                elif should_strict_by_explanation:
                    strict_reason = "transfer-or-close-bias-explanation"
                self.logger.print_log(
                    "Re-validating Java MLK path with strict branch semantics.",
                    f"reason={strict_reason}",
                    f"release_context={path_release_context}",
                    f"guarantee_level={path_guarantee_level}",
                )
                strict_pv_input = PathValidatorInput(
                    self.bug_type,
                    buggy_path,
                    values_to_functions,
                    strict_branch_semantics=True,
                    resource_kind=path_resource_kind,
                    release_context=path_release_context,
                    guarantee_level=path_guarantee_level,
                    resource_semantic_rules=path_semantic_rules,
                    servlet_context=path_servlet_context,
                )
                strict_pv_output = self.path_validator.invoke(
                    strict_pv_input, PathValidatorOutput
                )
                if strict_pv_output is not None:
                    pv_output = strict_pv_output

            if (
                self.language == "Java"
                and self.bug_type == "MLK"
                and not pv_output.is_reachable
                and self.__should_accept_java_mlk_no_sink_fallback(
                    buggy_path=buggy_path,
                    pv_explanation=pv_output.explanation_str,
                    guarantee_level=path_guarantee_level,
                )
            ):
                fallback_explanation = (
                    pv_output.explanation_str
                    + "\n\nFallback: no-sink/weak-release branch is treated as leak-reachable."
                )
                issue_signature = self.__build_java_mlk_issue_signature(
                    src_value,
                    resource_kind=path_resource_kind,
                    guarantee_level=path_guarantee_level,
                )
                previous_candidate = pending_fallback_candidates.get(issue_signature)
                should_replace = False
                if previous_candidate is None:
                    should_replace = True
                else:
                    previous_path = cast(List[Value], previous_candidate["buggy_path"])
                    if len(buggy_path) < len(previous_path):
                        should_replace = True
                if should_replace:
                    pending_fallback_candidates[issue_signature] = {
                        "buggy_path": list(buggy_path),
                        "values_to_functions": dict(values_to_functions),
                        "explanation": fallback_explanation,
                        "resource_kind": path_resource_kind,
                        "release_context": path_release_context,
                        "guarantee_level": path_guarantee_level,
                    }
                self.logger.print_log(
                    "Queue Java MLK candidate by no-sink fallback (deferred).",
                    f"source={str(src_value)}",
                    f"guarantee_level={path_guarantee_level}",
                )
                continue

            if pv_output.is_reachable:
                _reported, _issue_signature = _try_emit_reachable_candidate(
                    candidate_path=buggy_path,
                    value_to_function=values_to_functions,
                    explanation=pv_output.explanation_str,
                    resource_kind=path_resource_kind,
                    release_context=path_release_context,
                    guarantee_level=path_guarantee_level,
                )
                continue

        for issue_signature, pending_candidate in pending_fallback_candidates.items():
            if issue_signature in accepted_issue_signatures:
                continue
            self.logger.print_log(
                "Accept Java MLK candidate by no-sink fallback (deferred).",
                f"source={str(src_value)}",
            )
            pending_buggy_path = cast(List[Value], pending_candidate["buggy_path"])
            pending_values_to_functions = cast(
                Dict[Value, Optional[Function]],
                pending_candidate["values_to_functions"],
            )
            pending_explanation = str(pending_candidate["explanation"])
            pending_resource_kind = str(pending_candidate["resource_kind"])
            pending_release_context = str(pending_candidate["release_context"])
            pending_guarantee_level = str(pending_candidate["guarantee_level"])
            _try_emit_reachable_candidate(
                candidate_path=pending_buggy_path,
                value_to_function=pending_values_to_functions,
                explanation=pending_explanation,
                resource_kind=pending_resource_kind,
                release_context=pending_release_context,
                guarantee_level=pending_guarantee_level,
            )
        return

    def __classify_java_mlk_external_termination(
        self, value: Value
    ) -> Tuple[str, str, str]:
        """
        Classify terminal external-style values for Java MLK when no external match exists.
        Return:
          - ("no_real_transfer", reason, rule_hit): should be treated as leak candidate
          - ("ownership_transfer", reason, rule_hit): ownership transfer and stop reporting
        """
        function = self.ts_analyzer.get_function_from_localvalue(value)
        line_text = self.ts_analyzer.get_content_by_line_number(
            value.line_number, value.file
        )
        method_name = function.function_name.lower() if function is not None else ""

        if value.label == ValueLabel.ARG and self.java_mlk_validator is not None:
            if self.java_mlk_validator.is_non_ownership_argument(value, function):
                return (
                    "no_real_transfer",
                    "argument does not imply ownership transfer (e.g., println/logging)",
                    "arg_non_ownership",
                )
            return (
                "ownership_transfer",
                "argument likely transfers ownership but inter-procedural chain is missing",
                "arg_transfer_method",
            )

        if value.label in {ValueLabel.RET, ValueLabel.OUT, ValueLabel.PARA}:
            transfer_name_hints = {
                "put",
                "add",
                "set",
                "register",
                "cache",
                "store",
                "save",
                "attach",
                "bind",
                "subscribe",
            }
            return_transfer_hints = {
                "create",
                "open",
                "build",
                "new",
                "factory",
                "provider",
                "get",
            }
            if any(hint in method_name for hint in transfer_name_hints):
                return (
                    "ownership_transfer",
                    "terminal value appears in explicit transfer-style method",
                    "method_name_transfer_hint",
                )
            if value.label == ValueLabel.RET and any(
                hint in method_name for hint in return_transfer_hints
            ):
                return (
                    "ownership_transfer",
                    "return from factory/provider style method likely transfers ownership",
                    "method_name_return_factory_hint",
                )
            if value.label == ValueLabel.RET and "return " in line_text:
                # Keep return as possible transfer only when direct factory call appears.
                if re.search(r"\b(?:new|open|get|create)[A-Za-z0-9_]*\s*\(", line_text):
                    return (
                        "ownership_transfer",
                        "return statement directly returns factory-created resource",
                        "return_line_factory_hint",
                    )
            return (
                "no_real_transfer",
                "terminal boundary event has no explicit ownership-transfer evidence",
                "terminal_no_explicit_transfer",
            )

        if value.label == ValueLabel.ARG:
            return (
                "no_real_transfer",
                "argument termination without transfer evidence is treated conservatively",
                "arg_no_transfer_evidence",
            )

        return (
            "ownership_transfer",
            "default ownership transfer",
            "default_transfer",
        )

    def __infer_java_mlk_resource_kind(self, src_value: Value) -> str:
        if self.language != "Java" or self.bug_type != "MLK":
            return RESOURCE_KIND_AUTOCLOSEABLE
        return classify_resource_kind(src_value.name, src_value.file)

    def __build_java_mlk_intra_rules(
        self, resource_kind: str, source_file: str
    ) -> List[str]:
        if self.language != "Java" or self.bug_type != "MLK":
            return []
        return build_intra_resource_rules(
            normalize_resource_kind(resource_kind),
            is_servlet_context(source_file),
        )

    def __build_java_mlk_path_rules(
        self, resource_kind: str, servlet_context: bool
    ) -> List[str]:
        if self.language != "Java" or self.bug_type != "MLK":
            return []
        return build_path_resource_rules(
            normalize_resource_kind(resource_kind), servlet_context
        )

    def __extract_java_mlk_path_semantics(
        self, src_value: Value, path: List[Value]
    ) -> Tuple[str, str, str, bool]:
        resource_kind = self.__infer_java_mlk_resource_kind(src_value)
        release_context = RELEASE_CONTEXT_UNKNOWN
        guarantee_level = GUARANTEE_NONE
        for value in path:
            if value.label != ValueLabel.LOCAL:
                continue
            marker_name = value.name.strip()
            decoded_kind = decode_resource_kind_marker(marker_name)
            if decoded_kind != "":
                resource_kind = decoded_kind
                continue
            decoded_context = decode_release_context_marker(marker_name)
            if decoded_context != "":
                release_context = decoded_context
                continue
            decoded_guarantee = decode_guarantee_level_marker(marker_name)
            if decoded_guarantee != "":
                guarantee_level = decoded_guarantee
                continue

        resource_kind = normalize_resource_kind(resource_kind)
        release_context = normalize_release_context(release_context)
        guarantee_level = normalize_guarantee_level(guarantee_level)
        servlet_context = is_servlet_context(src_value.file)
        return resource_kind, release_context, guarantee_level, servlet_context

    def __infer_java_mlk_report_leak_root_method(
        self,
        src_value: Value,
        relevant_functions: Dict[int, Function],
    ) -> Tuple[str, str]:
        """
        Pick a leak-root method for one report.
        Prefer deepest reachable callee in the relevant subgraph from source method,
        so wrapper/forwarding methods do not dominate issue identity.
        """
        if self.language != "Java" or self.bug_type != "MLK":
            return "", "UNKNOWN_METHOD"

        src_function = self.ts_analyzer.get_function_from_localvalue(src_value)
        src_uid = ""
        src_fid = -1
        if src_function is not None:
            src_uid = (
                src_function.function_uid
                if src_function.function_uid != ""
                else self.__build_java_mlk_function_signature_key(src_function)
            )
            src_fid = src_function.function_id

        if len(relevant_functions) == 0:
            if src_uid != "":
                src_name = src_function.function_name if src_function is not None else "UNKNOWN_METHOD"
                return src_uid, src_name
            return "", "UNKNOWN_METHOD"

        uid_by_fid: Dict[int, str] = {}
        for function in relevant_functions.values():
            function_uid = (
                function.function_uid
                if function.function_uid != ""
                else self.__build_java_mlk_function_signature_key(function)
            )
            uid_by_fid[function.function_id] = function_uid

        relevant_fids = set(uid_by_fid.keys())
        if src_fid in relevant_fids and src_fid >= 0:
            call_out = self.ts_analyzer.function_caller_callee_map
            dist: Dict[int, int] = {src_fid: 0}
            queue: deque[int] = deque([src_fid])
            while len(queue) > 0:
                current = queue.popleft()
                current_dist = dist[current]
                for next_fid in call_out.get(current, set()):
                    if next_fid not in relevant_fids:
                        continue
                    if next_fid in dist:
                        continue
                    dist[next_fid] = current_dist + 1
                    queue.append(next_fid)

            # Prefer farthest reachable methods; if tie, prefer non-helper methods.
            ranked_candidates: List[Tuple[int, int, str, int]] = []
            for candidate_fid, depth in dist.items():
                candidate_function = relevant_functions.get(candidate_fid)
                candidate_uid = uid_by_fid.get(candidate_fid, "")
                if candidate_function is None or candidate_uid == "":
                    continue
                helper_penalty = (
                    1 if self.__is_java_mlk_helper_function_for_dedup(candidate_function) else 0
                )
                # (-depth) for max depth, helper_penalty for non-helper preference.
                ranked_candidates.append(
                    (
                        -depth,
                        helper_penalty,
                        candidate_uid,
                        candidate_function.start_line_number,
                    )
                )
            if len(ranked_candidates) > 0:
                ranked_candidates.sort()
                chosen_uid = ranked_candidates[0][2]
                chosen_fid = next(
                    (fid for fid, uid in uid_by_fid.items() if uid == chosen_uid),
                    src_fid,
                )
                chosen_function = relevant_functions.get(chosen_fid, src_function)
                chosen_name = (
                    chosen_function.function_name
                    if chosen_function is not None
                    else "UNKNOWN_METHOD"
                )
                return chosen_uid, chosen_name

        # Fallback: source method first, then deterministic relevant method.
        if src_uid != "":
            src_name = src_function.function_name if src_function is not None else "UNKNOWN_METHOD"
            return src_uid, src_name
        sorted_fids = sorted(relevant_fids)
        if len(sorted_fids) == 0:
            return "", "UNKNOWN_METHOD"
        fallback_fid = sorted_fids[0]
        fallback_uid = uid_by_fid.get(fallback_fid, "")
        fallback_name = relevant_functions[fallback_fid].function_name
        return fallback_uid, fallback_name

    def __build_java_mlk_report_metadata(
        self,
        src_value: Value,
        buggy_path: List[Value],
        relevant_functions: Dict[int, Function],
        resource_kind: str,
        release_context: str,
        guarantee_level: str,
    ) -> Dict[str, object]:
        if self.language != "Java" or self.bug_type != "MLK":
            return {}

        src_function = self.ts_analyzer.get_function_from_localvalue(src_value)
        src_method_uid = ""
        src_method_name = "UNKNOWN_METHOD"
        if src_function is not None:
            src_method_uid = (
                src_function.function_uid
                if src_function.function_uid != ""
                else self.__build_java_mlk_function_signature_key(src_function)
            )
            src_method_name = src_function.function_name
        obligation_key = self.__get_java_mlk_source_obligation_key(src_value)
        obligation_family_key = self.__get_java_mlk_source_obligation_family_key(
            src_value
        )
        obligation_component_key = self.__get_java_mlk_source_obligation_component_key(
            src_value
        )
        source_component_id = self.java_mlk_source_component_id_by_key.get(
            str(src_value), -1
        )
        leak_root_method_uid, leak_root_method_name = (
            self.__infer_java_mlk_report_leak_root_method(
                src_value,
                relevant_functions,
            )
        )
        source_origin = self.__infer_java_mlk_source_origin(src_value)
        source_confidence = self.__infer_java_mlk_source_confidence(src_value)
        source_symbol = self.__infer_java_mlk_source_symbol(src_value)
        has_no_sink_marker = self.__has_java_mlk_no_sink_marker(buggy_path)
        has_weak_release_marker = self.__has_java_mlk_weak_release_marker(buggy_path)
        metadata: Dict[str, object] = {
            "resource_kind": normalize_resource_kind(resource_kind),
            "release_context": normalize_release_context(release_context),
            "guarantee_level": normalize_guarantee_level(guarantee_level),
            "obligation_key": obligation_key,
            "obligation_family_key": obligation_family_key,
            "obligation_component_key": obligation_component_key,
            "source_component_id": source_component_id,
            "source_line": src_value.line_number,
            "source_file": src_value.file,
            "source_method_uid": src_method_uid,
            "source_method_name": src_method_name,
            "leak_root_method_uid": leak_root_method_uid,
            "leak_root_method_name": leak_root_method_name,
            "source_origin": source_origin,
            "source_confidence": source_confidence,
            "source_symbol": source_symbol,
            "has_no_sink_marker": has_no_sink_marker,
            "has_weak_release_marker": has_weak_release_marker,
            "path_length": len(buggy_path),
            "relevant_method_uids": sorted(
                {
                    (
                        function.function_uid
                        if function.function_uid != ""
                        else self.__build_java_mlk_function_signature_key(function)
                    )
                    for function in relevant_functions.values()
                }
            ),
        }
        return metadata

    def __should_keep_java_mlk_source_by_confidence(
        self, src_value: Value, buggy_path: List[Value]
    ) -> bool:
        if self.language != "Java" or self.bug_type != "MLK":
            return True
        minimum_rank = self.__java_mlk_source_confidence_rank(
            self.java_mlk_source_confidence_min
        )
        source_rank = self.__java_mlk_source_confidence_rank(
            self.__infer_java_mlk_source_confidence(src_value)
        )
        if source_rank >= minimum_rank:
            return True
        # Keep weak/no-sink branches even for lower-confidence sources;
        # they are useful for recall/debug and issue aggregation.
        return self.__has_java_mlk_no_sink_marker(
            buggy_path
        ) or self.__has_java_mlk_weak_release_marker(buggy_path)

    def __refine_java_mlk_release_semantics(
        self,
        src_value: Value,
        resource_kind: str,
        sink_edges: List[Tuple[Value, CallContext]],
        release_context: str,
        guarantee_level: str,
    ) -> Tuple[str, str]:
        refined_context = normalize_release_context(release_context)
        refined_guarantee = normalize_guarantee_level(guarantee_level)
        normalized_kind = normalize_resource_kind(resource_kind)

        sink_names = [sink_value.name.lower() for sink_value, _ in sink_edges]
        has_delete_on_exit = any("deleteonexit" in sink_name for sink_name in sink_names)
        has_delete_if_exists = any(
            "deleteifexists" in sink_name for sink_name in sink_names
        )
        has_direct_delete = any(
            ("delete(" in sink_name) and ("deleteonexit" not in sink_name)
            for sink_name in sink_names
        )
        has_unlock_like = any(
            ("unlock(" in sink_name) or ("tryunlock(" in sink_name) or ("release(" in sink_name)
            for sink_name in sink_names
        )

        if normalized_kind == RESOURCE_KIND_TEMP_RESOURCE:
            if has_delete_on_exit and not (has_delete_if_exists or has_direct_delete):
                if is_servlet_context(src_value.file):
                    return RELEASE_CONTEXT_NORMAL, GUARANTEE_NONE
                return RELEASE_CONTEXT_NORMAL, GUARANTEE_ALL_EXIT_PATHS

        if normalized_kind == RESOURCE_KIND_LOCK:
            if (
                has_unlock_like
                and refined_context not in {RELEASE_CONTEXT_FINALLY, RELEASE_CONTEXT_TWR}
                and refined_guarantee == GUARANTEE_ALL_EXIT_PATHS
            ):
                refined_guarantee = GUARANTEE_NORMAL_ONLY

        return refined_context, refined_guarantee

    def __is_delete_on_exit_only_sink_edges(
        self, sink_edges: List[Tuple[Value, CallContext]]
    ) -> bool:
        if len(sink_edges) == 0:
            return False
        has_delete_on_exit = False
        has_non_delete_on_exit = False
        for sink_value, _ in sink_edges:
            sink_name = sink_value.name.lower()
            if "deleteonexit" in sink_name:
                has_delete_on_exit = True
            else:
                has_non_delete_on_exit = True
        return has_delete_on_exit and not has_non_delete_on_exit

    def __should_skip_java_temp_nonsrv_no_sink_branch(
        self,
        src_value: Value,
        current_value_with_context: Tuple[Value, CallContext],
        path_index: int,
        reachable_values_paths: List[Set[Tuple[Value, CallContext]]],
        release_context_paths: List[str],
        guarantee_level_paths: List[str],
        resource_kind: str,
    ) -> bool:
        """
        Suppress a noisy no-sink branch in non-servlet temp_resource profile
        when a sibling branch already performs deleteOnExit-only cleanup under
        the benchmark policy.
        """
        if normalize_resource_kind(resource_kind) != RESOURCE_KIND_TEMP_RESOURCE:
            return False
        if is_servlet_context(src_value.file):
            return False

        current_value, _ = current_value_with_context
        if current_value != src_value:
            return False

        if path_index >= len(reachable_values_paths):
            return False
        if len(reachable_values_paths[path_index]) != 0:
            return False

        has_sibling_safe_delete_on_exit = False
        for sibling_index, sibling_path_set in enumerate(reachable_values_paths):
            if sibling_index == path_index:
                continue
            if len(sibling_path_set) == 0:
                continue
            sibling_sink_edges = [
                (value, ctx)
                for value, ctx in sibling_path_set
                if value.label == ValueLabel.SINK
            ]
            if len(sibling_sink_edges) == 0:
                continue
            if not self.__is_delete_on_exit_only_sink_edges(sibling_sink_edges):
                continue

            sibling_release_context = RELEASE_CONTEXT_UNKNOWN
            if sibling_index < len(release_context_paths):
                sibling_release_context = normalize_release_context(
                    release_context_paths[sibling_index]
                )
            sibling_guarantee = GUARANTEE_NONE
            if sibling_index < len(guarantee_level_paths):
                sibling_guarantee = normalize_guarantee_level(
                    guarantee_level_paths[sibling_index]
                )

            _, refined_sibling_guarantee = self.__refine_java_mlk_release_semantics(
                src_value=src_value,
                resource_kind=resource_kind,
                sink_edges=sibling_sink_edges,
                release_context=sibling_release_context,
                guarantee_level=sibling_guarantee,
            )
            if is_all_exit_guaranteed(refined_sibling_guarantee):
                has_sibling_safe_delete_on_exit = True
                break

        if not has_sibling_safe_delete_on_exit:
            return False

        return True

    def __build_java_mlk_empty_branch_candidate_path(
        self,
        src_value: Value,
        current_value_with_context: Tuple[Value, CallContext],
        path_with_unknown_status: List[Value],
        path_index: int,
        resource_kind: str,
        release_context: str,
        guarantee_level: str,
    ) -> List[Value]:
        """
        Build a candidate path for empty path_set branches and attach a branch marker.
        This helps PathValidator avoid being biased by close calls from other branches.
        """
        current_value, _ = current_value_with_context
        marker = Value(
            f"__NO_SINK_BRANCH_PATH_{path_index}__",
            current_value.line_number,
            ValueLabel.LOCAL,
            current_value.file,
        )
        candidate_path = list(path_with_unknown_status)
        candidate_path.append(marker)
        self.__append_java_mlk_semantic_markers(
            candidate_path,
            marker,
            resource_kind,
            release_context,
            guarantee_level,
        )
        if src_value not in candidate_path:
            candidate_path = [src_value] + candidate_path
        return candidate_path

    def __build_java_mlk_terminal_branch_candidate_path(
        self,
        src_value: Value,
        path_with_unknown_status: List[Value],
        terminal_value: Value,
        path_index: int,
        resource_kind: str,
        release_context: str,
        guarantee_level: str,
    ) -> List[Value]:
        """
        Build a candidate path for non-empty terminal branches that still have no
        sink on this branch. Attach the same no-sink marker so strict branch
        semantics can be applied during PathValidator re-check.
        """
        marker = Value(
            f"__NO_SINK_BRANCH_PATH_{path_index}__",
            terminal_value.line_number,
            ValueLabel.LOCAL,
            terminal_value.file,
        )
        candidate_path = list(path_with_unknown_status)
        candidate_path.append(terminal_value)
        candidate_path.append(marker)
        self.__append_java_mlk_semantic_markers(
            candidate_path,
            marker,
            resource_kind,
            release_context,
            guarantee_level,
        )
        if src_value not in candidate_path:
            candidate_path = [src_value] + candidate_path
        return candidate_path

    def __build_java_mlk_sink_branch_candidate_path(
        self,
        src_value: Value,
        path_with_unknown_status: List[Value],
        sink_value: Value,
        path_index: int,
        resource_kind: str,
        release_context: str,
        guarantee_level: str,
    ) -> List[Value]:
        marker = Value(
            f"__WEAK_RELEASE_BRANCH_PATH_{path_index}__",
            sink_value.line_number,
            ValueLabel.LOCAL,
            sink_value.file,
        )
        candidate_path = list(path_with_unknown_status)
        candidate_path.append(sink_value)
        candidate_path.append(marker)
        self.__append_java_mlk_semantic_markers(
            candidate_path,
            marker,
            resource_kind,
            release_context,
            guarantee_level,
        )
        if src_value not in candidate_path:
            candidate_path = [src_value] + candidate_path
        return candidate_path

    def __append_java_mlk_semantic_markers(
        self,
        candidate_path: List[Value],
        anchor_value: Value,
        resource_kind: str,
        release_context: str,
        guarantee_level: str,
    ) -> None:
        candidate_path.append(
            Value(
                encode_resource_kind_marker(resource_kind),
                anchor_value.line_number,
                ValueLabel.LOCAL,
                anchor_value.file,
            )
        )
        candidate_path.append(
            Value(
                encode_release_context_marker(release_context),
                anchor_value.line_number,
                ValueLabel.LOCAL,
                anchor_value.file,
            )
        )
        candidate_path.append(
            Value(
                encode_guarantee_level_marker(guarantee_level),
                anchor_value.line_number,
                ValueLabel.LOCAL,
                anchor_value.file,
            )
        )

    def __is_non_executed_return_branch(
        self,
        current_value_with_context: Tuple[Value, CallContext],
        reachable_values_paths: List[Set[Tuple[Value, CallContext]]],
    ) -> bool:
        """
        Heuristic for Java MLK:
        If the current value is a return-expression carrier (RET/OUT on a return line)
        and this node has mixed reachable path sets (both empty and non-empty),
        then empty path sets usually mean "source is not executed on this branch"
        rather than "executed but leaked". In that case, ignore empty path sets.
        """
        value, _ = current_value_with_context
        if value.label not in {ValueLabel.OUT, ValueLabel.RET}:
            return False

        has_non_empty = any(len(path_set) > 0 for path_set in reachable_values_paths)
        has_empty = any(len(path_set) == 0 for path_set in reachable_values_paths)
        if not (has_non_empty and has_empty):
            return False

        current_function = self.ts_analyzer.get_function_from_localvalue(value)
        if current_function is None:
            return False

        return_values = self.ts_analyzer.get_return_values_in_single_function(
            current_function
        )
        for ret_value in return_values:
            if ret_value.line_number == value.line_number:
                return True
        return False

    def __has_sibling_continue_arg_for_para(
        self,
        para_with_ctx: Tuple[Value, CallContext],
        reachable_values_snapshot: Dict[
            Tuple[Value, CallContext], List[Set[Tuple[Value, CallContext]]]
        ],
        external_match_snapshot: Dict[
            Tuple[Value, CallContext], Set[Tuple[Value, CallContext]]
        ],
    ) -> bool:
        """
        Check whether this PARA leaf comes from an ARG call site that has sibling
        inter-procedural ARG branches in the same caller path_set.

        This is used to suppress helper-only duplicate branches such as:
        run(in)->traceResource(in) + run(in)->consume(in) where traceResource is
        no-propagation.
        """
        value, _ = para_with_ctx
        if value.label != ValueLabel.PARA:
            return False

        incoming_args: List[Tuple[Value, CallContext]] = []
        for external_start, external_ends in external_match_snapshot.items():
            if para_with_ctx in external_ends and external_start[0].label == ValueLabel.ARG:
                incoming_args.append(external_start)

        if len(incoming_args) == 0:
            return False

        for incoming_arg in incoming_args:
            for _, path_sets in reachable_values_snapshot.items():
                for path_set in path_sets:
                    if incoming_arg not in path_set:
                        continue
                    for sibling in path_set:
                        if sibling == incoming_arg:
                            continue
                        sibling_value, _ = sibling
                        if (
                            sibling_value.label == ValueLabel.ARG
                            and sibling in external_match_snapshot
                        ):
                            return True
        return False

    def __has_sibling_continue_external_edge(
        self,
        reachable_values_paths: List[Set[Tuple[Value, CallContext]]],
        external_match_snapshot: Dict[
            Tuple[Value, CallContext], Set[Tuple[Value, CallContext]]
        ],
    ) -> bool:
        """
        Whether any sibling path_set contains a continue edge (external match).
        Used to suppress OUT/PARA empty-path short candidates when a real
        inter-procedural continuation already exists in the same function.
        """
        for path_set in reachable_values_paths:
            if len(path_set) == 0:
                continue
            for value_with_ctx in path_set:
                value, _ = value_with_ctx
                if value.label not in {
                    ValueLabel.PARA,
                    ValueLabel.RET,
                    ValueLabel.ARG,
                    ValueLabel.OUT,
                }:
                    continue
                if value_with_ctx in external_match_snapshot:
                    if len(external_match_snapshot[value_with_ctx]) > 0:
                        return True
        return False

    def __record_java_mlk_transfer(
        self,
        src_value: Value,
        path: List[Value],
        reason: str,
        terminal_value: Optional[Value] = None,
        rule_hit: str = "",
    ) -> None:
        if self.language != "Java" or self.bug_type != "MLK":
            return
        src_key = str(src_value)
        path_key = str(path)
        event = {
            "src_value": src_key,
            "reason": reason,
            "rule_hit": rule_hit,
            "path_key": path_key,
            "path_length": len(path),
            "terminal_label": (
                terminal_value.label.name if terminal_value is not None else "UNKNOWN"
            ),
            "terminal_value": str(terminal_value) if terminal_value is not None else "",
            "terminal_line": terminal_value.line_number if terminal_value is not None else -1,
            "terminal_file": terminal_value.file if terminal_value is not None else "",
        }
        with self.lock:
            if src_key not in self.java_mlk_transfer_records:
                self.java_mlk_transfer_records[src_key] = []
            self.java_mlk_transfer_records[src_key].append(event)
        self.logger.print_log(
            "Classified as Java MLK responsibility transfer:",
            src_key,
            reason,
            f"rule={rule_hit}",
        )

    def __dump_java_mlk_transfer_records(self) -> None:
        if self.language != "Java" or self.bug_type != "MLK":
            return
        transfer_path = self.res_dir_path + "/transfer_info.json"
        with self.lock:
            payload = dict(self.java_mlk_transfer_records)
        with open(transfer_path, "w") as transfer_file:
            json.dump(payload, transfer_file, indent=4)

    def __skip_by_java_soot_prefilter(
        self,
        src_value: Value,
        buggy_path: List[Value],
        values_to_functions: Dict[Value, Optional[Function]],
    ) -> bool:
        if self.java_soot_prefilter is None:
            return False
        soot_result = self.java_soot_prefilter.evaluate(buggy_path, values_to_functions)
        self.soot_prefilter_stats.update(soot_result, self.soot_shadow_mode)
        self.logger.print_log(
            "[Soot prefilter]",
            f"verdict={soot_result.verdict}",
            f"reason={soot_result.reason}",
            f"matched_methods={soot_result.matched_methods}",
            f"elapsed_ms={soot_result.elapsed_ms:.2f}",
        )
        if len(soot_result.evidence) > 0:
            self.logger.print_log("[Soot prefilter] evidence:", soot_result.evidence[0])
        return soot_result.should_skip_llm and not self.soot_shadow_mode

    def __skip_source_by_java_soot_prefilter(
        self, src_value: Value, src_function: Optional[Function]
    ) -> bool:
        if self.java_soot_prefilter is None:
            return False
        if src_function is None:
            return False
        soot_result = self.java_soot_prefilter.evaluate(
            [src_value], {src_value: src_function}
        )
        strict_hard_safe, strict_reason = self.java_soot_prefilter.evaluate_source_hard_safety(
            src_value, src_function
        )
        skip_suppressed_by_strict = soot_result.should_skip_llm and not strict_hard_safe
        should_skip = (
            soot_result.should_skip_llm
            and strict_hard_safe
            and not self.soot_shadow_mode
        )
        self.logger.print_log(
            "[Soot source gate]",
            f"verdict={soot_result.verdict}",
            f"reason={soot_result.reason}",
            f"strict_hard_safe={strict_hard_safe}",
            f"strict_reason={strict_reason}",
            f"elapsed_ms={soot_result.elapsed_ms:.2f}",
        )
        if len(soot_result.evidence) > 0:
            self.logger.print_log("[Soot source gate] evidence:", soot_result.evidence[0])
        if skip_suppressed_by_strict:
            self.logger.print_log(
                "[Soot source gate] Skip suppressed by strict hard-proof policy."
            )
        if should_skip:
            with self.lock:
                self.soot_prefilter_source_skipped += 1
            self.logger.print_log(
                f"[Soot source gate] Skip source before path search: {str(src_value)}"
            )
        self.__record_soot_source_gate_event(
            src_value=src_value,
            src_function=src_function,
            soot_result=soot_result,
            strict_hard_safe=strict_hard_safe,
            strict_reason=strict_reason,
            blocked_by_soot=should_skip,
            skip_suppressed_by_strict=skip_suppressed_by_strict,
        )
        return should_skip

    def __record_soot_source_gate_event(
        self,
        src_value: Value,
        src_function: Function,
        soot_result,
        strict_hard_safe: bool,
        strict_reason: str,
        blocked_by_soot: bool,
        skip_suppressed_by_strict: bool,
    ) -> None:
        function_uid = src_function.function_uid or src_function.function_name
        function_name_lower = src_function.function_name.lower()
        in_bad_method = "bad" in function_name_lower
        event = {
            "src_value": str(src_value),
            "src_line": src_value.line_number,
            "src_file": src_value.file,
            "function_uid": function_uid,
            "function_name": src_function.function_name,
            "prefilter_verdict": str(soot_result.verdict),
            "prefilter_reason": soot_result.reason,
            "strict_hard_safe": strict_hard_safe,
            "strict_reason": strict_reason,
            "blocked_by_soot": blocked_by_soot,
            "skip_suppressed_by_strict": skip_suppressed_by_strict,
            "shadow_mode": self.soot_shadow_mode,
            "in_bad_method": in_bad_method,
            "evidence": soot_result.evidence[0] if len(soot_result.evidence) > 0 else "",
        }
        with self.lock:
            self.soot_source_gate_events.append(event)

    def __dump_soot_source_gate_events(self) -> None:
        if self.language != "Java" or self.bug_type != "MLK":
            return
        if self.java_soot_prefilter is None:
            return
        events_path = self.res_dir_path + "/soot_source_gate_events.json"
        with self.lock:
            events_payload = list(self.soot_source_gate_events)

        total = len(events_payload)
        blocked = sum(1 for item in events_payload if bool(item["blocked_by_soot"]))
        suppressed = sum(
            1 for item in events_payload if bool(item["skip_suppressed_by_strict"])
        )
        bad_total = sum(1 for item in events_payload if bool(item["in_bad_method"]))
        bad_blocked = sum(
            1
            for item in events_payload
            if bool(item["in_bad_method"]) and bool(item["blocked_by_soot"])
        )
        bad_pass = bad_total - bad_blocked
        good_total = total - bad_total
        good_blocked = blocked - bad_blocked
        good_pass = good_total - good_blocked

        summary = {
            "total": total,
            "blocked": blocked,
            "passed": total - blocked,
            "suppressed_by_strict_policy": suppressed,
            "bad_method_total": bad_total,
            "bad_method_blocked": bad_blocked,
            "bad_method_passed": bad_pass,
            "good_or_unknown_method_total": good_total,
            "good_or_unknown_method_blocked": good_blocked,
            "good_or_unknown_method_passed": good_pass,
            # Proxy confusion matrix: "bad*" methods are treated as positives.
            "proxy_confusion_matrix": {
                "tp_bad_passed": bad_pass,
                "fn_bad_blocked": bad_blocked,
                "tn_good_blocked": good_blocked,
                "fp_good_passed": good_pass,
            },
        }

        payload = {
            "summary": summary,
            "events": events_payload,
        }
        with open(events_path, "w") as events_file:
            json.dump(payload, events_file, indent=4)

        if bad_blocked > 0:
            self.logger.print_log(
                "[Soot source gate] Warning:",
                f"blocked {bad_blocked} source(s) in bad* methods. Consider turning on shadow mode for source gate.",
            )

    def __build_java_mlk_source_coverage_stats(
        self, src_values: List[Value]
    ) -> Dict[str, object]:
        if self.language != "Java" or self.bug_type != "MLK":
            return {}

        java_files = sorted(
            file_path.replace("\\", "/")
            for file_path in self.ts_analyzer.code_in_files.keys()
            if file_path.lower().endswith(".java")
        )
        source_count_by_file: Dict[str, int] = {file_path: 0 for file_path in java_files}
        source_lines_by_file: Dict[str, Set[int]] = {file_path: set() for file_path in java_files}
        source_count_by_confidence: Dict[str, int] = {
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        source_count_by_origin: Dict[str, int] = {}

        for src_value in src_values:
            normalized_file = src_value.file.replace("\\", "/")
            if normalized_file not in source_count_by_file:
                source_count_by_file[normalized_file] = 0
                source_lines_by_file[normalized_file] = set()
            source_count_by_file[normalized_file] += 1
            source_lines_by_file[normalized_file].add(src_value.line_number)
            confidence = self.__infer_java_mlk_source_confidence(src_value)
            source_count_by_confidence[confidence] = (
                source_count_by_confidence.get(confidence, 0) + 1
            )
            origin = self.__infer_java_mlk_source_origin(src_value)
            source_count_by_origin[origin] = source_count_by_origin.get(origin, 0) + 1

        files_with_sources = sum(
            1 for source_count in source_count_by_file.values() if source_count > 0
        )
        total_files = len(source_count_by_file)
        zero_source_files = sorted(
            file_path
            for file_path, source_count in source_count_by_file.items()
            if source_count == 0
        )
        coverage_ratio = (
            float(files_with_sources) / float(total_files) if total_files > 0 else 0.0
        )

        return {
            "total_java_files": total_files,
            "files_with_sources": files_with_sources,
            "files_without_sources": total_files - files_with_sources,
            "coverage_ratio": coverage_ratio,
            "total_sources": len(src_values),
            "source_count_by_confidence": source_count_by_confidence,
            "source_count_by_origin": source_count_by_origin,
            "zero_source_files": zero_source_files,
            "source_count_by_file": source_count_by_file,
            "source_lines_by_file": {
                file_path: sorted(lines)
                for file_path, lines in source_lines_by_file.items()
            },
        }

    def __dump_java_mlk_source_coverage_stats(self) -> None:
        if self.language != "Java" or self.bug_type != "MLK":
            return
        stats_path = self.res_dir_path + "/source_coverage_stats.json"
        with open(stats_path, "w") as stats_file:
            json.dump(self.java_mlk_source_coverage_stats, stats_file, indent=4)

    def __skip_by_java_z3_prefilter(
        self,
        src_value: Value,
        buggy_path: List[Value],
        values_to_functions: Dict[Value, Optional[Function]],
    ) -> bool:
        if self.java_z3_prefilter is None:
            return False
        line_hints = self.__build_java_z3_line_hints(
            src_value, buggy_path, values_to_functions
        )
        z3_result = self.java_z3_prefilter.evaluate(
            buggy_path, values_to_functions, line_hints
        )
        self.z3_prefilter_stats.update(z3_result, self.z3_shadow_mode)
        self.logger.print_log(
            "[Z3 prefilter]",
            f"verdict={z3_result.verdict}",
            f"reason={z3_result.reason}",
            f"parsed={z3_result.parsed_constraints}/{z3_result.total_constraints}",
            f"elapsed_ms={z3_result.elapsed_ms:.2f}",
        )
        if len(z3_result.unsat_core) > 0:
            self.logger.print_log("[Z3 prefilter] unsat_core:", z3_result.unsat_core)
        if z3_result.should_skip_llm and z3_result.parsed_constraints < self.z3_min_parsed_constraints:
            self.logger.print_log(
                "[Z3 prefilter] Skip is suppressed:",
                f"parsed_constraints={z3_result.parsed_constraints} < threshold={self.z3_min_parsed_constraints}",
            )
            return False
        return z3_result.should_skip_llm and not self.z3_shadow_mode

    def __build_java_z3_line_hints(
        self,
        src_value: Value,
        buggy_path: List[Value],
        values_to_functions: Dict[Value, Optional[Function]],
    ) -> Dict[int, List[int]]:
        line_hints: Dict[int, List[int]] = {}

        # Base hints from the concrete values on the candidate path.
        for value in buggy_path:
            function = values_to_functions.get(value)
            if function is None:
                continue
            relative_line = function.file_line2function_line(value.line_number)
            if relative_line <= 0:
                continue
            line_hints.setdefault(function.function_id, []).append(relative_line)

        # Extra hints from intra-procedural path line traces.
        # We do not rely on source function only; instead, merge traces for all
        # functions that are relevant to the current candidate path.
        marker_indexes = self.__extract_java_mlk_marker_path_indexes(buggy_path)
        state_snapshot = self.state.path_line_numbers_per_path
        target_function_ids = {
            function.function_id
            for function in values_to_functions.values()
            if function is not None
        }
        path_values = set(buggy_path)
        src_function = self.ts_analyzer.get_function_from_localvalue(src_value)
        if src_function is not None:
            target_function_ids.add(src_function.function_id)

        for (state_value, _), line_traces in state_snapshot.items():
            function = self.ts_analyzer.get_function_from_localvalue(state_value)
            if function is None:
                continue
            if function.function_id not in target_function_ids:
                continue

            selected_traces: List[List[int]] = []
            if len(marker_indexes) > 0:
                for marker_index in marker_indexes:
                    if marker_index < 0 or marker_index >= len(line_traces):
                        continue
                    selected_traces.append(line_traces[marker_index])
            elif len(line_traces) == 1:
                selected_traces.append(line_traces[0])
            elif state_value in path_values:
                # Prefer traces that explicitly execute the state value line.
                state_rel_line = function.file_line2function_line(state_value.line_number)
                for trace in line_traces:
                    if state_rel_line in trace:
                        selected_traces.append(trace)

            for trace in selected_traces:
                line_hints.setdefault(function.function_id, []).extend(trace)

        for function_id in line_hints:
            line_hints[function_id] = sorted(
                set(line for line in line_hints[function_id] if line > 0)
            )
        return line_hints

    def __extract_java_mlk_marker_path_indexes(self, path: List[Value]) -> List[int]:
        indexes: List[int] = []
        marker_re = re.compile(
            r"^__(?:NO_SINK_BRANCH_PATH|WEAK_RELEASE_BRANCH_PATH)_(\d+)__$"
        )
        for value in path:
            if value.label != ValueLabel.LOCAL:
                continue
            marker_match = marker_re.match(value.name)
            if marker_match is None:
                continue
            marker_index = int(marker_match.group(1))
            if marker_index not in indexes:
                indexes.append(marker_index)
        return indexes

    def __dump_z3_prefilter_stats(self) -> None:
        if self.language != "Java" or self.bug_type != "MLK":
            return
        if self.java_z3_prefilter is None:
            return
        stats_path = self.res_dir_path + "/z3_prefilter_stats.json"
        with open(stats_path, "w") as stats_file:
            json.dump(self.z3_prefilter_stats.to_dict(), stats_file, indent=4)

    def __dump_soot_prefilter_stats(self) -> None:
        if self.language != "Java" or self.bug_type != "MLK":
            return
        if self.java_soot_prefilter is None:
            return
        stats_path = self.res_dir_path + "/soot_prefilter_stats.json"
        payload = self.soot_prefilter_stats.to_dict()
        payload["source_skipped_before_path_search"] = self.soot_prefilter_source_skipped
        with self.lock:
            source_events = list(self.soot_source_gate_events)
        payload["source_skip_suppressed_by_strict"] = sum(
            1 for item in source_events if bool(item.get("skip_suppressed_by_strict", False))
        )
        payload["source_bad_method_blocked"] = sum(
            1
            for item in source_events
            if bool(item.get("in_bad_method", False))
            and bool(item.get("blocked_by_soot", False))
        )
        with open(stats_path, "w") as stats_file:
            json.dump(payload, stats_file, indent=4)

    def __build_java_mlk_source_obligation_index(
        self, src_values: List[Value]
    ) -> Dict[str, str]:
        """
        Build obligation keys for Java MLK sources.
        Multiple derived sources in the same resource family (e.g., wrapper/factory chain)
        should map to one obligation key, while independent sources remain separated.
        """
        if self.language != "Java" or self.bug_type != "MLK":
            return {}

        result: Dict[str, str] = {}
        sources_by_function: Dict[int, List[Value]] = defaultdict(list)
        source_local_key_by_src: Dict[str, str] = {}
        source_value_by_src_key: Dict[str, Value] = {}
        function_source_context: Dict[int, Dict[str, object]] = {}

        for src_value in src_values:
            src_key = str(src_value)
            source_value_by_src_key[src_key] = src_value
            src_function = self.ts_analyzer.get_function_from_localvalue(src_value)
            if src_function is None:
                normalized_file = src_value.file.replace("\\", "/").lower()
                normalized_src_name = self.__normalize_java_mlk_source_name(src_value.name)
                local_key = (
                    f"{normalized_file}:UNKNOWN:src:{normalized_src_name}:{src_value.line_number}"
                )
                result[src_key] = local_key
                source_local_key_by_src[src_key] = local_key
                continue
            sources_by_function[src_function.function_id].append(src_value)

        for function_id, function_sources in sources_by_function.items():
            if function_id not in self.ts_analyzer.function_env:
                continue
            function = self.ts_analyzer.function_env[function_id]
            normalized_file = function.file_path.replace("\\", "/").lower()
            function_key = self.__build_java_mlk_function_signature_key(function)
            paras = (
                function.paras
                if function.paras is not None
                else self.ts_analyzer.get_parameters_in_single_function(function)
            )
            para_name_to_index: Dict[str, int] = {
                para.name: para.index for para in paras if para.index >= 0
            }

            assignment_timeline = self.__build_java_mlk_assignment_timeline(function)
            source_var_by_src_key: Dict[str, str] = {}
            source_lines_by_var: Dict[str, List[int]] = defaultdict(list)
            root_var_by_src_key: Dict[str, str] = {}
            source_line_by_src_key: Dict[str, int] = {}
            source_norm_expr_by_src_key: Dict[str, str] = {}
            source_symbol_by_src_key: Dict[str, str] = {}
            source_anchor_by_src_key: Dict[str, str] = {}
            source_keys_by_norm_expr: Dict[str, List[Tuple[int, str]]] = defaultdict(list)
            source_keys_by_line: Dict[int, List[str]] = defaultdict(list)

            for src_value in function_sources:
                src_key = str(src_value)
                line_text = self.ts_analyzer.get_content_by_line_number(
                    src_value.line_number, src_value.file
                )
                assigned_var, _ = self.__parse_java_assignment_line(line_text)
                source_var = assigned_var
                if source_var == "":
                    source_var = self.__extract_java_receiver_identifier(src_value.name)
                source_var_by_src_key[src_key] = source_var
                if source_var != "":
                    source_lines_by_var[source_var].append(src_value.line_number)
                source_line_by_src_key[src_key] = src_value.line_number
                normalized_src_name = self.__normalize_java_mlk_source_name(src_value.name)
                source_norm_expr_by_src_key[src_key] = normalized_src_name
                source_symbol_by_src_key[src_key] = self.__infer_java_mlk_source_symbol(
                    src_value
                )
                source_keys_by_norm_expr[normalized_src_name].append(
                    (src_value.line_number, src_key)
                )
                source_keys_by_line[src_value.line_number].append(src_key)

            for var_name, line_numbers in source_lines_by_var.items():
                source_lines_by_var[var_name] = sorted(set(line_numbers))
            for normalized_expr in source_keys_by_norm_expr:
                source_keys_by_norm_expr[normalized_expr] = sorted(
                    source_keys_by_norm_expr[normalized_expr],
                    key=lambda item: (item[0], item[1]),
                )
            for line_number in source_keys_by_line:
                source_keys_by_line[line_number] = sorted(
                    set(source_keys_by_line[line_number])
                )

            for src_value in function_sources:
                src_key = str(src_value)
                source_var = source_var_by_src_key.get(src_key, "")
                if source_var != "":
                    root_var = self.__resolve_java_root_variable_at_line(
                        source_var,
                        src_value.line_number,
                        assignment_timeline,
                        set(),
                    )
                    root_source_line = self.__pick_java_root_source_line(
                        root_var,
                        src_value.line_number,
                        source_lines_by_var,
                    )
                    root_var_by_src_key[src_key] = root_var
                    local_key = (
                        f"{normalized_file}:{function_key}:root:{root_var.lower()}:{root_source_line}"
                    )
                else:
                    normalized_src_name = self.__normalize_java_mlk_source_name(
                        src_value.name
                    )
                    root_var_by_src_key[src_key] = ""
                    local_key = (
                        f"{normalized_file}:{function_key}:src:{normalized_src_name}:{src_value.line_number}"
                    )
                result[src_key] = local_key
                source_local_key_by_src[src_key] = local_key
                source_symbol = source_symbol_by_src_key.get(src_key, "unknown")
                source_anchor_by_src_key[src_key] = self.__extract_java_mlk_obligation_anchor(
                    local_key, source_symbol
                )

            function_source_context[function_id] = {
                "function": function,
                "function_sources": list(function_sources),
                "assignment_timeline": assignment_timeline,
                "source_lines_by_var": source_lines_by_var,
                "source_var_by_src_key": source_var_by_src_key,
                "root_var_by_src_key": root_var_by_src_key,
                "source_line_by_src_key": source_line_by_src_key,
                "source_norm_expr_by_src_key": source_norm_expr_by_src_key,
                "source_symbol_by_src_key": source_symbol_by_src_key,
                "source_anchor_by_src_key": source_anchor_by_src_key,
                "source_keys_by_norm_expr": source_keys_by_norm_expr,
                "source_keys_by_line": source_keys_by_line,
                "para_name_to_index": para_name_to_index,
            }

        # Inter-procedural obligation linking:
        # if a callee source is derived from parameter i and caller passes a source
        # (or a source-derived variable) as argument i, merge them into one obligation.
        parent: Dict[str, str] = {src_key: src_key for src_key in result}

        def find_root(src_key: str) -> str:
            current = src_key
            while parent[current] != current:
                parent[current] = parent[parent[current]]
                current = parent[current]
            return current

        def union(src_a: str, src_b: str) -> bool:
            root_a = find_root(src_a)
            root_b = find_root(src_b)
            if root_a == root_b:
                return False
            key_a = source_local_key_by_src.get(root_a, result.get(root_a, root_a))
            key_b = source_local_key_by_src.get(root_b, result.get(root_b, root_b))
            if key_a <= key_b:
                parent[root_b] = root_a
            else:
                parent[root_a] = root_b
            return True

        callee_param_derived_sources: Dict[int, Dict[int, List[str]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for function_id, context in function_source_context.items():
            source_var_by_src_key = context["source_var_by_src_key"]
            assignment_timeline = context["assignment_timeline"]
            para_name_to_index = context["para_name_to_index"]
            function_sources = context["function_sources"]

            for src_value in function_sources:
                src_key = str(src_value)
                source_var = source_var_by_src_key.get(src_key, "")
                param_indices = self.__infer_java_mlk_source_parameter_indices(
                    src_value=src_value,
                    source_var=source_var,
                    para_name_to_index=para_name_to_index,
                    assignment_timeline=assignment_timeline,
                )
                # Keep propagation conservative: only merge when the source is
                # clearly derived from one parameter slot.
                if len(param_indices) != 1:
                    continue
                param_index = next(iter(param_indices))
                callee_param_derived_sources[function_id][param_index].append(src_key)

        interproc_link_count = 0
        for caller_function_id, caller_context in function_source_context.items():
            caller_function = caller_context["function"]
            callee_functions = self.ts_analyzer.get_all_callee_functions(caller_function)
            if len(callee_functions) == 0:
                continue

            for callee_function in callee_functions:
                callee_function_id = callee_function.function_id
                if callee_function_id not in callee_param_derived_sources:
                    continue
                param_source_map = callee_param_derived_sources[callee_function_id]
                if len(param_source_map) == 0:
                    continue

                call_sites = self.ts_analyzer.get_callsites_by_callee_function(
                    caller_function, callee_function
                )
                if len(call_sites) == 0:
                    continue

                for call_site in call_sites:
                    resolved_callee_ids = self.ts_analyzer.get_callee_function_ids_at_callsite(
                        caller_function, call_site
                    )
                    # Keep ambiguous-overload callsites if the current callee is one
                    # of the resolved targets. Requiring exactly one target misses
                    # many forwarding/overload chains (e.g., readFile(String)->readFile(Reader)).
                    if callee_function_id not in resolved_callee_ids:
                        continue

                    call_arguments = self.ts_analyzer.get_arguments_at_callsite(
                        caller_function, call_site
                    )
                    arg_by_index = {arg.index: arg for arg in call_arguments}
                    for param_index, callee_src_keys in param_source_map.items():
                        call_arg = arg_by_index.get(param_index)
                        if call_arg is None:
                            continue
                        caller_src_key = self.__resolve_java_mlk_argument_source_key(
                            call_arg, caller_context
                        )
                        if caller_src_key == "" or caller_src_key not in parent:
                            continue
                        for callee_src_key in callee_src_keys:
                            if callee_src_key not in parent:
                                continue
                            if union(caller_src_key, callee_src_key):
                                interproc_link_count += 1

        # Extra inter-procedural linking for wrapper/forwarding styles:
        # caller source is a direct callee invocation result on the same line.
        for caller_context in function_source_context.values():
            caller_function = cast(Function, caller_context["function"])
            source_line_by_src_key = cast(Dict[str, int], caller_context["source_line_by_src_key"])
            source_norm_expr_by_src_key = cast(
                Dict[str, str], caller_context["source_norm_expr_by_src_key"]
            )
            source_code = self.ts_analyzer.code_in_files.get(caller_function.file_path, "")
            if source_code == "":
                continue

            callee_functions = self.ts_analyzer.get_all_callee_functions(caller_function)
            if len(callee_functions) == 0:
                continue

            for callee_function in callee_functions:
                callee_context = function_source_context.get(callee_function.function_id)
                if callee_context is None:
                    continue
                callee_sources = cast(List[Value], callee_context["function_sources"])
                if len(callee_sources) == 0:
                    continue

                call_sites = self.ts_analyzer.get_callsites_by_callee_function(
                    caller_function, callee_function
                )
                if len(call_sites) == 0:
                    continue

                for call_site in call_sites:
                    resolved_callee_ids = self.ts_analyzer.get_callee_function_ids_at_callsite(
                        caller_function, call_site
                    )
                    if callee_function.function_id not in resolved_callee_ids:
                        continue

                    callsite_line = source_code[: call_site.start_byte].count("\n") + 1
                    call_expr_text = source_code[call_site.start_byte : call_site.end_byte]
                    if callee_function.function_name not in call_expr_text:
                        continue

                    caller_candidates: List[str] = []
                    for src_key, src_line in source_line_by_src_key.items():
                        if src_line != callsite_line:
                            continue
                        normalized_expr = source_norm_expr_by_src_key.get(src_key, "")
                        if normalized_expr == "":
                            continue
                        if (
                            f"{callee_function.function_name}(" in normalized_expr
                            or normalized_expr.endswith(callee_function.function_name)
                        ):
                            caller_candidates.append(src_key)

                    if len(caller_candidates) == 0:
                        continue

                    for caller_src_key in caller_candidates:
                        if caller_src_key not in parent:
                            continue
                        for callee_src in callee_sources:
                            callee_src_key = str(callee_src)
                            if callee_src_key not in parent:
                                continue
                            if union(caller_src_key, callee_src_key):
                                interproc_link_count += 1

        group_members: Dict[str, List[str]] = defaultdict(list)
        for src_key in result:
            group_members[find_root(src_key)].append(src_key)
        for member_keys in group_members.values():
            ranked_candidates: List[Tuple[int, str]] = []
            for member_key in member_keys:
                member_value = source_value_by_src_key.get(member_key)
                confidence_rank = 2
                if member_value is not None:
                    confidence_rank = self.__java_mlk_source_confidence_rank(
                        self.__infer_java_mlk_source_confidence(member_value)
                    )
                local_key = source_local_key_by_src.get(member_key, result[member_key])
                ranked_candidates.append((-confidence_rank, local_key))
            ranked_candidates.sort()
            representative_key = ranked_candidates[0][1]
            for member_key in member_keys:
                result[member_key] = representative_key

        if interproc_link_count > 0:
            self.logger.print_log(
                "Java MLK obligation inter-procedural links:",
                f"linked={interproc_link_count}",
            )

        return result

    def __build_java_mlk_source_obligation_family_index(
        self,
        src_values: List[Value],
        source_obligation_keys: Dict[str, str],
    ) -> Dict[str, str]:
        if self.language != "Java" or self.bug_type != "MLK":
            return {}

        # Start from source-local family projection.
        source_family_keys: Dict[str, str] = {}
        families_by_file: Dict[str, List[Tuple[str, str, str]]] = defaultdict(list)
        for src_value in src_values:
            src_key = str(src_value)
            obligation_key = source_obligation_keys.get(src_key, "")
            if obligation_key == "":
                obligation_key = self.__get_java_mlk_source_obligation_key(src_value)
            family_key = self.__derive_java_mlk_obligation_family_key(
                src_value, obligation_key
            )
            source_family_keys[src_key] = family_key
            source_file = src_value.file.replace("\\", "/").lower()
            source_method_uid = ""
            src_function = self.ts_analyzer.get_function_from_localvalue(src_value)
            if src_function is not None:
                source_method_uid = (
                    src_function.function_uid
                    if src_function.function_uid != ""
                    else self.__build_java_mlk_function_signature_key(src_function)
                )
            families_by_file[source_file].append((src_key, family_key, source_method_uid))

        if self.java_mlk_family_link_mode != "aggressive":
            return source_family_keys

        # Aggressive linking mode: union family keys when methods have caller-callee
        # relation and symbols are compatible. This mainly targets wrapper overload
        # duplication (e.g., readFile(String)->readFile(Reader)).
        parent: Dict[str, str] = {}
        for src_key, family_key in source_family_keys.items():
            parent[src_key] = src_key

        def find_root(src_key: str) -> str:
            current = src_key
            while parent[current] != current:
                parent[current] = parent[parent[current]]
                current = parent[current]
            return current

        def union(src_a: str, src_b: str) -> None:
            root_a = find_root(src_a)
            root_b = find_root(src_b)
            if root_a == root_b:
                return
            key_a = source_family_keys.get(root_a, "")
            key_b = source_family_keys.get(root_b, "")
            if key_a <= key_b:
                parent[root_b] = root_a
            else:
                parent[root_a] = root_b

        function_id_to_sources: Dict[int, List[Value]] = defaultdict(list)
        for src_value in src_values:
            src_function = self.ts_analyzer.get_function_from_localvalue(src_value)
            if src_function is None:
                continue
            function_id_to_sources[src_function.function_id].append(src_value)

        for caller_function in self.ts_analyzer.function_env.values():
            caller_sources = function_id_to_sources.get(caller_function.function_id, [])
            if len(caller_sources) == 0:
                continue
            callee_functions = self.ts_analyzer.get_all_callee_functions(caller_function)
            if len(callee_functions) == 0:
                continue
            caller_src_keys = {str(src_value) for src_value in caller_sources}
            caller_symbol_set = {
                self.__infer_java_mlk_source_symbol(src_value) for src_value in caller_sources
            }
            for callee_function in callee_functions:
                callee_sources = function_id_to_sources.get(callee_function.function_id, [])
                if len(callee_sources) == 0:
                    continue
                callee_symbol_set = {
                    self.__infer_java_mlk_source_symbol(src_value)
                    for src_value in callee_sources
                }
                if len(caller_symbol_set & callee_symbol_set) == 0:
                    continue
                for caller_src_key in caller_src_keys:
                    if caller_src_key not in parent:
                        continue
                    for callee_src in callee_sources:
                        callee_src_key = str(callee_src)
                        if callee_src_key not in parent:
                            continue
                        union(caller_src_key, callee_src_key)

        grouped_members: Dict[str, List[str]] = defaultdict(list)
        for src_key in source_family_keys.keys():
            grouped_members[find_root(src_key)].append(src_key)

        for member_keys in grouped_members.values():
            representative_family = min(
                source_family_keys.get(member_key, "") for member_key in member_keys
            )
            for member_key in member_keys:
                source_family_keys[member_key] = representative_family

        return source_family_keys

    def __build_java_mlk_source_obligation_component_index(
        self,
        src_values: List[Value],
        source_obligation_keys: Dict[str, str],
    ) -> Dict[str, str]:
        """
        Build a coarser component-level obligation id for dedup.
        Goal: collapse wrapper/callee chain variants into one obligation component,
        while keeping independent resources in the same file separated.
        """
        if self.language != "Java" or self.bug_type != "MLK":
            return {}

        source_attrs: Dict[str, Dict[str, object]] = {}
        parent: Dict[str, str] = {}
        for src_value in src_values:
            src_key = str(src_value)
            obligation_key = source_obligation_keys.get(src_key, "")
            if obligation_key == "":
                obligation_key = self.__get_java_mlk_source_obligation_key(src_value)
            src_function = self.ts_analyzer.get_function_from_localvalue(src_value)
            source_method_uid = ""
            if src_function is not None:
                source_method_uid = (
                    src_function.function_uid
                    if src_function.function_uid != ""
                    else self.__build_java_mlk_function_signature_key(src_function)
                )
            source_attrs[src_key] = {
                "file": src_value.file.replace("\\", "/").lower(),
                "resource_kind": normalize_resource_kind(
                    classify_resource_kind(src_value.name, src_value.file)
                ),
                "source_symbol": self.__infer_java_mlk_source_symbol(src_value),
                "source_line": src_value.line_number,
                "source_method_uid": source_method_uid,
                "obligation_key": obligation_key,
                "obligation_anchor": self.__extract_java_mlk_obligation_anchor(
                    obligation_key,
                    self.__infer_java_mlk_source_symbol(src_value),
                ),
            }
            parent[src_key] = src_key

        def _find_root(src_key: str) -> str:
            current = src_key
            while parent[current] != current:
                parent[current] = parent[parent[current]]
                current = parent[current]
            return current

        def _union(src_a: str, src_b: str) -> bool:
            root_a = _find_root(src_a)
            root_b = _find_root(src_b)
            if root_a == root_b:
                return False
            key_a = str(source_attrs[root_a].get("obligation_key", ""))
            key_b = str(source_attrs[root_b].get("obligation_key", ""))
            if key_a <= key_b:
                parent[root_b] = root_a
            else:
                parent[root_a] = root_b
            return True

        def _component_size(src_key: str) -> int:
            root_key = _find_root(src_key)
            size = 0
            for candidate_key in source_attrs.keys():
                if _find_root(candidate_key) == root_key:
                    size += 1
            return size

        def _union_with_size_cap(src_a: str, src_b: str, max_size: int) -> bool:
            root_a = _find_root(src_a)
            root_b = _find_root(src_b)
            if root_a == root_b:
                return False
            size_a = _component_size(root_a)
            size_b = _component_size(root_b)
            if size_a + size_b > max_size:
                return False
            return _union(root_a, root_b)

        low_info_symbols = {
            "",
            "unknown",
            "in",
            "out",
            "is",
            "os",
            "stream",
            "reader",
            "writer",
            "input",
            "output",
            "file",
            "tmp",
            "buffer",
            "obj",
            "value",
            "result",
            "false",
            "true",
            "null",
        }

        def _is_low_info_symbol(symbol: str) -> bool:
            normalized_symbol = symbol.strip().lower()
            return normalized_symbol in low_info_symbols

        # Baseline: same exact obligation key always belongs to one component.
        obligation_members: Dict[str, List[str]] = defaultdict(list)
        for src_key, attrs in source_attrs.items():
            obligation_members[str(attrs.get("obligation_key", ""))].append(src_key)
        for member_keys in obligation_members.values():
            if len(member_keys) <= 1:
                continue
            head = member_keys[0]
            for member_key in member_keys[1:]:
                _union(head, member_key)

        if self.java_mlk_family_link_mode == "aggressive":
            # P0 hard-safety refactor:
            # keep cross-method collapsing evidence-driven only.
            # Cross-method hard links are already encoded in obligation_key by
            # __build_java_mlk_source_obligation_index (parameter derivation /
            # wrapper-return linking). Therefore, in aggressive mode we only
            # apply an extra *local* merge in the same method for extremely
            # near-line duplicates and never merge cross-method by symbol/hops.
            strict_local_link_count = 0
            strict_local_cap_skipped = 0
            max_local_component_size = 6

            local_buckets: Dict[Tuple[str, str, str, str], List[str]] = defaultdict(list)
            for src_key, attrs in source_attrs.items():
                method_uid = str(attrs.get("source_method_uid", ""))
                if method_uid == "":
                    continue
                source_symbol = str(attrs.get("source_symbol", "")).strip().lower()
                if _is_low_info_symbol(source_symbol):
                    continue
                local_key = (
                    str(attrs.get("file", "")),
                    method_uid,
                    str(attrs.get("resource_kind", "")),
                    str(attrs.get("obligation_anchor", "")),
                )
                local_buckets[local_key].append(src_key)

            for member_keys in local_buckets.values():
                if len(member_keys) <= 1:
                    continue
                sorted_members = sorted(
                    member_keys,
                    key=lambda item: int(source_attrs[item].get("source_line", -1)),
                )
                head = sorted_members[0]
                head_line = int(source_attrs[head].get("source_line", -1))
                for member_key in sorted_members[1:]:
                    member_line = int(source_attrs[member_key].get("source_line", -1))
                    if head_line < 0 or member_line < 0:
                        continue
                    if abs(head_line - member_line) > 2:
                        continue
                    if _union_with_size_cap(
                        head, member_key, max_local_component_size
                    ):
                        strict_local_link_count += 1
                    else:
                        strict_local_cap_skipped += 1

            if strict_local_link_count > 0 or strict_local_cap_skipped > 0:
                self.logger.print_log(
                    "Java MLK component strict-local links:",
                    f"linked={strict_local_link_count}",
                    f"cap_skipped={strict_local_cap_skipped}",
                    f"max_component_size={max_local_component_size}",
                )

        grouped_members: Dict[str, List[str]] = defaultdict(list)
        for src_key in source_attrs.keys():
            grouped_members[_find_root(src_key)].append(src_key)

        source_component_keys: Dict[str, str] = {}
        for member_keys in grouped_members.values():
            sample_key = member_keys[0]
            sample_attrs = source_attrs[sample_key]
            normalized_file = str(sample_attrs.get("file", ""))
            resource_kind = str(sample_attrs.get("resource_kind", RESOURCE_KIND_AUTOCLOSEABLE))
            representative_symbol = "unknown"
            informative_symbols = sorted(
                {
                    str(source_attrs[member_key].get("source_symbol", "")).strip().lower()
                    for member_key in member_keys
                    if not _is_low_info_symbol(
                        str(source_attrs[member_key].get("source_symbol", ""))
                    )
                }
            )
            if len(informative_symbols) > 0:
                representative_symbol = informative_symbols[0]
            else:
                raw_symbol = str(sample_attrs.get("source_symbol", "unknown")).strip().lower()
                representative_symbol = (
                    raw_symbol if not _is_low_info_symbol(raw_symbol) else "unknown"
                )
            anchor_key = min(
                str(source_attrs[member_key].get("obligation_key", member_key))
                for member_key in member_keys
            )
            component_key = (
                f"{normalized_file}:component:{resource_kind}:{representative_symbol}:{anchor_key}"
            )
            for member_key in member_keys:
                source_component_keys[member_key] = component_key

        return source_component_keys

    def __build_java_mlk_assignment_timeline(
        self, function: Function
    ) -> Dict[str, List[Tuple[int, List[str]]]]:
        timeline: Dict[str, List[Tuple[int, List[str]]]] = defaultdict(list)
        for line_number in range(
            function.start_line_number, function.end_line_number + 1
        ):
            line_text = self.ts_analyzer.get_content_by_line_number(
                line_number, function.file_path
            )
            lhs, rhs_tokens = self.__parse_java_assignment_line(line_text)
            if lhs == "":
                continue
            timeline[lhs].append((line_number, rhs_tokens))
        for lhs in timeline:
            timeline[lhs].sort(key=lambda item: item[0])
        return timeline

    def __parse_java_assignment_line(self, line_text: str) -> Tuple[str, List[str]]:
        if line_text == "":
            return "", []
        stripped = line_text.split("//", 1)[0].strip()
        if stripped == "":
            return "", []

        assign_idx = -1
        depth = 0
        in_single_quote = False
        in_double_quote = False
        escaped = False
        for idx, ch in enumerate(stripped):
            if escaped:
                escaped = False
                continue
            if ch == "\\":
                escaped = True
                continue
            if ch == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
                continue
            if ch == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
                continue
            if in_single_quote or in_double_quote:
                continue

            if ch in "([{":
                depth += 1
                continue
            if ch in ")]}":
                depth = max(0, depth - 1)
                continue

            if ch != "=" or depth != 0:
                continue
            prev_ch = stripped[idx - 1] if idx > 0 else ""
            next_ch = stripped[idx + 1] if idx + 1 < len(stripped) else ""
            if prev_ch in {"=", "!", "<", ">"} or next_ch == "=":
                continue
            assign_idx = idx
            break

        if assign_idx < 0:
            return "", []

        left = stripped[:assign_idx].strip()
        right = stripped[assign_idx + 1 :].strip().rstrip(";")
        lhs_var = self.__extract_java_assigned_variable(left)
        if lhs_var == "":
            return "", []
        rhs_tokens = self.__extract_java_assignment_rhs_dependencies(right)
        return lhs_var, rhs_tokens

    def __extract_java_assigned_variable(self, left_expr: str) -> str:
        identifiers = self.JAVA_IDENTIFIER_RE.findall(left_expr)
        if len(identifiers) == 0:
            return ""
        for token in reversed(identifiers):
            token_lower = token.lower()
            if token_lower in self.JAVA_ASSIGNMENT_SKIP_KEYWORDS:
                continue
            if token_lower in {"final", "volatile", "transient", "var"}:
                continue
            return token
        return ""

    def __extract_java_assignment_rhs_dependencies(self, right_expr: str) -> List[str]:
        if right_expr == "":
            return []
        right_stripped = right_expr.strip()
        right_lower = right_stripped.lower()
        if right_lower.startswith("new "):
            return []

        this_receiver_match = re.search(
            r"\bthis\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\.",
            right_stripped,
        )
        if this_receiver_match is not None:
            return [this_receiver_match.group(1)]

        receiver_match = re.search(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\s*\(",
            right_stripped,
        )
        if receiver_match is not None:
            receiver = receiver_match.group(1)
            if receiver != "" and not receiver[0].isupper():
                token_lower = receiver.lower()
                if token_lower not in self.JAVA_ASSIGNMENT_SKIP_KEYWORDS:
                    return [receiver]

        tokens: List[str] = []
        for match in self.JAVA_IDENTIFIER_RE.finditer(right_stripped):
            token = match.group(0)
            token_lower = token.lower()
            if token_lower in self.JAVA_ASSIGNMENT_SKIP_KEYWORDS:
                continue
            if token[0].isupper():
                continue
            suffix = right_stripped[match.end() :].lstrip()
            if suffix.startswith("("):
                # Invoked method name, not variable dependency.
                continue
            if token not in tokens:
                tokens.append(token)
        return tokens

    def __extract_java_receiver_identifier(self, expr: str) -> str:
        if expr == "":
            return ""
        text = expr.strip()
        this_receiver_match = re.match(
            r"^this\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\.",
            text,
        )
        if this_receiver_match is not None:
            return this_receiver_match.group(1)

        receiver_match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\.", text)
        if receiver_match is None:
            return ""
        receiver = receiver_match.group(1)
        if receiver == "" or receiver[0].isupper():
            return ""
        token_lower = receiver.lower()
        if token_lower in self.JAVA_ASSIGNMENT_SKIP_KEYWORDS:
            return ""
        return receiver

    def __resolve_java_root_variable_at_line(
        self,
        variable_name: str,
        line_number: int,
        timeline: Dict[str, List[Tuple[int, List[str]]]],
        visited: Set[str],
    ) -> str:
        if variable_name == "":
            return ""
        if variable_name in visited:
            return variable_name
        visited.add(variable_name)

        assignments = timeline.get(variable_name, [])
        rhs_tokens: List[str] = []
        for assign_line, assign_rhs_tokens in assignments:
            if assign_line <= line_number:
                rhs_tokens = assign_rhs_tokens
            else:
                break

        if len(rhs_tokens) == 0:
            return variable_name

        next_var = ""
        for token in rhs_tokens:
            if token == variable_name:
                continue
            token_lower = token.lower()
            if token_lower in self.JAVA_ASSIGNMENT_SKIP_KEYWORDS:
                continue
            next_var = token
            break

        if next_var == "":
            return variable_name
        return self.__resolve_java_root_variable_at_line(
            next_var,
            line_number,
            timeline,
            visited,
        )

    def __pick_java_root_source_line(
        self,
        root_var: str,
        current_line: int,
        source_lines_by_var: Dict[str, List[int]],
    ) -> int:
        root_lines = source_lines_by_var.get(root_var, [])
        if len(root_lines) == 0:
            return current_line
        prior_lines = [line for line in root_lines if line <= current_line]
        if len(prior_lines) > 0:
            return prior_lines[-1]
        return root_lines[0]

    def __infer_java_mlk_source_parameter_indices(
        self,
        src_value: Value,
        source_var: str,
        para_name_to_index: Dict[str, int],
        assignment_timeline: Dict[str, List[Tuple[int, List[str]]]],
    ) -> Set[int]:
        param_indices: Set[int] = set()
        if len(para_name_to_index) == 0:
            return param_indices

        dependencies = self.__extract_java_expression_dependencies(src_value.name)
        for dependency in dependencies:
            if dependency in para_name_to_index:
                param_indices.add(para_name_to_index[dependency])

        receiver = self.__extract_java_receiver_identifier(src_value.name)
        if receiver in para_name_to_index:
            param_indices.add(para_name_to_index[receiver])

        if source_var != "":
            root_var = self.__resolve_java_root_variable_at_line(
                source_var,
                src_value.line_number,
                assignment_timeline,
                set(),
            )
            if root_var in para_name_to_index:
                param_indices.add(para_name_to_index[root_var])
        return param_indices

    def __extract_java_expression_dependencies(self, expression: str) -> List[str]:
        if expression == "":
            return []
        text = expression.strip()
        if text == "":
            return []

        skip_tokens = self.JAVA_ASSIGNMENT_SKIP_KEYWORDS.union(
            {
                "int",
                "long",
                "double",
                "float",
                "short",
                "byte",
                "char",
                "boolean",
                "void",
                "class",
                "interface",
                "enum",
                "instanceof",
                "throws",
                "throw",
            }
        )

        dependencies: List[str] = []
        for match in self.JAVA_IDENTIFIER_RE.finditer(text):
            token = match.group(0)
            token_lower = token.lower()
            if token_lower in skip_tokens:
                continue
            if token[0].isupper():
                continue
            suffix = text[match.end() :].lstrip()
            if suffix.startswith("("):
                # method/function name, not a variable dependency
                continue
            if token not in dependencies:
                dependencies.append(token)
        return dependencies

    def __pick_java_mlk_source_key_near_line(
        self,
        candidates: List[Tuple[int, str]],
        line_number: int,
    ) -> str:
        if len(candidates) == 0:
            return ""

        exact_candidates = [
            (candidate_line, candidate_key)
            for candidate_line, candidate_key in candidates
            if candidate_line == line_number
        ]
        if len(exact_candidates) > 0:
            exact_candidates.sort(key=lambda item: item[1])
            return exact_candidates[0][1]

        prior_candidates = [
            (candidate_line, candidate_key)
            for candidate_line, candidate_key in candidates
            if candidate_line <= line_number
        ]
        if len(prior_candidates) > 0:
            prior_candidates.sort(key=lambda item: (-item[0], item[1]))
            return prior_candidates[0][1]

        post_candidates = sorted(candidates, key=lambda item: (item[0], item[1]))
        return post_candidates[0][1]

    def __resolve_java_mlk_argument_source_key(
        self,
        call_arg: Value,
        caller_context: Dict[str, object],
    ) -> str:
        normalized_arg_expr = self.__normalize_java_mlk_source_name(call_arg.name)
        source_keys_by_norm_expr = caller_context["source_keys_by_norm_expr"]
        source_norm_expr_by_src_key = caller_context["source_norm_expr_by_src_key"]
        source_keys_by_line = caller_context["source_keys_by_line"]
        assignment_timeline = caller_context["assignment_timeline"]
        source_lines_by_var = caller_context["source_lines_by_var"]
        source_var_by_src_key = caller_context["source_var_by_src_key"]
        root_var_by_src_key = caller_context["root_var_by_src_key"]
        source_line_by_src_key = caller_context["source_line_by_src_key"]
        source_symbol_by_src_key = caller_context.get("source_symbol_by_src_key", {})
        source_anchor_by_src_key = caller_context.get("source_anchor_by_src_key", {})

        exact_candidates = source_keys_by_norm_expr.get(normalized_arg_expr, [])
        matched_source_key = self.__pick_java_mlk_source_key_near_line(
            exact_candidates,
            call_arg.line_number,
        )
        if matched_source_key != "":
            return matched_source_key

        # Same-line wrapper/cast variation matching.
        line_candidates = source_keys_by_line.get(call_arg.line_number, [])
        for candidate_key in line_candidates:
            candidate_norm = source_norm_expr_by_src_key.get(candidate_key, "")
            if candidate_norm == "":
                continue
            if candidate_norm in normalized_arg_expr or normalized_arg_expr in candidate_norm:
                return candidate_key

        dependency_tokens = self.__extract_java_expression_dependencies(call_arg.name)
        for dependency in dependency_tokens:
            root_var = self.__resolve_java_root_variable_at_line(
                dependency,
                call_arg.line_number,
                assignment_timeline,
                set(),
            )
            matched_line = self.__pick_java_root_source_line(
                root_var,
                call_arg.line_number,
                source_lines_by_var,
            )
            candidate_pairs: List[Tuple[int, str]] = []
            for src_key, src_line in source_line_by_src_key.items():
                src_var = source_var_by_src_key.get(src_key, "")
                src_root_var = root_var_by_src_key.get(src_key, "")
                if src_var != root_var and src_root_var != root_var:
                    continue
                if src_line != matched_line:
                    continue
                candidate_pairs.append((src_line, src_key))
            candidate_key = self.__pick_java_mlk_source_key_near_line(
                candidate_pairs,
                call_arg.line_number,
            )
            if candidate_key != "":
                return candidate_key

        # Fallback 1: expression symbol alignment + nearest source line.
        arg_symbol = self.__infer_java_mlk_symbol_from_expression(call_arg.name)
        if arg_symbol != "unknown":
            symbol_candidates: List[Tuple[int, str]] = []
            for src_key, src_symbol in source_symbol_by_src_key.items():
                if src_symbol != arg_symbol:
                    continue
                symbol_candidates.append(
                    (int(source_line_by_src_key.get(src_key, -1)), src_key)
                )
            symbol_matched = self.__pick_java_mlk_source_key_near_line(
                symbol_candidates,
                call_arg.line_number,
            )
            if symbol_matched != "":
                return symbol_matched

        # Fallback 2: anchor-level approximation for wrapper forwarding.
        arg_anchor_candidates: Set[str] = set()
        for dependency in dependency_tokens:
            root_var = self.__resolve_java_root_variable_at_line(
                dependency,
                call_arg.line_number,
                assignment_timeline,
                set(),
            )
            if root_var != "":
                arg_anchor_candidates.add(f"root:{root_var.lower()}")
        if arg_symbol != "unknown":
            arg_anchor_candidates.add(f"src:{arg_symbol}")
        if len(arg_anchor_candidates) > 0:
            anchor_candidates: List[Tuple[int, str]] = []
            for src_key, anchor in source_anchor_by_src_key.items():
                if anchor not in arg_anchor_candidates:
                    continue
                anchor_candidates.append(
                    (int(source_line_by_src_key.get(src_key, -1)), src_key)
                )
            anchor_matched = self.__pick_java_mlk_source_key_near_line(
                anchor_candidates,
                call_arg.line_number,
            )
            if anchor_matched != "":
                return anchor_matched

        return ""

    def __get_java_mlk_source_obligation_key(self, src_value: Value) -> str:
        if self.language != "Java" or self.bug_type != "MLK":
            normalized_file = src_value.file.replace("\\", "/").lower()
            normalized_src_name = self.__normalize_java_mlk_source_name(src_value.name)
            return (
                f"{normalized_file}:UNKNOWN:src:{normalized_src_name}:{src_value.line_number}"
            )

        key = self.java_mlk_source_obligation_keys.get(str(src_value), "")
        if key != "":
            return key

        src_function = self.ts_analyzer.get_function_from_localvalue(src_value)
        function_key = (
            self.__build_java_mlk_function_signature_key(src_function)
            if src_function is not None
            else "UNKNOWN"
        )
        normalized_file = src_value.file.replace("\\", "/").lower()
        normalized_src_name = self.__normalize_java_mlk_source_name(src_value.name)
        return f"{normalized_file}:{function_key}:src:{normalized_src_name}:{src_value.line_number}"

    def __get_java_mlk_source_obligation_family_key(self, src_value: Value) -> str:
        if self.language != "Java" or self.bug_type != "MLK":
            return self.__derive_java_mlk_obligation_family_key(
                src_value, self.__get_java_mlk_source_obligation_key(src_value)
            )
        src_key = str(src_value)
        family_key = self.java_mlk_source_obligation_family_keys.get(src_key, "")
        if family_key != "":
            return family_key
        obligation_key = self.__get_java_mlk_source_obligation_key(src_value)
        return self.__derive_java_mlk_obligation_family_key(src_value, obligation_key)

    def __get_java_mlk_source_obligation_component_key(self, src_value: Value) -> str:
        if self.language != "Java" or self.bug_type != "MLK":
            return self.__get_java_mlk_source_obligation_family_key(src_value)
        src_key = str(src_value)
        component_key = self.java_mlk_source_obligation_component_keys.get(src_key, "")
        if component_key != "":
            return component_key
        # Conservative fallback: family-level key.
        return self.__get_java_mlk_source_obligation_family_key(src_value)

    def __build_detect_info_payload(
        self, bug_reports: Dict[int, "BugReport"]
    ) -> Dict[int, dict]:
        return {
            bug_report_id: bug.to_dict()
            for bug_report_id, bug in bug_reports.items()
        }

    def __build_detect_info_by_file_payload(
        self, bug_reports: Dict[int, "BugReport"]
    ) -> Dict[str, dict]:
        grouped: Dict[str, Dict[str, object]] = {}
        uid_to_function: Dict[str, Function] = {}
        if self.language == "Java" and self.bug_type == "MLK":
            for function in self.ts_analyzer.function_env.values():
                function_uid = (
                    function.function_uid
                    if function.function_uid != ""
                    else self.__build_java_mlk_function_signature_key(function)
                )
                uid_to_function[function_uid] = function

        for bug_report_id in sorted(bug_reports.keys()):
            bug_report = bug_reports[bug_report_id]
            src_value = bug_report.buggy_value
            normalized_file = src_value.file.replace("\\", "/")

            if normalized_file not in grouped:
                grouped[normalized_file] = {
                    "file": normalized_file,
                    "file_name": os.path.basename(normalized_file),
                    "report_count": 0,
                    "report_ids": [],
                    "method_buckets": {},
                    "relevant_method_names": set(),
                }

            file_entry = grouped[normalized_file]
            file_entry["report_count"] = int(file_entry["report_count"]) + 1
            report_ids = cast(List[int], file_entry["report_ids"])
            report_ids.append(bug_report_id)

            for function in bug_report.relevant_functions.values():
                cast(Set[str], file_entry["relevant_method_names"]).add(
                    function.function_name
                )

            metadata = bug_report.metadata if hasattr(bug_report, "metadata") else {}
            source_line = int(metadata.get("source_line", src_value.line_number))
            source_method_uid = str(metadata.get("source_method_uid", "")).strip()
            source_method_name = str(metadata.get("source_method_name", "")).strip()

            method_uid = source_method_uid
            method_name = source_method_name
            method_start_line = -1
            method_end_line = -1
            helper_like = False
            if method_uid != "":
                method_function = uid_to_function.get(method_uid)
                if method_function is not None:
                    method_start_line = method_function.start_line_number
                    method_end_line = method_function.end_line_number
                    helper_like = self.__is_java_mlk_helper_function_for_dedup(
                        method_function
                    )
                if method_name == "":
                    method_name = (
                        method_function.function_name
                        if method_function is not None
                        else "UNKNOWN_METHOD"
                    )
            else:
                src_function = self.ts_analyzer.get_function_from_localvalue(src_value)
                if src_function is not None:
                    method_uid = (
                        src_function.function_uid
                        if src_function.function_uid != ""
                        else self.__build_java_mlk_function_signature_key(src_function)
                    )
                    method_name = src_function.function_name
                    method_start_line = src_function.start_line_number
                    method_end_line = src_function.end_line_number
                    helper_like = self.__is_java_mlk_helper_function_for_dedup(
                        src_function
                    )
                else:
                    method_uid = (
                        f"{normalized_file}:UNKNOWN_METHOD:{src_value.line_number}"
                    )
                    method_name = "UNKNOWN_METHOD"
                    method_start_line = -1
                    method_end_line = -1
                    helper_like = False
            if method_name == "":
                method_name = "UNKNOWN_METHOD"

            method_buckets = cast(Dict[str, Dict[str, object]], file_entry["method_buckets"])
            if method_uid not in method_buckets:
                method_buckets[method_uid] = {
                    "method_name": method_name,
                    "method_uid": method_uid,
                    "method_start_line": method_start_line,
                    "method_end_line": method_end_line,
                    "source_lines": set(),
                    "report_ids": [],
                    "report_count": 0,
                    "helper_like": helper_like,
                    "weak_evidence_count": 0,
                    "no_sink_marker_count": 0,
                    "weak_release_marker_count": 0,
                    "explanation_hit_count": 0,
                    "chain_support_count": 0,
                    "leak_root_hit_count": 0,
                    "source_high_confidence_count": 0,
                    "source_medium_confidence_count": 0,
                    "source_low_confidence_count": 0,
                }

            method_entry = method_buckets[method_uid]
            cast(Set[int], method_entry["source_lines"]).add(source_line)
            cast(List[int], method_entry["report_ids"]).append(bug_report_id)
            method_entry["report_count"] = int(method_entry["report_count"]) + 1
            guarantee_level = normalize_guarantee_level(
                str(metadata.get("guarantee_level", GUARANTEE_NONE))
            )
            if not is_all_exit_guaranteed(guarantee_level):
                method_entry["weak_evidence_count"] = int(
                    method_entry["weak_evidence_count"]
                ) + 1
            if bool(metadata.get("has_no_sink_marker", False)):
                method_entry["no_sink_marker_count"] = int(
                    method_entry["no_sink_marker_count"]
                ) + 1
            if bool(metadata.get("has_weak_release_marker", False)):
                method_entry["weak_release_marker_count"] = int(
                    method_entry["weak_release_marker_count"]
                ) + 1
            confidence = self.__normalize_java_mlk_source_confidence(
                str(metadata.get("source_confidence", "medium"))
            )
            if confidence == "high":
                method_entry["source_high_confidence_count"] = int(
                    method_entry["source_high_confidence_count"]
                ) + 1
            elif confidence == "medium":
                method_entry["source_medium_confidence_count"] = int(
                    method_entry["source_medium_confidence_count"]
                ) + 1
            else:
                method_entry["source_low_confidence_count"] = int(
                    method_entry["source_low_confidence_count"]
                ) + 1
            explanation_lower = bug_report.explanation.lower()
            if method_name != "UNKNOWN_METHOD" and method_name.lower() in explanation_lower:
                method_entry["explanation_hit_count"] = int(
                    method_entry["explanation_hit_count"]
                ) + 1
            leak_root_uid = str(metadata.get("leak_root_method_uid", "")).strip()
            if leak_root_uid != "" and leak_root_uid == method_uid:
                method_entry["leak_root_hit_count"] = int(
                    method_entry["leak_root_hit_count"]
                ) + 1

            # Add supporting methods from inter-procedural chain so primary
            # defect method can be chosen from relevant non-source methods too.
            for relevant_function in bug_report.relevant_functions.values():
                relevant_method_uid = (
                    relevant_function.function_uid
                    if relevant_function.function_uid != ""
                    else self.__build_java_mlk_function_signature_key(relevant_function)
                )
                if relevant_method_uid not in method_buckets:
                    method_buckets[relevant_method_uid] = {
                        "method_name": relevant_function.function_name,
                        "method_uid": relevant_method_uid,
                        "method_start_line": relevant_function.start_line_number,
                        "method_end_line": relevant_function.end_line_number,
                        "source_lines": set(),
                        "report_ids": [],
                        "report_count": 0,
                        "helper_like": self.__is_java_mlk_helper_function_for_dedup(
                            relevant_function
                        ),
                        "weak_evidence_count": 0,
                        "no_sink_marker_count": 0,
                        "weak_release_marker_count": 0,
                        "explanation_hit_count": 0,
                        "chain_support_count": 0,
                        "leak_root_hit_count": 0,
                        "source_high_confidence_count": 0,
                        "source_medium_confidence_count": 0,
                        "source_low_confidence_count": 0,
                    }
                if relevant_method_uid == method_uid:
                    continue
                relevant_entry = method_buckets[relevant_method_uid]
                relevant_entry["chain_support_count"] = int(
                    relevant_entry["chain_support_count"]
                ) + 1
                if leak_root_uid != "" and leak_root_uid == relevant_method_uid:
                    relevant_entry["leak_root_hit_count"] = int(
                        relevant_entry["leak_root_hit_count"]
                    ) + 1
                if (
                    relevant_function.function_name != "UNKNOWN_METHOD"
                    and relevant_function.function_name.lower() in explanation_lower
                ):
                    relevant_entry["explanation_hit_count"] = int(
                        relevant_entry["explanation_hit_count"]
                    ) + 1

        payload: Dict[str, dict] = {}
        for file_key in sorted(grouped.keys()):
            file_entry = grouped[file_key]
            method_buckets = cast(Dict[str, Dict[str, object]], file_entry["method_buckets"])
            leaking_methods: List[Dict[str, object]] = []
            method_candidates: List[Tuple[str, float, Dict[str, object]]] = []
            for method_key in sorted(method_buckets.keys()):
                method_entry = method_buckets[method_key]
                method_score = self.__score_java_mlk_method_bucket(method_entry)
                method_candidates.append((method_key, method_score, method_entry))
                leaking_methods.append(
                    {
                        "method_name": str(method_entry["method_name"]),
                        "method_uid": str(method_entry["method_uid"]),
                        "method_start_line": int(method_entry["method_start_line"]),
                        "method_end_line": int(method_entry["method_end_line"]),
                        "source_lines": sorted(cast(Set[int], method_entry["source_lines"])),
                        "report_ids": sorted(cast(List[int], method_entry["report_ids"])),
                        "report_count": int(method_entry["report_count"]),
                        "helper_like": bool(method_entry["helper_like"]),
                        "weak_evidence_count": int(method_entry["weak_evidence_count"]),
                        "no_sink_marker_count": int(method_entry["no_sink_marker_count"]),
                        "weak_release_marker_count": int(
                            method_entry["weak_release_marker_count"]
                        ),
                        "source_high_confidence_count": int(
                            method_entry["source_high_confidence_count"]
                        ),
                        "source_medium_confidence_count": int(
                            method_entry["source_medium_confidence_count"]
                        ),
                        "source_low_confidence_count": int(
                            method_entry["source_low_confidence_count"]
                        ),
                        "explanation_hit_count": int(method_entry["explanation_hit_count"]),
                        "chain_support_count": int(method_entry["chain_support_count"]),
                        "leak_root_hit_count": int(method_entry["leak_root_hit_count"]),
                        "forwarding_suspect": self.__is_java_mlk_forwarding_method_entry(
                            method_entry
                        ),
                        "method_score": method_score,
                    }
                )

            primary_method_name = "UNKNOWN_METHOD"
            primary_method_uid = ""
            primary_confidence = 0.0
            supporting_methods: List[str] = []
            if len(method_candidates) > 0:
                (
                    primary_method_uid,
                    primary_method_name,
                    primary_confidence,
                ) = self.__select_java_mlk_primary_method_from_candidates(
                    method_candidates
                )
                supporting_methods = sorted(
                    {
                        str(entry["method_name"])
                        for uid, _, entry in method_candidates
                        if str(uid) != primary_method_uid
                        if str(entry["method_name"]) != ""
                    }
                )

            payload[file_key] = {
                "file": str(file_entry["file"]),
                "file_name": str(file_entry["file_name"]),
                "report_count": int(file_entry["report_count"]),
                "report_ids": sorted(cast(List[int], file_entry["report_ids"])),
                "method_count": len(leaking_methods),
                "primary_defect_method": primary_method_name,
                "primary_defect_method_uid": primary_method_uid,
                "primary_confidence": primary_confidence,
                "leaking_methods": leaking_methods,
                "supporting_methods": supporting_methods,
                "related_methods": sorted(
                    cast(Set[str], file_entry["relevant_method_names"])
                ),
            }

        return payload

    def __java_mlk_method_local_evidence_count(
        self, method_entry: Dict[str, object]
    ) -> float:
        weak_evidence_count = float(int(method_entry.get("weak_evidence_count", 0)))
        no_sink_marker_count = float(int(method_entry.get("no_sink_marker_count", 0)))
        weak_release_marker_count = float(
            int(method_entry.get("weak_release_marker_count", 0))
        )
        source_line_count = float(
            len(cast(Set[int], method_entry.get("source_lines", set())))
        )
        report_count = float(int(method_entry.get("report_count", 0)))
        local_count = weak_evidence_count + no_sink_marker_count + weak_release_marker_count
        if report_count > 0 and source_line_count > 0:
            local_count += 0.5
        return local_count

    def __score_java_mlk_method_bucket(self, method_entry: Dict[str, object]) -> float:
        report_count = float(int(method_entry.get("report_count", 0)))
        weak_evidence_count = float(int(method_entry.get("weak_evidence_count", 0)))
        no_sink_marker_count = float(int(method_entry.get("no_sink_marker_count", 0)))
        weak_release_marker_count = float(
            int(method_entry.get("weak_release_marker_count", 0))
        )
        source_high_confidence_count = float(
            int(method_entry.get("source_high_confidence_count", 0))
        )
        source_medium_confidence_count = float(
            int(method_entry.get("source_medium_confidence_count", 0))
        )
        source_low_confidence_count = float(
            int(method_entry.get("source_low_confidence_count", 0))
        )
        explanation_hit_count = float(int(method_entry.get("explanation_hit_count", 0)))
        chain_support_count = float(int(method_entry.get("chain_support_count", 0)))
        leak_root_hit_count = float(int(method_entry.get("leak_root_hit_count", 0)))
        helper_like = bool(method_entry.get("helper_like", False))
        method_name = str(method_entry.get("method_name", ""))
        source_line_count = float(len(cast(Set[int], method_entry.get("source_lines", set()))))

        local_evidence_count = self.__java_mlk_method_local_evidence_count(method_entry)
        score = 3.0 * report_count
        score += 7.5 * weak_evidence_count
        score += 10.0 * no_sink_marker_count
        score += 8.0 * weak_release_marker_count
        score += 4.0 * source_high_confidence_count
        score += 2.0 * source_medium_confidence_count
        score -= 1.0 * source_low_confidence_count
        score += 2.5 * explanation_hit_count
        if report_count > 0:
            score += 0.8 * chain_support_count
            score += 6.0 * leak_root_hit_count
        else:
            score += 0.25 * chain_support_count
            score += 1.5 * leak_root_hit_count
        score += 1.0 * source_line_count
        if local_evidence_count <= 0 and chain_support_count > 0:
            # Supporting-only methods (no direct source evidence) should rarely
            # become primary defect method.
            score -= 12.0
        if report_count > 0 and local_evidence_count <= 0:
            # Report-backed but lacking local leak evidence is suspicious.
            score -= 5.0
        if report_count == 0:
            score -= 12.0
        if helper_like:
            score -= 8.0
        if method_name == "UNKNOWN_METHOD":
            score -= 5.0
        if self.JAVA_IDENTIFIER_RE.fullmatch(method_name) is None:
            # Decompiled or parser-noisy names are rarely reliable defect methods.
            score -= 10.0
        generic_method_names = {
            "run",
            "main",
            "call",
            "execute",
            "process",
            "load",
            "write",
            "read",
        }
        if method_name.lower() in generic_method_names:
            score -= 3.0
        if self.__is_java_mlk_forwarding_method_entry(method_entry):
            score -= 6.0
        return score

    def __is_java_mlk_forwarding_method_entry(
        self, method_entry: Dict[str, object]
    ) -> bool:
        """
        Heuristic: local source method that mainly forwards resource to downstream
        methods and lacks direct leak evidence in explanation/markers.
        """
        report_count = int(method_entry.get("report_count", 0))
        chain_support_count = int(method_entry.get("chain_support_count", 0))
        weak_evidence_count = int(method_entry.get("weak_evidence_count", 0))
        no_sink_marker_count = int(method_entry.get("no_sink_marker_count", 0))
        weak_release_marker_count = int(method_entry.get("weak_release_marker_count", 0))
        explanation_hit_count = int(method_entry.get("explanation_hit_count", 0))
        leak_root_hit_count = int(method_entry.get("leak_root_hit_count", 0))
        method_name = str(method_entry.get("method_name", "")).strip().lower()
        if report_count <= 0:
            return False
        if chain_support_count <= 0:
            return False
        if no_sink_marker_count > 0 or weak_release_marker_count > 0:
            return False
        if explanation_hit_count > 0:
            return False
        if leak_root_hit_count > 0:
            return False

        forwardish_names = {
            "get",
            "open",
            "create",
            "build",
            "load",
            "readfile",
            "writefile",
            "copy",
            "parse",
        }
        if method_name in forwardish_names:
            return True

        # If weak evidence only comes from upstream semantics while method itself
        # mostly serves as chain entry, treat as forwarding-like.
        return weak_evidence_count <= report_count

    def __select_java_mlk_primary_method_from_candidates(
        self,
        method_candidates: List[Tuple[str, float, Dict[str, object]]],
    ) -> Tuple[str, str, float]:
        if len(method_candidates) == 0:
            return "", "UNKNOWN_METHOD", 0.0

        def _candidate_sort_key(
            item: Tuple[str, float, Dict[str, object]]
        ) -> Tuple[float, int, str]:
            return (
                -item[1],
                int(item[2].get("method_start_line", -1)),
                str(item[2].get("method_name", "")),
            )

        method_candidates.sort(
            key=_candidate_sort_key
        )

        source_evidence_candidates: List[Tuple[str, float, Dict[str, object]]] = []
        eligible_candidates: List[Tuple[str, float, Dict[str, object]]] = []
        report_backed_candidates: List[Tuple[str, float, Dict[str, object]]] = []
        report_backed_local_candidates: List[Tuple[str, float, Dict[str, object]]] = []
        for method_uid, method_score, method_entry in method_candidates:
            report_count = int(method_entry.get("report_count", 0))
            local_evidence_count = self.__java_mlk_method_local_evidence_count(
                method_entry
            )
            if report_count > 0:
                report_backed_candidates.append((method_uid, method_score, method_entry))
                if local_evidence_count > 0:
                    report_backed_local_candidates.append(
                        (method_uid, method_score, method_entry)
                    )
            if bool(method_entry.get("helper_like", False)):
                continue
            if self.__is_java_mlk_forwarding_method_entry(method_entry):
                continue
            eligible_candidates.append((method_uid, method_score, method_entry))
            if report_count > 0 and local_evidence_count > 0:
                source_evidence_candidates.append((method_uid, method_score, method_entry))

        if len(source_evidence_candidates) > 0:
            ranked_candidates = sorted(source_evidence_candidates, key=_candidate_sort_key)
        elif len(report_backed_local_candidates) > 0:
            ranked_candidates = sorted(report_backed_local_candidates, key=_candidate_sort_key)
        elif len(report_backed_candidates) > 0:
            ranked_candidates = sorted(report_backed_candidates, key=_candidate_sort_key)
        elif len(eligible_candidates) > 0:
            ranked_candidates = sorted(eligible_candidates, key=_candidate_sort_key)
        else:
            ranked_candidates = method_candidates
        primary_uid, primary_score, primary_entry = ranked_candidates[0]
        primary_name = str(primary_entry.get("method_name", "UNKNOWN_METHOD"))

        if len(ranked_candidates) == 1:
            primary_confidence = 1.0
        else:
            second_score = ranked_candidates[1][1]
            normalized_gap = (primary_score - second_score) / max(1.0, abs(primary_score))
            primary_confidence = max(0.0, min(1.0, 0.5 + 0.5 * normalized_gap))

        return str(primary_uid), primary_name, primary_confidence

    def __build_java_mlk_issue_component_signature_from_report(
        self, bug_report: "BugReport"
    ) -> Tuple[str, str, str, str]:
        metadata = bug_report.metadata if hasattr(bug_report, "metadata") else {}
        source_file = str(
            metadata.get("source_file", bug_report.buggy_value.file)
        ).replace("\\", "/").lower()
        src_key = str(bug_report.buggy_value)
        pre_component_id = self.java_mlk_source_component_id_by_key.get(src_key)
        if pre_component_id is not None:
            component_key = f"pre_component:{pre_component_id}"
        else:
            component_key = str(
                metadata.get(
                    "obligation_component_key",
                    self.__get_java_mlk_source_obligation_component_key(
                        bug_report.buggy_value
                    ),
                )
            )
        resource_kind = normalize_resource_kind(
            str(metadata.get("resource_kind", RESOURCE_KIND_AUTOCLOSEABLE))
        )
        guarantee_level = normalize_guarantee_level(
            str(metadata.get("guarantee_level", GUARANTEE_NONE))
        )
        guarantee_class = (
            "strong" if is_all_exit_guaranteed(guarantee_level) else "weak_or_unknown"
        )
        return (
            source_file,
            component_key,
            resource_kind,
            guarantee_class,
        )

    def __build_java_mlk_issue_reports_from_raw(
        self, bug_reports: Dict[int, "BugReport"]
    ) -> Tuple[Dict[int, "BugReport"], Dict[str, object]]:
        if self.language != "Java" or self.bug_type != "MLK":
            return dict(bug_reports), {
                "mode": "issue_online_component",
                "raw_report_count": len(bug_reports),
                "issue_count": len(bug_reports),
                "pre_signature_group_count": len(bug_reports),
                "graph_merge_count": 0,
                "reduced_report_count": 0,
                "reduction_ratio": 0.0,
            }

        raw_count = len(bug_reports)
        if raw_count == 0:
            return {}, {
                "mode": "issue_online_component",
                "raw_report_count": 0,
                "issue_count": 0,
                "pre_signature_group_count": 0,
                "graph_merge_count": 0,
                "reduced_report_count": 0,
                "reduction_ratio": 0.0,
            }

        signatures: List[Tuple[str, str, str, str]] = []
        member_ids_by_signature: Dict[Tuple[str, str, str, str], List[int]] = defaultdict(list)
        for bug_report_id in sorted(bug_reports.keys()):
            signature = self.__build_java_mlk_issue_component_signature_from_report(
                bug_reports[bug_report_id]
            )
            member_ids_by_signature[signature].append(bug_report_id)
        signatures = sorted(member_ids_by_signature.keys())
        pre_signature_group_count = len(signatures)

        uid_to_function_id: Dict[str, int] = {}
        for function in self.ts_analyzer.function_env.values():
            function_uid = (
                function.function_uid
                if function.function_uid != ""
                else self.__build_java_mlk_function_signature_key(function)
            )
            uid_to_function_id[function_uid] = function.function_id
        call_out = self.ts_analyzer.function_caller_callee_map
        call_in = self.ts_analyzer.function_callee_caller_map

        def _coarse_family_anchor(component_key: str) -> str:
            if ":component:" in component_key:
                suffix = component_key.split(":component:", 1)[1]
            elif ":family:" in component_key:
                suffix = component_key.split(":family:", 1)[1]
            else:
                suffix = component_key
            parts = [part for part in suffix.split(":") if part != ""]
            if len(parts) >= 2:
                return ":".join(parts[:2])
            if len(parts) == 1:
                return parts[0]
            return suffix

        def _min_line_gap(lines_a: Set[int], lines_b: Set[int]) -> int:
            filtered_a = [line for line in lines_a if line >= 0]
            filtered_b = [line for line in lines_b if line >= 0]
            if len(filtered_a) == 0 or len(filtered_b) == 0:
                return 10**9
            return min(
                abs(line_a - line_b) for line_a in filtered_a for line_b in filtered_b
            )

        hop_cache: Dict[Tuple[str, str], bool] = {}

        def _short_hop_related(fid_a: int, fid_b: int, max_hops: int) -> bool:
            if fid_a == fid_b:
                return True
            queue: deque[Tuple[int, int]] = deque([(fid_a, 0)])
            visited: Set[int] = {fid_a}
            while len(queue) > 0:
                current_id, hop = queue.popleft()
                if hop >= max_hops:
                    continue
                neighbors = set(call_out.get(current_id, set()))
                neighbors.update(call_in.get(current_id, set()))
                for next_id in neighbors:
                    if next_id == fid_b:
                        return True
                    if next_id in visited:
                        continue
                    visited.add(next_id)
                    queue.append((next_id, hop + 1))
            return False

        def _method_sets_related_by_hops(
            method_uids_a: Set[str], method_uids_b: Set[str], max_pairs: int = 36
        ) -> bool:
            uid_pairs: List[Tuple[str, str]] = []
            for uid_a in sorted(method_uids_a):
                if uid_a == "":
                    continue
                for uid_b in sorted(method_uids_b):
                    if uid_b == "":
                        continue
                    if uid_a == uid_b:
                        return True
                    pair = (uid_a, uid_b) if uid_a <= uid_b else (uid_b, uid_a)
                    uid_pairs.append(pair)
            if len(uid_pairs) == 0:
                return False
            uid_pairs = sorted(set(uid_pairs))
            if len(uid_pairs) > max_pairs:
                uid_pairs = uid_pairs[:max_pairs]
            for uid_a, uid_b in uid_pairs:
                cache_key = (uid_a, uid_b)
                if cache_key in hop_cache:
                    if hop_cache[cache_key]:
                        return True
                    continue
                fid_a = uid_to_function_id.get(uid_a)
                fid_b = uid_to_function_id.get(uid_b)
                if fid_a is None or fid_b is None:
                    hop_cache[cache_key] = False
                    continue
                related = _short_hop_related(
                    fid_a, fid_b, self.java_mlk_issue_merge_hops
                )
                hop_cache[cache_key] = related
                if related:
                    return True
            return False

        feature_by_signature: Dict[Tuple[str, str, str, str], Dict[str, object]] = {}
        for signature in signatures:
            member_ids = sorted(set(member_ids_by_signature[signature]))
            method_uids: Set[str] = set()
            source_symbols: Set[str] = set()
            leak_root_uids: Set[str] = set()
            source_lines: Set[int] = set()
            component_keys: Set[str] = set()
            source_method_uids: Set[str] = set()
            for member_id in member_ids:
                bug_report = bug_reports[member_id]
                metadata = bug_report.metadata if hasattr(bug_report, "metadata") else {}
                source_method_uid = str(metadata.get("source_method_uid", "")).strip()
                if source_method_uid != "":
                    source_method_uids.add(source_method_uid)
                    method_uids.add(source_method_uid)
                leak_root_uid = str(metadata.get("leak_root_method_uid", "")).strip()
                if leak_root_uid != "":
                    leak_root_uids.add(leak_root_uid)
                    method_uids.add(leak_root_uid)
                relevant_uids = metadata.get("relevant_method_uids", [])
                if isinstance(relevant_uids, list):
                    for uid in relevant_uids:
                        uid_str = str(uid).strip()
                        if uid_str != "":
                            method_uids.add(uid_str)
                source_symbols.add(str(metadata.get("source_symbol", "unknown")).lower())
                source_lines.add(int(metadata.get("source_line", -1)))
                try:
                    component_id = int(metadata.get("source_component_id", -1))
                except Exception:
                    component_id = -1
                if component_id >= 0:
                    component_key = f"pre_component:{component_id}"
                else:
                    component_key = str(
                        metadata.get("obligation_component_key", "")
                    ).strip()
                if component_key != "":
                    component_keys.add(component_key)

            feature_by_signature[signature] = {
                "member_ids": member_ids,
                "method_uids": method_uids,
                "source_method_uids": source_method_uids,
                "source_symbols": source_symbols,
                "leak_root_uids": leak_root_uids,
                "source_lines": source_lines,
                "component_keys": component_keys,
                "family_anchor": _coarse_family_anchor(signature[1]),
            }

        parent: Dict[int, int] = {idx: idx for idx in range(len(signatures))}

        def _find_root(idx: int) -> int:
            current = idx
            while parent[current] != current:
                parent[current] = parent[parent[current]]
                current = parent[current]
            return current

        def _union(idx_a: int, idx_b: int) -> bool:
            root_a = _find_root(idx_a)
            root_b = _find_root(idx_b)
            if root_a == root_b:
                return False
            if signatures[root_a] <= signatures[root_b]:
                parent[root_b] = root_a
            else:
                parent[root_a] = root_b
            return True

        graph_merge_count = 0
        for idx_a in range(len(signatures)):
            sig_a = signatures[idx_a]
            feature_a = feature_by_signature[sig_a]
            for idx_b in range(idx_a + 1, len(signatures)):
                sig_b = signatures[idx_b]
                if (
                    sig_a[0] != sig_b[0]
                    or sig_a[2] != sig_b[2]
                    or sig_a[3] != sig_b[3]
                ):
                    continue
                feature_b = feature_by_signature[sig_b]

                method_uids_a = cast(Set[str], feature_a["method_uids"])
                method_uids_b = cast(Set[str], feature_b["method_uids"])
                source_method_uids_a = cast(Set[str], feature_a["source_method_uids"])
                source_method_uids_b = cast(Set[str], feature_b["source_method_uids"])
                symbols_a = cast(Set[str], feature_a["source_symbols"])
                symbols_b = cast(Set[str], feature_b["source_symbols"])
                leak_roots_a = cast(Set[str], feature_a["leak_root_uids"])
                leak_roots_b = cast(Set[str], feature_b["leak_root_uids"])
                source_lines_a = cast(Set[int], feature_a["source_lines"])
                source_lines_b = cast(Set[int], feature_b["source_lines"])
                component_keys_a = cast(Set[str], feature_a["component_keys"])
                component_keys_b = cast(Set[str], feature_b["component_keys"])
                family_anchor_a = str(feature_a["family_anchor"])
                family_anchor_b = str(feature_b["family_anchor"])

                symbols_intersection = symbols_a & symbols_b
                method_intersection = method_uids_a & method_uids_b
                source_method_intersection = source_method_uids_a & source_method_uids_b
                leak_root_intersection = leak_roots_a & leak_roots_b
                component_intersection = component_keys_a & component_keys_b
                min_line_gap = _min_line_gap(source_lines_a, source_lines_b)

                should_merge = False
                if len(component_intersection) > 0:
                    should_merge = True
                elif len(source_method_intersection) > 0 and len(symbols_intersection) > 0:
                    should_merge = True
                elif len(method_intersection) > 0 and min_line_gap <= 4:
                    should_merge = True
                elif len(leak_root_intersection) > 0 and len(symbols_intersection) > 0:
                    should_merge = True
                elif (
                    family_anchor_a != ""
                    and family_anchor_a == family_anchor_b
                    and len(symbols_intersection) > 0
                    and _method_sets_related_by_hops(method_uids_a, method_uids_b)
                    and min_line_gap <= 18
                ):
                    should_merge = True
                elif (
                    len(symbols_intersection) > 0
                    and _method_sets_related_by_hops(method_uids_a, method_uids_b)
                    and min_line_gap <= 10
                ):
                    should_merge = True

                if should_merge and _union(idx_a, idx_b):
                    graph_merge_count += 1

        component_member_ids: Dict[int, List[int]] = defaultdict(list)
        component_signatures: Dict[int, List[Tuple[str, str, str, str]]] = defaultdict(list)
        for idx, signature in enumerate(signatures):
            root_idx = _find_root(idx)
            component_member_ids[root_idx].extend(member_ids_by_signature[signature])
            component_signatures[root_idx].append(signature)

        issue_reports: Dict[int, BugReport] = {}
        component_roots = sorted(
            component_member_ids.keys(),
            key=lambda rid: min(component_member_ids[rid]),
        )
        for issue_idx, root_idx in enumerate(component_roots):
            member_ids = sorted(set(component_member_ids[root_idx]))
            method_buckets = self.__build_java_mlk_method_buckets_for_member_reports(
                member_ids, bug_reports
            )
            method_candidates: List[Tuple[str, float, Dict[str, object]]] = []
            for method_uid, method_entry in method_buckets.items():
                method_score = self.__score_java_mlk_method_bucket(method_entry)
                method_candidates.append((method_uid, method_score, method_entry))
            (
                primary_method_uid,
                primary_method_name,
                primary_method_confidence,
            ) = self.__select_java_mlk_primary_method_from_candidates(method_candidates)

            representative_id = member_ids[0]
            best_rep_score = -10**9
            for candidate_id in member_ids:
                candidate_report = bug_reports[candidate_id]
                candidate_metadata = (
                    candidate_report.metadata
                    if hasattr(candidate_report, "metadata")
                    else {}
                )
                confidence_rank = self.__java_mlk_source_confidence_rank(
                    str(candidate_metadata.get("source_confidence", "medium"))
                )
                marker_bonus = int(
                    bool(candidate_metadata.get("has_no_sink_marker", False))
                ) + int(bool(candidate_metadata.get("has_weak_release_marker", False)))
                candidate_method_uid = str(
                    candidate_metadata.get(
                        "source_method_uid",
                        candidate_metadata.get("leak_root_method_uid", ""),
                    )
                ).strip()
                primary_match_bonus = (
                    1 if primary_method_uid != "" and candidate_method_uid == primary_method_uid else 0
                )
                candidate_score = confidence_rank * 100 + marker_bonus * 10 + primary_match_bonus
                if candidate_score > best_rep_score:
                    best_rep_score = candidate_score
                    representative_id = candidate_id
                elif candidate_score == best_rep_score and candidate_id < representative_id:
                    representative_id = candidate_id

            representative_report = bug_reports[representative_id]
            merged_relevant_functions: Dict[int, Function] = {}
            source_lines: Set[int] = set()
            source_method_uids: Set[str] = set()
            source_method_names: Set[str] = set()
            component_keys: Set[str] = set()
            leak_root_uids: Set[str] = set()
            leak_root_names: Set[str] = set()
            for member_id in member_ids:
                member_report = bug_reports[member_id]
                for function_id, function in member_report.relevant_functions.items():
                    merged_relevant_functions[function_id] = function
                member_meta = (
                    member_report.metadata if hasattr(member_report, "metadata") else {}
                )
                source_lines.add(int(member_meta.get("source_line", -1)))
                source_method_uid = str(member_meta.get("source_method_uid", "")).strip()
                source_method_name = str(member_meta.get("source_method_name", "")).strip()
                if source_method_uid != "":
                    source_method_uids.add(source_method_uid)
                if source_method_name != "":
                    source_method_names.add(source_method_name)
                try:
                    component_id = int(member_meta.get("source_component_id", -1))
                except Exception:
                    component_id = -1
                if component_id >= 0:
                    component_key = f"pre_component:{component_id}"
                else:
                    component_key = str(
                        member_meta.get("obligation_component_key", "")
                    ).strip()
                if component_key != "":
                    component_keys.add(component_key)
                leak_root_uid = str(member_meta.get("leak_root_method_uid", "")).strip()
                leak_root_name = str(member_meta.get("leak_root_method_name", "")).strip()
                if leak_root_uid != "":
                    leak_root_uids.add(leak_root_uid)
                if leak_root_name != "":
                    leak_root_names.add(leak_root_name)

            issue_metadata = dict(
                representative_report.metadata
                if hasattr(representative_report, "metadata")
                else {}
            )
            issue_metadata["issue_mode"] = "issue_online_component"
            issue_metadata["issue_member_ids"] = member_ids
            issue_metadata["issue_member_count"] = len(member_ids)
            issue_metadata["issue_component_signatures"] = [
                [str(part) for part in signature]
                for signature in sorted(component_signatures[root_idx])
            ]
            issue_metadata["issue_component_keys"] = sorted(component_keys)
            issue_metadata["issue_source_lines"] = sorted(line for line in source_lines if line >= 0)
            issue_metadata["issue_source_method_uids"] = sorted(source_method_uids)
            issue_metadata["issue_source_methods"] = sorted(source_method_names)
            issue_metadata["issue_leak_root_method_uids"] = sorted(leak_root_uids)
            issue_metadata["issue_leak_root_methods"] = sorted(leak_root_names)
            issue_metadata["issue_primary_defect_method_uid"] = primary_method_uid
            issue_metadata["issue_primary_defect_method"] = primary_method_name
            issue_metadata["issue_primary_confidence"] = primary_method_confidence
            if primary_method_uid != "":
                issue_metadata["source_method_uid"] = primary_method_uid
            if primary_method_name != "":
                issue_metadata["source_method_name"] = primary_method_name
            if primary_method_uid != "":
                issue_metadata["leak_root_method_uid"] = primary_method_uid
            if primary_method_name != "":
                issue_metadata["leak_root_method_name"] = primary_method_name
            issue_metadata["relevant_method_uids"] = sorted(
                {
                    (
                        function.function_uid
                        if function.function_uid != ""
                        else self.__build_java_mlk_function_signature_key(function)
                    )
                    for function in merged_relevant_functions.values()
                }
            )
            sorted_source_lines = sorted(line for line in source_lines if line >= 0)
            if len(sorted_source_lines) > 0:
                issue_metadata["source_line"] = sorted_source_lines[0]

            issue_explanation = representative_report.explanation
            if len(member_ids) > 1:
                issue_explanation = (
                    issue_explanation
                    + f"\n\nIssue aggregation: merged {len(member_ids)} evidences into one issue component."
                )
            issue_report = BugReport(
                self.bug_type,
                representative_report.buggy_value,
                merged_relevant_functions,
                issue_explanation,
                metadata=issue_metadata,
                is_human_confirmed_true=representative_report.is_human_confirmed_true,
            )
            issue_reports[issue_idx] = issue_report

        issue_count = len(issue_reports)
        stats_payload: Dict[str, object] = {
            "mode": "issue_online_component",
            "raw_report_count": raw_count,
            "issue_count": issue_count,
            "pre_signature_group_count": pre_signature_group_count,
            "graph_merge_count": graph_merge_count,
            "reduced_report_count": raw_count - issue_count,
            "reduction_ratio": (
                float(raw_count - issue_count) / float(raw_count)
                if raw_count > 0
                else 0.0
            ),
        }
        return issue_reports, stats_payload

    def __build_java_mlk_issue_components_pre_llm(
        self, src_values: List[Value]
    ) -> Tuple[Dict[str, SourceInstance], List[IssueComponent], Dict[int, List[Value]]]:
        if self.language != "Java" or self.bug_type != "MLK":
            return {}, [], {}

        source_instances: List[SourceInstance] = []
        source_instances_by_key: Dict[str, SourceInstance] = {}
        source_value_by_key: Dict[str, Value] = {}
        for src_value in src_values:
            src_key = str(src_value)
            src_function = self.ts_analyzer.get_function_from_localvalue(src_value)
            source_method_uid = ""
            if src_function is not None:
                source_method_uid = (
                    src_function.function_uid
                    if src_function.function_uid != ""
                    else self.__build_java_mlk_function_signature_key(src_function)
                )
            component_key = self.__get_java_mlk_source_obligation_component_key(src_value)
            resource_kind = normalize_resource_kind(
                classify_resource_kind(src_value.name, src_value.file)
            )
            guarantee_class = "weak_or_unknown"
            source_symbol = self.__infer_java_mlk_source_symbol(src_value)
            source_file = src_value.file.replace("\\", "/").lower()
            inst = SourceInstance(
                src_key=src_key,
                src_value=src_value,
                source_file=source_file,
                source_method_uid=source_method_uid,
                obligation_component_key=component_key,
                resource_kind=resource_kind,
                guarantee_class=guarantee_class,
                source_symbol=source_symbol,
                source_line=src_value.line_number,
            )
            source_instances.append(inst)
            source_instances_by_key[src_key] = inst
            source_value_by_key[src_key] = src_value

        method_id_by_uid: Dict[str, int] = {}
        for function in self.ts_analyzer.function_env.values():
            function_uid = (
                function.function_uid
                if function.function_uid != ""
                else self.__build_java_mlk_function_signature_key(function)
            )
            method_id_by_uid[function_uid] = function.function_id

        builder = IssueGraphBuilder(
            source_instances=source_instances,
            method_id_by_uid=method_id_by_uid,
            call_out=self.ts_analyzer.function_caller_callee_map,
            call_in=self.ts_analyzer.function_callee_caller_map,
            max_method_hops=self.java_mlk_issue_merge_hops,
        )
        components = builder.connected_components()

        selector = ComponentWitnessSelector(
            source_by_key=source_instances_by_key,
            max_witness_per_component=self.java_mlk_max_witness_per_component,
        )
        component_selection: Dict[int, List[Value]] = {}
        for component in components:
            selection = selector.select(component)
            selected_values: List[Value] = []
            for src_key in selection.selected_source_keys:
                src_value = source_value_by_key.get(src_key)
                if src_value is not None:
                    selected_values.append(src_value)
            if len(selected_values) > 0:
                component_selection[component.component_id] = selected_values
        return source_instances_by_key, components, component_selection

    def __build_java_mlk_method_buckets_for_member_reports(
        self,
        member_ids: List[int],
        bug_reports: Dict[int, "BugReport"],
    ) -> Dict[str, Dict[str, object]]:
        method_buckets: Dict[str, Dict[str, object]] = {}
        for member_id in member_ids:
            bug_report = bug_reports[member_id]
            metadata = bug_report.metadata if hasattr(bug_report, "metadata") else {}
            source_method_uid = str(metadata.get("source_method_uid", "")).strip()
            source_method_name = str(metadata.get("source_method_name", "")).strip()
            source_line = int(metadata.get("source_line", -1))
            if source_method_uid == "":
                source_file_norm = bug_report.buggy_value.file.replace("\\", "/").lower()
                source_method_uid = (
                    f"{source_file_norm}:UNKNOWN_METHOD:{source_line}"
                )
            if source_method_name == "":
                source_method_name = "UNKNOWN_METHOD"

            method_start_line = -1
            method_end_line = -1
            helper_like = False
            method_uid_to_name: Dict[str, str] = {}
            for function in bug_report.relevant_functions.values():
                function_uid = (
                    function.function_uid
                    if function.function_uid != ""
                    else self.__build_java_mlk_function_signature_key(function)
                )
                method_uid_to_name[function_uid] = function.function_name
                if function_uid == source_method_uid:
                    method_start_line = function.start_line_number
                    method_end_line = function.end_line_number
                    helper_like = self.__is_java_mlk_helper_function_for_dedup(function)

            if source_method_uid not in method_buckets:
                method_buckets[source_method_uid] = {
                    "method_name": source_method_name,
                    "method_uid": source_method_uid,
                    "method_start_line": method_start_line,
                    "method_end_line": method_end_line,
                    "source_lines": set(),
                    "report_ids": [],
                    "report_count": 0,
                    "helper_like": helper_like,
                    "weak_evidence_count": 0,
                    "no_sink_marker_count": 0,
                    "weak_release_marker_count": 0,
                    "explanation_hit_count": 0,
                    "chain_support_count": 0,
                    "leak_root_hit_count": 0,
                    "source_high_confidence_count": 0,
                    "source_medium_confidence_count": 0,
                    "source_low_confidence_count": 0,
                }

            source_entry = method_buckets[source_method_uid]
            cast(Set[int], source_entry["source_lines"]).add(source_line)
            cast(List[int], source_entry["report_ids"]).append(member_id)
            source_entry["report_count"] = int(source_entry["report_count"]) + 1

            guarantee_level = normalize_guarantee_level(
                str(metadata.get("guarantee_level", GUARANTEE_NONE))
            )
            if not is_all_exit_guaranteed(guarantee_level):
                source_entry["weak_evidence_count"] = int(
                    source_entry["weak_evidence_count"]
                ) + 1
            if bool(metadata.get("has_no_sink_marker", False)):
                source_entry["no_sink_marker_count"] = int(
                    source_entry["no_sink_marker_count"]
                ) + 1
            if bool(metadata.get("has_weak_release_marker", False)):
                source_entry["weak_release_marker_count"] = int(
                    source_entry["weak_release_marker_count"]
                ) + 1

            confidence = self.__normalize_java_mlk_source_confidence(
                str(metadata.get("source_confidence", "medium"))
            )
            if confidence == "high":
                source_entry["source_high_confidence_count"] = int(
                    source_entry["source_high_confidence_count"]
                ) + 1
            elif confidence == "medium":
                source_entry["source_medium_confidence_count"] = int(
                    source_entry["source_medium_confidence_count"]
                ) + 1
            else:
                source_entry["source_low_confidence_count"] = int(
                    source_entry["source_low_confidence_count"]
                ) + 1

            explanation_lower = bug_report.explanation.lower()
            if source_method_name != "UNKNOWN_METHOD" and source_method_name.lower() in explanation_lower:
                source_entry["explanation_hit_count"] = int(
                    source_entry["explanation_hit_count"]
                ) + 1
            leak_root_uid = str(metadata.get("leak_root_method_uid", "")).strip()
            if leak_root_uid != "" and leak_root_uid == source_method_uid:
                source_entry["leak_root_hit_count"] = int(
                    source_entry["leak_root_hit_count"]
                ) + 1

            relevant_method_uids = metadata.get("relevant_method_uids", [])
            if isinstance(relevant_method_uids, list):
                for relevant_uid_any in relevant_method_uids:
                    relevant_uid = str(relevant_uid_any)
                    if relevant_uid == "" or relevant_uid == source_method_uid:
                        continue
                    if relevant_uid not in method_buckets:
                        relevant_name = method_uid_to_name.get(relevant_uid, "UNKNOWN_METHOD")
                        method_buckets[relevant_uid] = {
                            "method_name": relevant_name,
                            "method_uid": relevant_uid,
                            "method_start_line": -1,
                            "method_end_line": -1,
                            "source_lines": set(),
                            "report_ids": [],
                            "report_count": 0,
                            "helper_like": False,
                            "weak_evidence_count": 0,
                            "no_sink_marker_count": 0,
                            "weak_release_marker_count": 0,
                            "explanation_hit_count": 0,
                            "chain_support_count": 0,
                            "leak_root_hit_count": 0,
                            "source_high_confidence_count": 0,
                            "source_medium_confidence_count": 0,
                            "source_low_confidence_count": 0,
                        }
                    relevant_entry = method_buckets[relevant_uid]
                    relevant_entry["chain_support_count"] = int(
                        relevant_entry["chain_support_count"]
                    ) + 1
                    if leak_root_uid != "" and leak_root_uid == relevant_uid:
                        relevant_entry["leak_root_hit_count"] = int(
                            relevant_entry["leak_root_hit_count"]
                        ) + 1
                    relevant_name = str(relevant_entry["method_name"])
                    if (
                        relevant_name != "UNKNOWN_METHOD"
                        and relevant_name.lower() in explanation_lower
                    ):
                        relevant_entry["explanation_hit_count"] = int(
                            relevant_entry["explanation_hit_count"]
                        ) + 1

        return method_buckets

    def __write_detect_outputs(self) -> int:
        bug_reports = self.state.bug_reports
        raw_detect_payload = self.__build_detect_info_payload(bug_reports)
        detect_payload = raw_detect_payload
        detect_by_file_payload = self.__build_detect_info_by_file_payload(bug_reports)
        issue_count = len(raw_detect_payload)
        issue_stats: Dict[str, object] = {}
        if self.language == "Java" and self.bug_type == "MLK":
            issue_reports, issue_stats = self.__build_java_mlk_issue_reports_from_raw(
                bug_reports
            )
            detect_payload = self.__build_detect_info_payload(issue_reports)
            detect_by_file_payload = self.__build_detect_info_by_file_payload(
                issue_reports
            )
            issue_count = len(detect_payload)

        with self.lock:
            os.makedirs(self.res_dir_path, exist_ok=True)
            with open(self.res_dir_path + "/detect_info.json", "w") as bug_info_file:
                json.dump(detect_payload, bug_info_file, indent=4)
            with open(
                self.res_dir_path + "/detect_info_by_file.json", "w"
            ) as by_file_info_file:
                json.dump(detect_by_file_payload, by_file_info_file, indent=4)

            if self.language == "Java" and self.bug_type == "MLK":
                with open(
                    self.res_dir_path + "/detect_info_raw.json", "w"
                ) as raw_info_file:
                    json.dump(raw_detect_payload, raw_info_file, indent=4)
                with open(
                    self.res_dir_path + "/detect_info_issue_stats.json", "w"
                ) as issue_stats_file:
                    json.dump(issue_stats, issue_stats_file, indent=4)

        return issue_count

    def __collect_llm_usage_stats(self) -> Dict[str, object]:
        tool_entries = [
            self.intra_dfa.get_usage_stats(),
            self.path_validator.get_usage_stats(),
        ]
        tool_breakdown = {
            str(entry["tool_name"]): entry for entry in tool_entries
        }
        total_input_tokens = sum(int(entry["input_tokens"]) for entry in tool_entries)
        total_output_tokens = sum(int(entry["output_tokens"]) for entry in tool_entries)
        total_query_count = sum(int(entry["query_count"]) for entry in tool_entries)
        total_provider_total_tokens = sum(
            int(entry.get("provider_total_tokens", 0)) for entry in tool_entries
        )
        total_reasoning_tokens = sum(
            int(entry.get("reasoning_tokens", 0)) for entry in tool_entries
        )
        total_prompt_cache_hit_tokens = sum(
            int(entry.get("prompt_cache_hit_tokens", 0)) for entry in tool_entries
        )
        total_prompt_cache_miss_tokens = sum(
            int(entry.get("prompt_cache_miss_tokens", 0)) for entry in tool_entries
        )
        representative_entry = tool_entries[0] if len(tool_entries) > 0 else {}

        return {
            "model_name": self.model_name,
            "model_family": representative_entry.get("model_family", "unknown"),
            "token_count_mode": representative_entry.get(
                "token_count_mode", "model_family_estimated"
            ),
            "token_encoding_name": representative_entry.get(
                "token_encoding_name", "unknown"
            ),
            "input_tokens": total_input_tokens,
            "output_tokens": total_output_tokens,
            "total_tokens": (
                total_provider_total_tokens
                if representative_entry.get("token_count_mode") == "provider_usage"
                else total_input_tokens + total_output_tokens
            ),
            "provider_total_tokens": total_provider_total_tokens,
            "reasoning_tokens": total_reasoning_tokens,
            "prompt_cache_hit_tokens": total_prompt_cache_hit_tokens,
            "prompt_cache_miss_tokens": total_prompt_cache_miss_tokens,
            "query_count": total_query_count,
            "tool_breakdown": tool_breakdown,
        }

    def __dump_run_metrics(self, scan_total_sec: float) -> None:
        metrics_payload = {
            "schema_version": "1.0",
            "project_name": self.project_name,
            "project_path": self.project_path,
            "model_name": self.model_name,
            "language": self.language,
            "bug_type": self.bug_type,
            "run_id": Path(self.res_dir_path).name,
            "result_dir": self.res_dir_path,
            "log_dir": self.log_dir_path,
            "timing": {
                "pipeline_total_sec": None,
                "soot_facts_generation_sec": None,
                "scan_total_sec": round(scan_total_sec, 3),
            },
            "llm_usage": self.__collect_llm_usage_stats(),
        }

        metrics_path = Path(self.res_dir_path) / "run_metrics_raw.json"
        with self.lock:
            os.makedirs(self.res_dir_path, exist_ok=True)
            with open(metrics_path, "w") as metrics_file:
                json.dump(metrics_payload, metrics_file, indent=4)

    def __is_java_mlk_helper_function_for_dedup(self, function: Function) -> bool:
        if self.language != "Java" or self.bug_type != "MLK":
            return False
        file_path = function.file_path.replace("\\", "/").lower()
        function_name = function.function_name.lower()
        if file_path.endswith("/io.java"):
            return True
        if function_name in {
            "writeline",
            "writestring",
            "print",
            "println",
            "printf",
            "format",
            "debug",
            "info",
            "warn",
            "error",
            "trace",
            "log",
        } and ("/support/" in file_path or "/util/" in file_path):
            return True
        return False

    def __build_java_mlk_function_signature_key(self, function: Function) -> str:
        if function.function_uid != "":
            return function.function_uid
        normalized_path = function.file_path.replace("\\", "/").lower()
        return f"{normalized_path}:{function.function_name}:{function.start_line_number}"

    def __normalize_java_mlk_source_name(self, source_name: str) -> str:
        normalized = source_name.strip().rstrip(";")
        assign_match = re.match(r"^[^=]+=\s*(.+)$", normalized)
        if assign_match is not None and "==" not in normalized:
            normalized = assign_match.group(1).strip()
        if normalized.startswith("return "):
            normalized = normalized[len("return ") :].strip()
        normalized = re.sub(r"\s+", "", normalized)
        return normalized

    def __normalize_java_mlk_source_confidence(self, confidence: str) -> str:
        normalized = confidence.strip().lower()
        if normalized in {"high", "medium", "low"}:
            return normalized
        return "medium"

    def __java_mlk_source_confidence_rank(self, confidence: str) -> int:
        normalized = self.__normalize_java_mlk_source_confidence(confidence)
        if normalized == "high":
            return 3
        if normalized == "medium":
            return 2
        return 1

    def __infer_java_mlk_source_origin(self, src_value: Value) -> str:
        origin = getattr(src_value, "java_mlk_source_origin", "")
        if isinstance(origin, str) and origin.strip() != "":
            return origin.strip().lower()
        normalized_expr = self.__normalize_java_mlk_source_name(src_value.name)
        if normalized_expr.startswith("new"):
            return "new"
        if "(" in normalized_expr and ")" in normalized_expr:
            return "factory"
        return "unknown"

    def __infer_java_mlk_source_confidence(self, src_value: Value) -> str:
        confidence = getattr(src_value, "java_mlk_source_confidence", "")
        if isinstance(confidence, str) and confidence.strip() != "":
            return self.__normalize_java_mlk_source_confidence(confidence)

        origin = self.__infer_java_mlk_source_origin(src_value)
        if origin in {"new", "twr_decl", "acquire"}:
            return "high"
        if origin in {"line_pattern", "unknown"}:
            return "low"
        return "medium"

    def __infer_java_mlk_symbol_from_expression(self, expression: str) -> str:
        normalized_expr = self.__normalize_java_mlk_source_name(expression)
        creation_match = re.search(
            r"\bnew([A-Za-z_][A-Za-z0-9_]*)\s*\(",
            normalized_expr,
            re.IGNORECASE,
        )
        if creation_match is not None:
            return creation_match.group(1).lower()
        call_match = re.search(
            r"\.([A-Za-z_][A-Za-z0-9_]*)\s*\(",
            normalized_expr,
            re.IGNORECASE,
        )
        if call_match is not None:
            return call_match.group(1).lower()
        token_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)", normalized_expr)
        if token_match is not None:
            return token_match.group(1).lower()
        return "unknown"

    def __extract_java_mlk_obligation_anchor(
        self, obligation_key: str, source_symbol: str
    ) -> str:
        match = re.search(r":(root|src):([^:]+):(-?\d+)$", obligation_key)
        if match is None:
            return f"src:{source_symbol.lower()}"
        anchor_kind = match.group(1).lower()
        anchor_token = match.group(2).lower()
        if anchor_kind == "src":
            anchor_token = source_symbol.lower()
        return f"{anchor_kind}:{anchor_token}"

    def __infer_java_mlk_source_symbol(self, src_value: Value) -> str:
        return self.__infer_java_mlk_symbol_from_expression(src_value.name)

    def __derive_java_mlk_obligation_family_key(
        self, src_value: Value, obligation_key: str
    ) -> str:
        normalized_file = src_value.file.replace("\\", "/").lower()
        source_symbol = self.__infer_java_mlk_source_symbol(src_value)
        source_origin = self.__infer_java_mlk_source_origin(src_value)
        source_confidence = self.__infer_java_mlk_source_confidence(src_value)

        # Typical key: <file>:<function_key>:root:<var>:<line> or ...:src:<expr>:<line>
        match = re.search(r":(root|src):([^:]+):(-?\d+)$", obligation_key)
        if match is not None:
            anchor_kind = match.group(1)
            anchor_token = match.group(2).lower()
            if anchor_kind == "src":
                anchor_token = source_symbol
            if self.java_mlk_family_link_mode == "aggressive":
                # In aggressive mode, drop method granularity and keep file-level
                # semantic anchors so wrapper/callee chain variants can collapse.
                return (
                    f"{normalized_file}:family:{anchor_kind}:{anchor_token}:{source_symbol}"
                )
            prefix = obligation_key[: match.start()]
            return f"{prefix}:family:{anchor_kind}:{anchor_token}:{source_symbol}:{source_confidence}"

        # Fallback for malformed keys.
        if self.java_mlk_family_link_mode == "aggressive":
            return f"{normalized_file}:family:src:{source_symbol}"
        return f"{normalized_file}:family:src:{source_symbol}:{source_origin}:{source_confidence}"

    def __build_java_mlk_report_signature(
        self,
        src_value: Value,
        relevant_functions: Dict[int, Function],
    ) -> Tuple[object, ...]:
        normalized_src_file = src_value.file.replace("\\", "/").lower()
        normalized_src_name = self.__normalize_java_mlk_source_name(src_value.name)
        src_signature = f"{normalized_src_file}:{normalized_src_name}"

        source_anchor_key = ""
        non_helper_keys: List[str] = []
        fallback_keys: List[str] = []

        for function in relevant_functions.values():
            function_key = self.__build_java_mlk_function_signature_key(function)
            fallback_keys.append(function_key)

            if self.__is_java_mlk_helper_function_for_dedup(function):
                continue
            non_helper_keys.append(function_key)

            normalized_function_file = function.file_path.replace("\\", "/").lower()
            if normalized_function_file != normalized_src_file:
                continue
            if (
                function.start_line_number
                <= src_value.line_number
                <= function.end_line_number
            ):
                source_anchor_key = function_key

        if source_anchor_key == "":
            if len(non_helper_keys) > 0:
                source_anchor_key = sorted(set(non_helper_keys))[0]
            elif len(fallback_keys) > 0:
                source_anchor_key = sorted(set(fallback_keys))[0]
            else:
                source_anchor_key = "UNKNOWN"
        return (src_signature, source_anchor_key)

    def __build_java_mlk_issue_signature(
        self,
        src_value: Value,
        resource_kind: str = RESOURCE_KIND_AUTOCLOSEABLE,
        guarantee_level: str = GUARANTEE_NONE,
    ) -> Tuple[object, ...]:
        normalized_src_file = src_value.file.replace("\\", "/").lower()
        obligation_component_signature = (
            self.__get_java_mlk_source_obligation_component_key(src_value)
        )
        guarantee_class = (
            "strong" if is_all_exit_guaranteed(guarantee_level) else "weak_or_unknown"
        )
        return (
            normalized_src_file,
            obligation_component_signature,
            normalize_resource_kind(resource_kind),
            guarantee_class,
        )

    def __register_java_mlk_report_signature(
        self,
        src_value: Value,
        relevant_functions: Dict[int, Function],
    ) -> bool:
        if self.language != "Java" or self.bug_type != "MLK":
            return True
        signature = self.__build_java_mlk_report_signature(
            src_value,
            relevant_functions,
        )
        with self.lock:
            if signature in self.java_mlk_report_signatures:
                return False
            self.java_mlk_report_signatures.add(signature)
        return True

    def __post_validate_java_mlk_with_objid(
        self,
        src_value: Value,
        buggy_path: List[Value],
        values_to_functions: Dict[Value, Optional[Function]],
    ) -> Tuple[bool, str]:
        if self.language != "Java" or self.bug_type != "MLK":
            return True, "not Java MLK"
        if self.java_mlk_validator is None:
            return True, "validator disabled"
        return self.java_mlk_validator.validate_candidate(
            src_value, buggy_path, values_to_functions
        )

    def __has_java_mlk_no_sink_marker(self, path: List[Value]) -> bool:
        for value in path:
            if (
                value.label == ValueLabel.LOCAL
                and value.name.startswith("__NO_SINK_BRANCH_PATH_")
            ):
                return True
        return False

    def __has_java_mlk_weak_release_marker(self, path: List[Value]) -> bool:
        for value in path:
            if (
                value.label == ValueLabel.LOCAL
                and value.name.startswith("__WEAK_RELEASE_BRANCH_PATH_")
            ):
                return True
        return False

    def __is_java_mlk_close_biased_negative(self, explanation: str) -> bool:
        text = explanation.lower()
        if "answer: no" not in text:
            return False
        return any(
            keyword in text
            for keyword in [
                "close",
                "closed",
                "finally",
                "try-with-resources",
                "sink",
                "unlock",
                "release",
                "shutdown",
                "delete",
            ]
        )

    def __should_force_java_mlk_strict_recheck(
        self,
        buggy_path: List[Value],
        pv_explanation: str,
        release_context: str,
        guarantee_level: str,
    ) -> bool:
        if self.language != "Java" or self.bug_type != "MLK":
            return False
        weak_semantics = should_trigger_strict_recheck(release_context, guarantee_level)
        if not weak_semantics:
            return False

        has_marker_hint = self.__has_java_mlk_no_sink_marker(
            buggy_path
        ) or self.__has_java_mlk_weak_release_marker(buggy_path)
        lowered = pv_explanation.lower()
        transfer_hint = any(
            keyword in lowered
            for keyword in [
                "ownership",
                "transfer",
                "escape",
                "returned",
                "caller",
            ]
        )
        close_biased_no = self.__is_java_mlk_close_biased_negative(pv_explanation)
        return has_marker_hint or transfer_hint or close_biased_no

    def __should_accept_java_mlk_no_sink_fallback(
        self,
        buggy_path: List[Value],
        pv_explanation: str,
        guarantee_level: str,
    ) -> bool:
        if self.language != "Java" or self.bug_type != "MLK":
            return False
        has_no_sink_like = self.__has_java_mlk_no_sink_marker(
            buggy_path
        ) or self.__has_java_mlk_weak_release_marker(buggy_path)
        if not has_no_sink_like:
            return False
        if is_all_exit_guaranteed(guarantee_level):
            return False

        lowered = pv_explanation.lower()
        if "answer: no" not in lowered:
            return False
        # Respect explicit infeasibility/conflict reasoning.
        if any(
            keyword in lowered
            for keyword in [
                "branch conditions conflict",
                "infeasible",
                "contradict",
                "unreachable",
                "cannot execute",
            ]
        ):
            return False
        if self.__is_java_mlk_close_biased_negative(pv_explanation):
            return True
        if any(
            keyword in lowered
            for keyword in [
                "ownership",
                "transfer",
                "escaped",
                "escape",
                "returned",
                "caller",
            ]
        ):
            return True
        return False

    def __filter_redundant_java_mlk_paths(
        self, src_value: Value, buggy_paths: Dict[str, List[Value]]
    ) -> List[List[Value]]:
        paths = list(buggy_paths.values())
        if self.language != "Java" or self.bug_type != "MLK":
            return paths
        if len(paths) <= 1:
            return paths

        # Step 1: exact semantic dedup (order-insensitive), keeping shorter path.
        unique_by_signature: Dict[Tuple[object, ...], List[Value]] = {}
        for path in paths:
            normalized_set = self.__normalize_java_mlk_path_for_dedup(path)
            signature = self.__build_java_mlk_path_signature(
                path,
                normalized_set=normalized_set,
            )
            prev = unique_by_signature.get(signature)
            if prev is None or len(path) < len(prev):
                unique_by_signature[signature] = path
        dedup_paths = list(unique_by_signature.values())

        # Step 1.5: fold no-sink / weak-release branch variants by semantic key.
        # These branch-preserving markers are valuable, but they also create many
        # near-identical candidates that differ only by path construction details.
        marker_semantic_representatives: Dict[Tuple[object, ...], List[Value]] = {}
        non_marker_paths: List[List[Value]] = []
        for path in dedup_paths:
            has_marker = self.__has_java_mlk_no_sink_marker(
                path
            ) or self.__has_java_mlk_weak_release_marker(path)
            if not has_marker:
                non_marker_paths.append(path)
                continue
            semantic_key = self.__build_java_mlk_branch_semantic_key(path)
            prev = marker_semantic_representatives.get(semantic_key)
            if prev is None or len(path) < len(prev):
                marker_semantic_representatives[semantic_key] = path
        if len(marker_semantic_representatives) > 0:
            dedup_paths = non_marker_paths + list(
                marker_semantic_representatives.values()
            )

        # Step 2: subset pruning on normalized value sets.
        path_sets = [
            self.__normalize_java_mlk_path_for_dedup(path) for path in dedup_paths
        ]
        has_no_sink_flags = [
            self.__has_java_mlk_no_sink_marker(path) for path in dedup_paths
        ]
        keep = [True for _ in dedup_paths]

        for i in range(len(dedup_paths)):
            if not keep[i]:
                continue
            # Keep explicit no-sink branch candidates; they are high-value for
            # weak-release/no-close leakage and should not be removed only by
            # set-subset relation.
            if has_no_sink_flags[i]:
                continue
            for j in range(len(dedup_paths)):
                if i == j:
                    continue
                if len(path_sets[i]) >= len(path_sets[j]):
                    continue
                if path_sets[i].issubset(path_sets[j]):
                    keep[i] = False
                    break

        filtered_paths = [dedup_paths[i] for i in range(len(dedup_paths)) if keep[i]]
        if len(filtered_paths) < len(paths):
            self.logger.print_log(
                f"Pruned {len(paths) - len(filtered_paths)} short Java MLK candidate path(s) for source {str(src_value)}"
            )
        return filtered_paths

    def __compress_java_mlk_candidate_path(self, path: List[Value]) -> List[Value]:
        if self.language != "Java" or self.bug_type != "MLK":
            return list(path)
        compressed: List[Value] = []
        seen_non_local_values: Set[str] = set()
        for value in path:
            if value.label == ValueLabel.LOCAL:
                compressed.append(value)
                continue
            value_key = str(value)
            if value_key in seen_non_local_values:
                continue
            seen_non_local_values.add(value_key)
            compressed.append(value)
        return compressed

    def __build_java_mlk_path_validator_signature(
        self,
        path: List[Value],
        resource_kind: str,
        release_context: str,
        guarantee_level: str,
        servlet_context: bool,
    ) -> Tuple[object, ...]:
        ordered_values: List[str] = []
        has_no_sink_marker = False
        has_weak_release_marker = False
        for value in path:
            if value.label == ValueLabel.LOCAL:
                marker_name = value.name.strip()
                if marker_name.startswith("__NO_SINK_BRANCH_PATH_"):
                    has_no_sink_marker = True
                    continue
                if marker_name.startswith("__WEAK_RELEASE_BRANCH_PATH_"):
                    has_weak_release_marker = True
                    continue
                if marker_name.startswith("__RESOURCE_KIND_"):
                    continue
                if marker_name.startswith("__RELEASE_CONTEXT_"):
                    continue
                if marker_name.startswith("__GUARANTEE_LEVEL_"):
                    continue
            ordered_values.append(str(value))
        return (
            tuple(ordered_values),
            has_no_sink_marker,
            has_weak_release_marker,
            normalize_resource_kind(resource_kind),
            normalize_release_context(release_context),
            normalize_guarantee_level(guarantee_level),
            servlet_context,
        )

    def __build_java_mlk_path_signature(
        self,
        path: List[Value],
        normalized_set: Optional[Set[str]] = None,
    ) -> Tuple[object, ...]:
        if normalized_set is None:
            normalized_set = self.__normalize_java_mlk_path_for_dedup(path)
        has_no_sink_marker = False
        has_weak_release_marker = False
        resource_kind = ""
        release_context = ""
        guarantee_level = ""
        for value in path:
            if value.label != ValueLabel.LOCAL:
                continue
            marker_name = value.name.strip()
            if marker_name.startswith("__NO_SINK_BRANCH_PATH_"):
                has_no_sink_marker = True
                continue
            if marker_name.startswith("__WEAK_RELEASE_BRANCH_PATH_"):
                has_weak_release_marker = True
                continue
            decoded_kind = decode_resource_kind_marker(marker_name)
            if decoded_kind != "":
                resource_kind = decoded_kind
                continue
            decoded_release_context = decode_release_context_marker(marker_name)
            if decoded_release_context != "":
                release_context = decoded_release_context
                continue
            decoded_guarantee_level = decode_guarantee_level_marker(marker_name)
            if decoded_guarantee_level != "":
                guarantee_level = decoded_guarantee_level
                continue
        return (
            frozenset(normalized_set),
            has_no_sink_marker,
            has_weak_release_marker,
            resource_kind,
            release_context,
            guarantee_level,
        )

    def __build_java_mlk_branch_semantic_key(
        self, path: List[Value]
    ) -> Tuple[object, ...]:
        """
        Build a coarse branch-semantic key for no-sink / weak-release candidates.
        We intentionally ignore marker indexes (PATH_0/PATH_1...) and keep
        terminal shape + semantics so equivalent branch artifacts can collapse.
        """
        normalized_set = self.__normalize_java_mlk_path_for_dedup(path)
        path_signature = self.__build_java_mlk_path_signature(
            path,
            normalized_set=normalized_set,
        )
        terminal_label = "NONE"
        terminal_method_uid = "UNKNOWN"
        terminal_line = -1
        for value in reversed(path):
            if value.label == ValueLabel.LOCAL:
                continue
            terminal_label = value.label.name
            terminal_line = value.line_number
            terminal_function = self.ts_analyzer.get_function_from_localvalue(value)
            if terminal_function is not None:
                terminal_method_uid = (
                    terminal_function.function_uid
                    if terminal_function.function_uid != ""
                    else self.__build_java_mlk_function_signature_key(terminal_function)
                )
            break
        return (
            path_signature,
            terminal_label,
            terminal_method_uid,
            terminal_line,
        )

    def __normalize_java_mlk_path_for_dedup(self, path: List[Value]) -> Set[str]:
        normalized: Set[str] = set()
        for value in path:
            if value.label == ValueLabel.LOCAL:
                if value.name.startswith("__NO_SINK_BRANCH_PATH_"):
                    continue
                if value.name.startswith("__WEAK_RELEASE_BRANCH_PATH_"):
                    continue
                if value.name.startswith("__RESOURCE_KIND_"):
                    continue
                if value.name.startswith("__RELEASE_CONTEXT_"):
                    continue
                if value.name.startswith("__GUARANTEE_LEVEL_"):
                    continue
            normalized.add(str(value))
        return normalized

    def get_agent_state(self) -> DFBScanState:
        return self.state

    def get_log_files(self) -> List[str]:
        log_files = []
        log_files.append(self.log_dir_path + "/" + "dfbscan.log")
        return log_files
