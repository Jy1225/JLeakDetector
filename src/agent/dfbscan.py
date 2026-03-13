import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from tqdm import tqdm

from agent.agent import *

from tstool.dfbscan_extractor.Java.Java_MLK_extractor import Java_MLK_Extractor
from tstool.validator.java_resource_ownership_validator import JavaResourceOwnershipValidator
from tstool.validator.java_resource_semantics import (
    RESOURCE_KIND_AUTOCLOSEABLE,
    RESOURCE_KIND_LOCK,
    RESOURCE_KIND_EXECUTOR,
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
            if not os.path.exists(self.log_dir_path):
                os.makedirs(self.log_dir_path)
            self.logger = Logger(self.log_dir_path + "/" + "dfbscan.log")

            if not os.path.exists(self.res_dir_path):
                os.makedirs(self.res_dir_path)

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
        self.java_mlk_transfer_records: Dict[str, Dict[str, str]] = {}

        self.src_values, self.sink_values = self.extractor.extract_all()
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
        path_with_unknown_status: List[Value] = [],
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
                            transfer_kind, reason = (
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
                )
        return

    # TOBE deprecated
    def start_scan_sequential(self) -> None:
        self.logger.print_console("Start data-flow bug scanning...")

        # Total number of source values
        total_src_values = len(self.src_values)

        # Process each source value sequentially with a progress bar
        with tqdm(
            total=total_src_values, desc="Processing Source Values", unit="src"
        ) as pbar:
            for src_value in self.src_values:
                worklist = []
                src_function = self.ts_analyzer.get_function_from_localvalue(src_value)
                if src_function is None:
                    pbar.update(1)
                    continue

                if self.__skip_source_by_java_soot_prefilter(src_value, src_function):
                    pbar.update(1)
                    continue

                initial_context = CallContext(False)
                root_resource_kind = self.__infer_java_mlk_resource_kind(src_value)
                worklist.append((src_value, src_function, initial_context))

                while len(worklist) > 0:
                    (start_value, start_function, call_context) = worklist.pop(0)
                    if len(call_context.context) >= self.call_depth:
                        continue

                    # Construct the input for intra-procedural data-flow analysis
                    sinks_in_function = self.extractor.extract_sinks(start_function)
                    sink_values = [
                        (
                            sink.name,
                            sink.line_number - start_function.start_line_number + 1,
                        )
                        for sink in sinks_in_function
                    ]

                    call_statements = []
                    for call_site_node in start_function.function_call_site_nodes:
                        file_content = self.ts_analyzer.code_in_files[
                            start_function.file_path
                        ]
                        call_site_line_number = (
                            file_content[: call_site_node.start_byte].count("\n") + 1
                        )
                        call_site_name = file_content[
                            call_site_node.start_byte : call_site_node.end_byte
                        ]
                        call_statements.append((call_site_name, call_site_line_number))

                    ret_values = [
                        (
                            ret.name,
                            ret.line_number - start_function.start_line_number + 1,
                        )
                        for ret in (
                            start_function.retvals
                            if start_function.retvals is not None
                            else []
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
                    df_output = self.intra_dfa.invoke(
                        df_input, IntraDataFlowAnalyzerOutput
                    )
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
                            path_line_numbers = df_output.path_line_numbers_per_path[
                                path_index
                            ]
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
                        worklist.extend(delta_worklist)

                self.__collect_potential_buggy_paths(
                    src_value, (src_value, CallContext(False))
                )

                if src_value not in self.state.potential_buggy_paths:
                    pbar.update(1)
                    continue

                buggy_paths = self.__filter_redundant_java_mlk_paths(
                    src_value, self.state.potential_buggy_paths[src_value]
                )
                for buggy_path in buggy_paths:
                    values_to_functions = {
                        value: self.ts_analyzer.get_function_from_localvalue(value)
                        for value in buggy_path
                    }

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
                    pv_input = PathValidatorInput(
                        self.bug_type,
                        buggy_path,
                        values_to_functions,
                        resource_kind=path_resource_kind,
                        release_context=path_release_context,
                        guarantee_level=path_guarantee_level,
                        resource_semantic_rules=self.__build_java_mlk_path_rules(
                            path_resource_kind, path_servlet_context
                        ),
                        servlet_context=path_servlet_context,
                    )
                    pv_output = self.path_validator.invoke(
                        pv_input, PathValidatorOutput
                    )

                    if pv_output is None:
                        continue

                    should_strict_by_marker = (
                        self.__has_java_mlk_no_sink_marker(buggy_path)
                        and self.__is_java_mlk_close_biased_negative(
                            pv_output.explanation_str
                        )
                    )
                    should_strict_by_semantics = should_trigger_strict_recheck(
                        path_release_context, path_guarantee_level
                    )
                    if (
                        self.language == "Java"
                        and self.bug_type == "MLK"
                        and not pv_output.is_reachable
                        and (should_strict_by_marker or should_strict_by_semantics)
                    ):
                        strict_pv_input = PathValidatorInput(
                            self.bug_type,
                            buggy_path,
                            values_to_functions,
                            strict_branch_semantics=True,
                            resource_kind=path_resource_kind,
                            release_context=path_release_context,
                            guarantee_level=path_guarantee_level,
                            resource_semantic_rules=self.__build_java_mlk_path_rules(
                                path_resource_kind, path_servlet_context
                            ),
                            servlet_context=path_servlet_context,
                        )
                        strict_pv_output = self.path_validator.invoke(
                            strict_pv_input, PathValidatorOutput
                        )
                        if strict_pv_output is not None:
                            pv_output = strict_pv_output

                    if pv_output.is_reachable:
                        passed_post_validation, reason = (
                            self.__post_validate_java_mlk_with_objid(
                                src_value,
                                buggy_path,
                                values_to_functions,
                            )
                        )
                        if not passed_post_validation:
                            self.logger.print_log(
                                f"Skip candidate after Java MLK ownership validation: {reason}"
                            )
                            continue
                        relevant_functions = {}
                        for value in buggy_path:
                            function = self.ts_analyzer.get_function_from_localvalue(
                                value
                            )
                            if function is not None:
                                relevant_functions[function.function_id] = function

                        bug_report = BugReport(
                            self.bug_type,
                            src_value,
                            relevant_functions,
                            pv_output.explanation_str,
                        )
                        self.state.update_bug_report(bug_report)

                # Dump bug reports
                bug_report_dict = {
                    bug_report_id: bug.to_dict()
                    for bug_report_id, bug in self.state.bug_reports.items()
                }
                with open(
                    self.res_dir_path + "/detect_info.json", "w"
                ) as bug_info_file:
                    json.dump(bug_report_dict, bug_info_file, indent=4)

                # Update the progress bar
                pbar.update(1)

        # Final summary
        total_bug_number = len(self.state.bug_reports.values())
        self.logger.print_console(
            f"{total_bug_number} bug(s) was/were detected in total."
        )
        self.logger.print_console(
            f"The bug report(s) has/have been dumped to {self.res_dir_path}/detect_info.json"
        )
        self.logger.print_console("The log files are as follows:")
        for log_file in self.get_log_files():
            self.logger.print_console(log_file)
        self.logger.print_console(
            f"Soot source-level skipped source(s): {self.soot_prefilter_source_skipped}"
        )
        self.__dump_java_mlk_transfer_records()
        self.__dump_soot_source_gate_events()
        self.__dump_soot_prefilter_stats()
        self.__dump_z3_prefilter_stats()
        return

    def start_scan(self) -> None:
        self.logger.print_console("Start data-flow bug scanning in parallel...")
        self.logger.print_console(f"Max number of workers: {self.max_neural_workers}")

        # Total number of source values
        total_src_values = len(self.src_values)

        # Process each source value in parallel with a progress bar
        with tqdm(
            total=total_src_values, desc="Processing Source Values", unit="src"
        ) as pbar:
            with ThreadPoolExecutor(max_workers=self.max_neural_workers) as executor:
                futures = [
                    executor.submit(self.__process_src_value, src_value)
                    for src_value in self.src_values
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
        total_bug_number = len(self.state.bug_reports.values())
        self.logger.print_console(
            f"{total_bug_number} bug(s) was/were detected in total."
        )
        self.logger.print_console(
            f"The bug report(s) has/have been dumped to {self.res_dir_path}/detect_info.json"
        )
        self.logger.print_console("The log files are as follows:")
        for log_file in self.get_log_files():
            self.logger.print_console(log_file)
        self.logger.print_console(
            f"Soot source-level skipped source(s): {self.soot_prefilter_source_skipped}"
        )
        self.__dump_java_mlk_transfer_records()
        self.__dump_soot_source_gate_events()
        self.__dump_soot_prefilter_stats()
        self.__dump_z3_prefilter_stats()
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
        while len(worklist) > 0:
            (start_value, start_function, call_context) = worklist.pop(0)
            if len(call_context.context) > self.call_depth:
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
                worklist.extend(delta_worklist)

        # Collect potential buggy paths
        self.__collect_potential_buggy_paths(src_value, (src_value, CallContext(False)))

        # If no potential buggy paths are found, return early
        if src_value not in self.state.potential_buggy_paths:
            return

        # Validate buggy paths and generate bug reports
        buggy_paths = self.__filter_redundant_java_mlk_paths(
            src_value, self.state.potential_buggy_paths[src_value]
        )
        for buggy_path in buggy_paths:
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
            if (
                self.language == "Java"
                and self.bug_type == "MLK"
                and not pv_output.is_reachable
                and (should_strict_by_marker or should_strict_by_semantics)
            ):
                strict_reason = (
                    "marker-close-bias"
                    if should_strict_by_marker
                    else "weak-release-semantics"
                )
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

            if pv_output.is_reachable:
                passed_post_validation, reason = (
                    self.__post_validate_java_mlk_with_objid(
                        src_value, buggy_path, values_to_functions
                    )
                )
                if not passed_post_validation:
                    self.logger.print_log(
                        f"Skip candidate after Java MLK ownership validation: {reason}"
                    )
                    continue
                relevant_functions = {}
                for value in buggy_path:
                    function = self.ts_analyzer.get_function_from_localvalue(value)
                    if function is not None:
                        relevant_functions[function.function_id] = function

                bug_report = BugReport(
                    self.bug_type,
                    src_value,
                    relevant_functions,
                    pv_output.explanation_str,
                )
                self.state.update_bug_report(bug_report)
                bug_report_dict = {
                    bug_report_id: bug.to_dict()
                    for bug_report_id, bug in self.state.bug_reports.items()
                }

                with open(
                    self.res_dir_path + "/detect_info.json", "w"
                ) as bug_info_file:
                    json.dump(bug_report_dict, bug_info_file, indent=4)
        return

    def __classify_java_mlk_external_termination(self, value: Value) -> Tuple[str, str]:
        """
        Classify terminal external-style values for Java MLK when no external match exists.
        Return:
          - ("no_real_transfer", reason): should be treated as leak candidate
          - ("ownership_transfer", reason): ownership transfer and stop reporting
        """
        function = self.ts_analyzer.get_function_from_localvalue(value)

        if value.label == ValueLabel.ARG and self.java_mlk_validator is not None:
            if self.java_mlk_validator.is_non_ownership_argument(value, function):
                return (
                    "no_real_transfer",
                    "argument does not imply ownership transfer (e.g., println/logging)",
                )
            return (
                "ownership_transfer",
                "argument likely transfers ownership but inter-procedural chain is missing",
            )

        if value.label in {ValueLabel.RET, ValueLabel.OUT, ValueLabel.PARA}:
            return (
                "ownership_transfer",
                "resource escapes function boundary and ownership is treated as transferred",
            )

        return ("ownership_transfer", "default ownership transfer")

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
        self, src_value: Value, path: List[Value], reason: str
    ) -> None:
        if self.language != "Java" or self.bug_type != "MLK":
            return
        src_key = str(src_value)
        path_key = str(path)
        with self.lock:
            if src_key not in self.java_mlk_transfer_records:
                self.java_mlk_transfer_records[src_key] = {}
            self.java_mlk_transfer_records[src_key][path_key] = reason
        self.logger.print_log(
            "Classified as Java MLK responsibility transfer:", src_key, reason
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

    def __filter_redundant_java_mlk_paths(
        self, src_value: Value, buggy_paths: Dict[str, List[Value]]
    ) -> List[List[Value]]:
        paths = list(buggy_paths.values())
        if self.language != "Java" or self.bug_type != "MLK":
            return paths
        if len(paths) <= 1:
            return paths

        path_sets = [self.__normalize_java_mlk_path_for_dedup(path) for path in paths]
        keep = [True for _ in paths]

        for i in range(len(paths)):
            if not keep[i]:
                continue
            for j in range(len(paths)):
                if i == j:
                    continue
                if len(path_sets[i]) >= len(path_sets[j]):
                    continue
                if path_sets[i].issubset(path_sets[j]):
                    keep[i] = False
                    break

        filtered_paths = [paths[i] for i in range(len(paths)) if keep[i]]
        if len(filtered_paths) < len(paths):
            self.logger.print_log(
                f"Pruned {len(paths) - len(filtered_paths)} short Java MLK candidate path(s) for source {str(src_value)}"
            )
        return filtered_paths

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
