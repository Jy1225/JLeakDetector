import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from tqdm import tqdm

from agent.agent import *

from tstool.analyzer.TS_analyzer import *
from tstool.analyzer.Cpp_TS_analyzer import *
from tstool.analyzer.Go_TS_analyzer import *
from tstool.analyzer.Java_TS_analyzer import *
from tstool.analyzer.Python_TS_analyzer import *

from tstool.dfbscan_extractor.dfbscan_extractor import *
from tstool.dfbscan_extractor.Cpp.Cpp_MLK_extractor import *
from tstool.dfbscan_extractor.Cpp.Cpp_NPD_extractor import *
from tstool.dfbscan_extractor.Cpp.Cpp_UAF_extractor import *
from tstool.dfbscan_extractor.Java.Java_MLK_extractor import *
from tstool.dfbscan_extractor.Java.Java_NPD_extractor import *
from tstool.dfbscan_extractor.Python.Python_NPD_extractor import *
from tstool.dfbscan_extractor.Go.Go_NPD_extractor import *

from llmtool.LLM_utils import *
from llmtool.dfbscan.intra_dataflow_analyzer import *
from llmtool.dfbscan.path_validator import *

from memory.semantic.dfbscan_state import *
from memory.syntactic.function import *
from memory.syntactic.value import *
from tstool.validator.java_resource_ownership_validator import *

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
                # Java-MLK special handling: scan all path_set twice globally.
                # This avoids "early terminal" on a partial path_set when another path_set
                # still has a valid inter-procedural continuation.
                all_continue_edges: List[
                    Tuple[
                        Tuple[Value, CallContext],
                        Set[Tuple[Value, CallContext]],
                    ]
                ] = []
                all_terminal_edges: List[Tuple[Value, CallContext]] = []
                all_sink_edges: List[Tuple[Value, CallContext]] = []
                has_empty_path_set = False

                for path_set in reachable_values_paths:
                    if not path_set:
                        has_empty_path_set = True
                        continue

                    for value, ctx in path_set:
                        if value.label == ValueLabel.SINK:
                            all_sink_edges.append((value, ctx))
                            continue

                        if value.label in {
                            ValueLabel.PARA,
                            ValueLabel.RET,
                            ValueLabel.ARG,
                            ValueLabel.OUT,
                        }:
                            external_ends = external_match_snapshot.get((value, ctx))
                            if external_ends:
                                all_continue_edges.append(((value, ctx), external_ends))
                            else:
                                all_terminal_edges.append((value, ctx))

                # Priority:
                #   1) Any continue edge -> only continue (Case 3).
                #   2) Otherwise sink edges.
                #   3) Otherwise terminal external edges (Case 1/2).
                #   4) Otherwise empty path_set fallback for source-must-reach-sink style.
                handled_in_priority = False
                if all_continue_edges:
                    seen_continue_edges = set()
                    for (value, ctx), external_ends in all_continue_edges:
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
                    handled_in_priority = True
                elif all_sink_edges:
                    if self.is_reachable:
                        seen_sinks = set()
                        for sink_value, sink_ctx in all_sink_edges:
                            sink_key = (sink_value, sink_ctx)
                            if sink_key in seen_sinks:
                                continue
                            seen_sinks.add(sink_key)
                            self.state.update_potential_buggy_paths(
                                src_value, path_with_unknown_status + [sink_value]
                            )
                    handled_in_priority = True
                elif all_terminal_edges:
                    # If the current value can still be mapped outside this function
                    # (e.g., PARA -> caller ARG side-effect), defer terminal judgement
                    # and let the external-match recursion continue first.
                    if current_value_with_context in external_match_snapshot:
                        handled_in_priority = True
                    else:
                        seen_terminals = set()
                        for terminal_value, terminal_ctx in all_terminal_edges:
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
                                    path_with_unknown_status + [terminal_value]
                                )
                                if src_value not in candidate_path:
                                    candidate_path = [src_value] + candidate_path
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
                        handled_in_priority = True

                if (
                    (not handled_in_priority)
                    and has_empty_path_set
                    and not self.is_reachable
                ):
                    self.state.update_potential_buggy_paths(
                        src_value, path_with_unknown_status + [src_value]
                    )
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

                initial_context = CallContext(False)
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

                for buggy_path in self.state.potential_buggy_paths[src_value].values():
                    pv_input = PathValidatorInput(
                        self.bug_type,
                        buggy_path,
                        {
                            value: self.ts_analyzer.get_function_from_localvalue(value)
                            for value in buggy_path
                        },
                    )
                    pv_output = self.path_validator.invoke(
                        pv_input, PathValidatorOutput
                    )

                    if pv_output is None:
                        continue

                    if pv_output.is_reachable:
                        passed_post_validation, reason = (
                            self.__post_validate_java_mlk_with_objid(
                                src_value,
                                buggy_path,
                                {
                                    value: self.ts_analyzer.get_function_from_localvalue(
                                        value
                                    )
                                    for value in buggy_path
                                },
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
        self.__dump_java_mlk_transfer_records()
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
        self.__dump_java_mlk_transfer_records()
        return

    def __process_src_value(self, src_value: Value) -> None:
        worklist = []
        src_function = self.ts_analyzer.get_function_from_localvalue(src_value)
        if src_function is None:
            return
        initial_context = CallContext(False)

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
                start_function, start_value, sink_values, call_statements, ret_values
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
        for buggy_path in self.state.potential_buggy_paths[src_value].values():
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

            pv_input = PathValidatorInput(
                self.bug_type,
                buggy_path,
                values_to_functions,
            )
            pv_output = self.path_validator.invoke(pv_input, PathValidatorOutput)

            if pv_output is None:
                continue

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

    def get_agent_state(self) -> DFBScanState:
        return self.state

    def get_log_files(self) -> List[str]:
        log_files = []
        log_files.append(self.log_dir_path + "/" + "dfbscan.log")
        return log_files
