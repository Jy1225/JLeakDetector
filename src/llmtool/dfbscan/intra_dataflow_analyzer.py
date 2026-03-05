from os import path
import json
import time
from typing import List, Set, Optional, Dict
from llmtool.LLM_utils import *
from llmtool.LLM_tool import *
from memory.syntactic.function import *
from memory.syntactic.value import *
from memory.syntactic.api import *

BASE_PATH = Path(__file__).resolve().parent.parent.parent


class IntraDataFlowAnalyzerInput(LLMToolInput):
    def __init__(
        self,
        function: Function,
        summary_start: Value,
        sink_values: List[Tuple[str, int]],
        call_statements: List[Tuple[str, int]],
        ret_values: List[Tuple[str, int]],
    ) -> None:
        self.function = function
        self.summary_start = summary_start
        self.sink_values = sink_values
        self.call_statements = call_statements
        self.ret_values = ret_values
        return

    def __hash__(self) -> int:
        return hash((self.function.function_id, str(self.summary_start)))


class IntraDataFlowAnalyzerOutput(LLMToolOutput):
    def __init__(
        self, reachable_values: List[Set[Value]], source_executed_per_path: List[bool]
    ) -> None:
        self.reachable_values = reachable_values
        self.source_executed_per_path = source_executed_per_path
        return

    def __str__(self):
        output_str = ""
        for i, reachable_values_per_path in enumerate(self.reachable_values):
            output_str += f"Path {i}:\n"
            for value in reachable_values_per_path:
                output_str += f"- {value}\n"
        return output_str


class IntraDataFlowAnalyzer(LLMTool):
    def __init__(
        self,
        model_name: str,
        temperature: float,
        language: str,
        bug_type: str,
        max_query_num: int,
        logger: Logger,
    ) -> None:
        """
        :param model_name: the model name
        :param temperature: the temperature
        :param language: the programming language
        :param bug_type: the bug type
        :param max_query_num: the maximum number of queries if the model fails
        :param logger: the logger
        """
        super().__init__(model_name, temperature, language, max_query_num, logger)
        self.bug_type = bug_type
        if language == "Java" and bug_type == "MLK":
            self.prompt_file = (
                f"{BASE_PATH}/prompt/{language}/dfbscan/intra_dataflow_analyzer_mlk.json"
            )
        else:
            self.prompt_file = (
                f"{BASE_PATH}/prompt/{language}/dfbscan/intra_dataflow_analyzer.json"
            )
        return

    def _get_prompt(self, input: LLMToolInput) -> str:
        if not isinstance(input, IntraDataFlowAnalyzerInput):
            raise TypeError("Expect IntraDataFlowAnalyzerInput")
        with open(self.prompt_file, "r") as f:
            prompt_template_dict = json.load(f)
        prompt = prompt_template_dict["task"]
        prompt += "\n" + "\n".join(prompt_template_dict["analysis_rules"])
        prompt += "\n" + "\n".join(prompt_template_dict["analysis_examples"])
        prompt += "\n" + "".join(prompt_template_dict["meta_prompts"])
        prompt = prompt.replace(
            "<ANSWER>", "\n".join(prompt_template_dict["answer_format_cot"])
        )
        prompt = prompt.replace("<QUESTION>", prompt_template_dict["question_template"])

        prompt = (
            prompt.replace("<FUNCTION>", input.function.lined_code)
            .replace("<SRC_NAME>", input.summary_start.name)
            .replace(
                "<SRC_LINE>",
                str(
                    input.summary_start.line_number
                    - input.function.start_line_number
                    + 1
                ),
            )
        )

        sinks_str = "Sink values in this function:\n"
        for sink_value in input.sink_values:
            sinks_str += f"- {sink_value[0]} at line {sink_value[1]}\n"
        prompt = prompt.replace("<SINK_VALUES>", sinks_str)

        calls_str = "Call statements in this function:\n"
        for call_statement in input.call_statements:
            calls_str += f"- {call_statement[0]} at line {call_statement[1]}\n"
        prompt = prompt.replace("<CALL_STATEMENTS>", calls_str)

        rets_str = "Return values in this function:\n"
        for ret_val in input.ret_values:
            rets_str += f"- {ret_val[0]} at line {ret_val[1]}\n"
        prompt = prompt.replace("<RETURN_VALUES>", rets_str)
        return prompt

    def _parse_response(
        self, response: str, input: Optional[LLMToolInput] = None
    ) -> Optional[LLMToolOutput]:
        """
        Parse the LLM response to extract all execution paths and their propagation details.

        Args:
            response (str): The response string from the LLM.
            input (IntraDataFlowAnalyzerInput): The input object containing function details.

        Returns:
            IntraDataFlowAnalyzerOutput: The output containing reachable values for each path.
        """
        paths: List[Dict] = []

        # Regex to match a path header line, e.g., "Path 1: Lines 2 -> 3"
        path_header_re = re.compile(r"Path\s*(\d+):\s*([^;]+);?$")

        # Regex to match a propagation detail line, e.g.,
        # "  - Type: Return; Name: getNullObject(); Function: None; Index: 0; Line: 3; Dependency: ..."
        detail_re = re.compile(
            r"Type:\s*([^;]+);\s*"
            r"Name:\s*([^;]+);\s*"
            r"Function:\s*([^;]+);\s*"
            r"Index:\s*([^;]+);\s*"
            r"Line:\s*([^;]+);"
        )

        current_path = None
        for line in response.splitlines():
            line = line.strip().lstrip("-").strip()
            if not line:
                continue

            # Check for path header
            header_match = path_header_re.match(line)
            if header_match:
                if current_path:
                    paths.append(current_path)
                current_path = {
                    "path_number": header_match.group(1).strip(),
                    "execution_path": header_match.group(2).strip(),
                    "propagation_details": [],
                }
            else:
                # Check for propagation detail line
                detail_match = detail_re.match(line)
                if detail_match and current_path is not None:
                    detail = {
                        "type": detail_match.group(1).strip(),
                        "name": detail_match.group(2).strip(),
                        "function": detail_match.group(3).strip(),
                        "index": detail_match.group(4).strip(),
                        "line": detail_match.group(5).strip(),
                    }
                    current_path["propagation_details"].append(detail)

                elif current_path is not None:
                    paths.append(current_path)
                    current_path = None

        if current_path:
            paths.append(current_path)

        assert input is not None, "input cannot be none"
        if not isinstance(input, IntraDataFlowAnalyzerInput):
            raise TypeError("Expect IntraDataFlowAnalyzerInput")

        # Process paths to extract reachable values
        reachable_values = []
        source_executed_per_path: List[bool] = []
        file_path = input.function.file_path
        start_line_number = input.function.start_line_number
        source_line_in_function = (
            input.summary_start.line_number - input.function.start_line_number + 1
        )

        for single_path in paths:
            reachable_values_per_path = set()
            source_executed = self._is_source_executed_in_path(
                single_path.get("execution_path", ""),
                source_line_in_function,
                single_path.get("propagation_details", []),
            )
            for detail in single_path["propagation_details"]:
                if not detail["line"].isdigit():
                    continue
                line_number = int(detail["line"]) + start_line_number - 1
                detail_type = self._normalize_detail_type(detail)
                detail_index = self._safe_index(detail["index"])
                if detail_type == "Argument":
                    reachable_values_per_path.add(
                        Value(
                            detail["name"],
                            line_number,
                            ValueLabel.ARG,
                            file_path,
                            detail_index,
                        )
                    )
                elif detail_type == "Parameter":
                    reachable_values_per_path.add(
                        Value(
                            detail["name"],
                            line_number,
                            ValueLabel.PARA,
                            file_path,
                            detail_index,
                        )
                    )
                elif detail_type == "Return":
                    reachable_values_per_path.add(
                        Value(
                            detail["name"],
                            line_number,
                            ValueLabel.RET,
                            file_path,
                            detail_index,
                        )
                    )
                elif detail_type == "Sink":
                    reachable_values_per_path.add(
                        Value(detail["name"], line_number, ValueLabel.SINK, file_path)
                    )
            reachable_values.append(reachable_values_per_path)
            source_executed_per_path.append(source_executed)

        output = IntraDataFlowAnalyzerOutput(
            reachable_values, source_executed_per_path
        )
        self.logger.print_log(
            "Output of intra-procedural data-flow analyzer:", output.reachable_values
        )
        return output

    def _is_source_executed_in_path(
        self, execution_path: str, source_line_in_function: int, details: List[Dict[str, str]]
    ) -> bool:
        line_numbers = [int(item) for item in re.findall(r"\d+", execution_path)]
        if source_line_in_function in line_numbers:
            return True
        # If parsing of execution lines is weak but the model still emitted propagation
        # details for this path, treat source as executed to avoid over-pruning.
        if len(details) > 0:
            return True
        return False

    def _normalize_detail_type(self, detail: Dict[str, str]) -> str:
        normalized = detail["type"].strip()
        if normalized == "ResourceClose":
            return "Sink"
        if normalized == "ResourceEscape":
            if detail["function"].strip() != "None":
                return "Argument"
            return "Return"
        if normalized == "ResourceWrap":
            if detail["function"].strip() != "None":
                return "Parameter"
            return "Return"
        return normalized

    def _safe_index(self, raw_index: str) -> int:
        normalized = raw_index.strip()
        if normalized.isdigit():
            return int(normalized)
        return 0
