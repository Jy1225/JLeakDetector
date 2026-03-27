from os import path
import json
import time
from typing import List, Set, Optional, Dict, Tuple
from llmtool.LLM_utils import *
from llmtool.LLM_tool import *
from memory.syntactic.function import *
from memory.syntactic.value import *
from memory.syntactic.api import *
from tstool.validator.java_resource_semantics import (
    RESOURCE_KIND_AUTOCLOSEABLE,
    GUARANTEE_NONE,
    RELEASE_CONTEXT_UNKNOWN,
    normalize_guarantee_level,
    normalize_release_context,
    normalize_resource_kind,
)

BASE_PATH = Path(__file__).resolve().parent.parent.parent


class IntraDataFlowAnalyzerInput(LLMToolInput):
    def __init__(
        self,
        function: Function,
        summary_start: Value,
        sink_values: List[Tuple[str, int]],
        call_statements: List[Tuple[str, int]],
        ret_values: List[Tuple[str, int]],
        resource_kind: str = RESOURCE_KIND_AUTOCLOSEABLE,
        resource_rules: Optional[List[str]] = None,
    ) -> None:
        self.function = function
        self.summary_start = summary_start
        self.sink_values = sink_values
        self.call_statements = call_statements
        self.ret_values = ret_values
        self.resource_kind = normalize_resource_kind(resource_kind)
        self.resource_rules = list(resource_rules or [])
        return

    def __hash__(self) -> int:
        return hash(
            (
                self.function.function_id,
                str(self.summary_start),
                self.resource_kind,
                tuple(self.resource_rules),
            )
        )


class IntraDataFlowAnalyzerOutput(LLMToolOutput):
    def __init__(
        self,
        reachable_values: List[Set[Value]],
        source_executed_per_path: List[bool],
        path_line_numbers_per_path: List[List[int]],
        release_context_per_path: List[str],
        guarantee_level_per_path: List[str],
    ) -> None:
        self.reachable_values = reachable_values
        self.source_executed_per_path = source_executed_per_path
        self.path_line_numbers_per_path = path_line_numbers_per_path
        self.release_context_per_path = release_context_per_path
        self.guarantee_level_per_path = guarantee_level_per_path
        return

    def __str__(self):
        output_str = ""
        for i, reachable_values_per_path in enumerate(self.reachable_values):
            output_str += f"Path {i}:\n"
            if i < len(self.path_line_numbers_per_path):
                output_str += f"  lines={self.path_line_numbers_per_path[i]}\n"
            if i < len(self.release_context_per_path):
                output_str += f"  release_context={self.release_context_per_path[i]}\n"
            if i < len(self.guarantee_level_per_path):
                output_str += f"  guarantee_level={self.guarantee_level_per_path[i]}\n"
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
        with open(self.prompt_file, "r", encoding="utf-8") as f:
            self.prompt_template_dict = json.load(f)
        return

    def _get_prompt(self, input: LLMToolInput) -> str:
        if not isinstance(input, IntraDataFlowAnalyzerInput):
            raise TypeError("Expect IntraDataFlowAnalyzerInput")
        prompt_template_dict = self.prompt_template_dict
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

        resource_rules_text = ""
        if len(input.resource_rules) > 0:
            resource_rules_text = "\n".join(f"- {rule}" for rule in input.resource_rules)
        else:
            resource_rules_text = "- Use generic resource lifecycle rules."
        prompt = prompt.replace("<RESOURCE_KIND>", input.resource_kind)
        prompt = prompt.replace("<RESOURCE_RULES>", resource_rules_text)

        if "<RESOURCE_RULES>" in prompt or "<RESOURCE_KIND>" in prompt:
            # Fallback in case some prompt templates do not provide placeholders.
            prompt = prompt.replace("<RESOURCE_RULES>", resource_rules_text)
            prompt = prompt.replace("<RESOURCE_KIND>", input.resource_kind)
        return prompt

    def _parse_response(
        self, response: str, input: Optional[LLMToolInput] = None
    ) -> Optional[LLMToolOutput]:
        """
        Parse the LLM response to extract all execution paths and their propagation details.
        """
        paths: List[Dict[str, object]] = []

        path_header_re = re.compile(r"Path\s*(\d+):\s*([^;]+);?$")
        detail_re = re.compile(
            r"Type:\s*([^;]+);\s*"
            r"Name:\s*([^;]+);\s*"
            r"Function:\s*([^;]+);\s*"
            r"Index:\s*([^;]+);\s*"
            r"Line:\s*([^;]+);"
        )

        current_path: Optional[Dict[str, object]] = None
        for raw_line in response.splitlines():
            line = raw_line.strip().lstrip("-").strip()
            if line == "":
                continue

            header_match = path_header_re.match(line)
            if header_match:
                if current_path is not None:
                    paths.append(current_path)
                current_path = {
                    "path_number": header_match.group(1).strip(),
                    "execution_path": header_match.group(2).strip(),
                    "propagation_details": [],
                    "release_context": RELEASE_CONTEXT_UNKNOWN,
                    "guarantee_level": GUARANTEE_NONE,
                }
                continue

            if current_path is None:
                continue

            detail_match = detail_re.match(line)
            if detail_match:
                detail = {
                    "type": detail_match.group(1).strip(),
                    "name": detail_match.group(2).strip(),
                    "function": detail_match.group(3).strip(),
                    "index": detail_match.group(4).strip(),
                    "line": detail_match.group(5).strip(),
                }
                cast(List[Dict[str, str]], current_path["propagation_details"]).append(
                    detail
                )
                continue

            release_context = self._extract_release_context(line)
            if release_context != "":
                current_path["release_context"] = normalize_release_context(
                    release_context
                )

            guarantee_level = self._extract_guarantee_level(line)
            if guarantee_level != "":
                current_path["guarantee_level"] = normalize_guarantee_level(
                    guarantee_level
                )

        if current_path is not None:
            paths.append(current_path)

        if len(paths) == 0:
            self.logger.print_log(
                "No valid path entries were parsed from intra_dataflow_analyzer response."
            )
            return None

        assert input is not None, "input cannot be none"
        if not isinstance(input, IntraDataFlowAnalyzerInput):
            raise TypeError("Expect IntraDataFlowAnalyzerInput")

        reachable_values: List[Set[Value]] = []
        source_executed_per_path: List[bool] = []
        path_line_numbers_per_path: List[List[int]] = []
        release_context_per_path: List[str] = []
        guarantee_level_per_path: List[str] = []

        file_path = input.function.file_path
        start_line_number = input.function.start_line_number
        source_line_in_function = (
            input.summary_start.line_number - input.function.start_line_number + 1
        )
        source_tokens = self._extract_identifier_tokens(input.summary_start.name)

        for single_path in paths:
            reachable_values_per_path: Set[Value] = set()
            execution_path = str(single_path.get("execution_path", ""))
            details = cast(
                List[Dict[str, str]], single_path.get("propagation_details", [])
            )
            path_line_numbers = self._extract_path_line_numbers(execution_path)
            source_executed = self._is_source_executed_in_path(
                path_line_numbers,
                source_line_in_function,
                details,
                source_tokens,
            )

            for detail in details:
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

            release_context = normalize_release_context(
                str(single_path.get("release_context", RELEASE_CONTEXT_UNKNOWN))
            )
            guarantee_level = normalize_guarantee_level(
                str(single_path.get("guarantee_level", GUARANTEE_NONE))
            )

            reachable_values.append(reachable_values_per_path)
            source_executed_per_path.append(source_executed)
            path_line_numbers_per_path.append(path_line_numbers)
            release_context_per_path.append(release_context)
            guarantee_level_per_path.append(guarantee_level)

        output = IntraDataFlowAnalyzerOutput(
            reachable_values,
            source_executed_per_path,
            path_line_numbers_per_path,
            release_context_per_path,
            guarantee_level_per_path,
        )
        self.logger.print_log(
            "Output of intra-procedural data-flow analyzer:",
            output.reachable_values,
        )
        return output

    def _is_source_executed_in_path(
        self,
        path_line_numbers: List[int],
        source_line_in_function: int,
        details: List[Dict[str, str]],
        source_tokens: List[str],
    ) -> bool:
        if source_line_in_function in path_line_numbers:
            return True

        if len(path_line_numbers) == 0 and len(source_tokens) > 0:
            for detail in details:
                detail_name = detail.get("name", "")
                for token in source_tokens:
                    if re.search(rf"\b{re.escape(token)}\b", detail_name):
                        return True
        return False

    def _extract_path_line_numbers(self, execution_path: str) -> List[int]:
        line_numbers: List[int] = []
        for item in re.findall(r"\d+", execution_path):
            value = int(item)
            if value not in line_numbers:
                line_numbers.append(value)
        return line_numbers

    def _extract_identifier_tokens(self, expr: str) -> List[str]:
        tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expr)
        return [token for token in tokens if token != "new"]

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

    def _extract_release_context(self, line: str) -> str:
        pattern = re.compile(
            r"(?:release[_\s]?context|releasecontext)\s*[:=]\s*([A-Za-z_\-]+)",
            re.IGNORECASE,
        )
        match = pattern.search(line)
        if match is None:
            return ""
        return match.group(1).strip()

    def _extract_guarantee_level(self, line: str) -> str:
        pattern = re.compile(
            r"(?:guarantee[_\s]?level|guarantee)\s*[:=]\s*([A-Za-z_\-]+)",
            re.IGNORECASE,
        )
        match = pattern.search(line)
        if match is None:
            return ""
        return match.group(1).strip()
