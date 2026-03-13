from os import path
import json
from typing import List, Dict, Optional
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


class PathValidatorInput(LLMToolInput):
    def __init__(
        self,
        bug_type: str,
        values: List[Value],
        values_to_functions: Dict[Value, Optional[Function]],
        strict_branch_semantics: bool = False,
        resource_kind: str = RESOURCE_KIND_AUTOCLOSEABLE,
        release_context: str = RELEASE_CONTEXT_UNKNOWN,
        guarantee_level: str = GUARANTEE_NONE,
        resource_semantic_rules: Optional[List[str]] = None,
        servlet_context: bool = False,
    ) -> None:
        self.bug_type = bug_type
        self.values = values
        self.values_to_functions = values_to_functions
        self.strict_branch_semantics = strict_branch_semantics
        self.resource_kind = normalize_resource_kind(resource_kind)
        self.release_context = normalize_release_context(release_context)
        self.guarantee_level = normalize_guarantee_level(guarantee_level)
        self.resource_semantic_rules = list(resource_semantic_rules or [])
        self.servlet_context = servlet_context
        return

    def __hash__(self) -> int:
        return hash(
            (
                self.bug_type,
                tuple(str(value) for value in self.values),
                self.strict_branch_semantics,
                self.resource_kind,
                self.release_context,
                self.guarantee_level,
                tuple(self.resource_semantic_rules),
                self.servlet_context,
            )
        )


class PathValidatorOutput(LLMToolOutput):
    def __init__(self, is_reachable: bool, explanation_str: str) -> None:
        self.is_reachable = is_reachable
        self.explanation_str = explanation_str
        return

    def __str__(self):
        return (
            f"Is reachable: {self.is_reachable} \nExplanation: {self.explanation_str}"
        )


class PathValidator(LLMTool):
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
        if language == "Java" and bug_type == "MLK":
            self.prompt_file = (
                f"{BASE_PATH}/prompt/{language}/dfbscan/path_validator_mlk.json"
            )
        else:
            self.prompt_file = (
                f"{BASE_PATH}/prompt/{language}/dfbscan/path_validator.json"
            )
        return

    def _get_prompt(self, input: LLMToolInput) -> str:
        if not isinstance(input, PathValidatorInput):
            raise TypeError("expect PathValidatorInput")
        with open(self.prompt_file, "r") as f:
            prompt_template_dict = json.load(f)
        prompt = prompt_template_dict["task"]
        prompt += "\n" + "\n".join(prompt_template_dict["analysis_rules"])
        prompt += "\n" + "\n".join(prompt_template_dict["analysis_examples"])
        prompt += "\n" + "".join(prompt_template_dict["meta_prompts"])
        prompt = prompt.replace(
            "<ANSWER>", "\n".join(prompt_template_dict["answer_format"])
        ).replace("<QUESTION>", "\n".join(prompt_template_dict["question_template"]))

        value_lines = []
        for value in input.values:
            if value.label == ValueLabel.LOCAL and (
                value.name.startswith("__RESOURCE_KIND_")
                or value.name.startswith("__RELEASE_CONTEXT_")
                or value.name.startswith("__GUARANTEE_LEVEL_")
            ):
                continue
            value_line = " - " + str(value)
            function = input.values_to_functions.get(value)
            if function is None:
                continue
            value_line += (
                " in the function "
                + function.function_name
                + " at the line "
                + str(value.line_number - function.start_line_number + 1)
            )
            value_lines.append(value_line)
        prompt = prompt.replace("<PATH>", "\n".join(value_lines))
        prompt = prompt.replace("<BUG_TYPE>", input.bug_type)

        unique_functions: List[Function] = []
        seen_function_keys = set()
        for func in input.values_to_functions.values():
            if func is None:
                continue
            function_key = (
                func.function_uid
                if func.function_uid != ""
                else f"{func.file_path}:{func.function_name}:{func.start_line_number}"
            )
            if function_key in seen_function_keys:
                continue
            seen_function_keys.add(function_key)
            unique_functions.append(func)

        program = "\n".join(
            ["```\n" + func.lined_code + "\n```\n" for func in unique_functions]
        )
        prompt = prompt.replace("<PROGRAM>", program)

        resource_semantic_lines = [
            "Resource semantic context:",
            f"- resource_kind: {input.resource_kind}",
            f"- release_context(from intra): {input.release_context}",
            f"- guarantee_level(from intra): {input.guarantee_level}",
            f"- servlet_context: {'yes' if input.servlet_context else 'no'}",
        ]
        for rule in input.resource_semantic_rules:
            resource_semantic_lines.append(f"- {rule}")
        prompt += "\n\n" + "\n".join(resource_semantic_lines)

        marker_values = [
            value
            for value in input.values
            if value.label == ValueLabel.LOCAL
            and value.name.startswith("__NO_SINK_BRANCH_PATH_")
        ]
        if len(marker_values) > 0 and input.strict_branch_semantics:
            branch_rules = prompt_template_dict.get("branch_marker_rules", [])
            strict_branch_rules = prompt_template_dict.get(
                "strict_branch_marker_rules", []
            )
            marker_names = ", ".join(
                sorted(set(value.name for value in marker_values))
            )

            marker_hint_lines = [
                "Branch marker context:",
                f"- Active marker(s): {marker_names}",
            ]
            for rule in branch_rules:
                marker_hint_lines.append(f"- {rule}")

            marker_hint_lines.append("- Strict mode enabled for this re-check.")
            for rule in strict_branch_rules:
                marker_hint_lines.append(f"- {rule}")

            prompt += "\n\n" + "\n".join(marker_hint_lines)
        elif input.strict_branch_semantics:
            strict_hint_lines = [
                "Strict re-check context:",
                "- Strict mode enabled for weak-release path verification.",
                f"- release_context={input.release_context}",
                f"- guarantee_level={input.guarantee_level}",
                "- Require all-exit release proof before answering No.",
            ]
            prompt += "\n\n" + "\n".join(strict_hint_lines)
        return prompt

    def _parse_response(
        self, response: str, input: Optional[LLMToolInput] = None
    ) -> Optional[LLMToolOutput]:
        answer_match = re.search(r"Answer:\s*(\w+)", response)
        if answer_match:
            answer = answer_match.group(1).strip()
            output = PathValidatorOutput(answer == "Yes", response)
            self.logger.print_log("Output of path_validator:\n", str(output))
        else:
            self.logger.print_log(f"Answer not found in output")
            output = None
        return output
