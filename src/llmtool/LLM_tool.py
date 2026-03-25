from llmtool.LLM_utils import *
from abc import ABC, abstractmethod
from typing import Dict, Optional, Type, TypeVar, cast
import threading
from ui.logger import Logger


class LLMToolInput(ABC):
    def __init__(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def __hash__(self) -> int:
        raise NotImplementedError

    def __eq__(self, value) -> bool:
        if value is None or type(self) is not type(value):
            return False
        return self.__hash__() == value.__hash__()


class LLMToolOutput(ABC):
    def __init__(self):
        pass


T = TypeVar("T", bound=LLMToolOutput)


class LLMTool(ABC):
    def __init__(
        self,
        model_name: str,
        temperature: float,
        language: str,
        max_query_num: int,
        logger: Logger,
    ) -> None:
        self.language = language
        self.model_name = model_name
        self.temperature = temperature
        self.language = language
        self.max_query_num = max_query_num
        self.logger = logger

        self.model = LLM(model_name, self.logger, temperature)
        self.cache: Dict[LLMToolInput, LLMToolOutput] = {}
        self._inflight_inputs: Dict[LLMToolInput, threading.Event] = {}
        self._cache_lock = threading.Lock()

        self.input_token_cost = 0
        self.output_token_cost = 0
        self.total_query_num = 0
        self.reasoning_token_cost = 0
        self.prompt_cache_hit_tokens = 0
        self.prompt_cache_miss_tokens = 0
        self.provider_total_tokens = 0
        self.token_count_mode = getattr(
            self.model, "token_count_mode", "model_family_estimated"
        )

    def get_usage_stats(self) -> Dict[str, object]:
        return {
            "tool_name": type(self).__name__,
            "model_name": self.model_name,
            "model_family": getattr(self.model, "model_family", "unknown"),
            "token_count_mode": self.token_count_mode,
            "token_encoding_name": getattr(self.model, "token_encoding_name", "unknown"),
            "input_tokens": self.input_token_cost,
            "output_tokens": self.output_token_cost,
            "total_tokens": (
                self.provider_total_tokens
                if self.token_count_mode == "provider_usage"
                else self.input_token_cost + self.output_token_cost
            ),
            "provider_total_tokens": self.provider_total_tokens,
            "reasoning_tokens": self.reasoning_token_cost,
            "prompt_cache_hit_tokens": self.prompt_cache_hit_tokens,
            "prompt_cache_miss_tokens": self.prompt_cache_miss_tokens,
            "query_count": self.total_query_num,
        }

    def invoke(self, input: LLMToolInput, cls: Type[T]) -> Optional[T]:
        """
        Invoke the LLM tool with the given input.
        :param input: the input of the LLM tool
        :param cls: the class of the output
        :return: the output of the LLM tool
        """
        output = self._invoke(input)
        if output is None:
            return None

        if not isinstance(output, cls):
            raise TypeError(f"Expected output of type {cls}, but got {type(output)}")

        return cast(T, output)

    def _invoke(self, input: LLMToolInput) -> Optional[LLMToolOutput]:
        class_name = type(self).__name__

        inflight_event: Optional[threading.Event] = None
        while True:
            with self._cache_lock:
                cached_output = self.cache.get(input)
                if cached_output is not None:
                    self.logger.print_log("Cache hit.")
                    return cached_output

                existing_event = self._inflight_inputs.get(input)
                if existing_event is None:
                    inflight_event = threading.Event()
                    self._inflight_inputs[input] = inflight_event
                    break

            # Another worker is already computing the same input.
            existing_event.wait()

        self.logger.print_console(
            f"The LLM Tool {class_name} is invoked (cache miss)."
        )

        prompt = self._get_prompt(input)
        self.logger.print_log("Prompt:", "\n", prompt)

        single_query_num = 0
        output = None
        try:
            while True:
                if single_query_num > self.max_query_num:
                    break
                single_query_num += 1
                response, input_token_cost, output_token_cost, usage_info = self.model.infer(
                    prompt, True
                )
                self.logger.print_log("Response:", "\n", response)
                self.input_token_cost += input_token_cost
                self.output_token_cost += output_token_cost
                if usage_info is not None:
                    self.token_count_mode = str(
                        usage_info.get("token_count_mode", self.token_count_mode)
                    )
                    self.reasoning_token_cost += int(
                        usage_info.get("reasoning_tokens", 0)
                    )
                    self.prompt_cache_hit_tokens += int(
                        usage_info.get("prompt_cache_hit_tokens", 0)
                    )
                    self.prompt_cache_miss_tokens += int(
                        usage_info.get("prompt_cache_miss_tokens", 0)
                    )
                    self.provider_total_tokens += int(
                        usage_info.get(
                            "total_tokens", input_token_cost + output_token_cost
                        )
                    )
                output = self._parse_response(response, input)

                if output is not None:
                    break
        finally:
            self.total_query_num += single_query_num
            with self._cache_lock:
                if output is not None:
                    self.cache[input] = output
                event = self._inflight_inputs.pop(input, None)
                if event is not None:
                    event.set()

        return output

    @abstractmethod
    def _get_prompt(self, input: LLMToolInput) -> str:
        pass

    @abstractmethod
    def _parse_response(
        self, response: str, input: Optional[LLMToolInput] = None
    ) -> Optional[LLMToolOutput]:
        pass
