# Imports
from openai import *
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import google.generativeai as genai
import anthropic
import signal
import sys
import tiktoken
import time
import os
import concurrent.futures
from functools import partial
import threading

import json
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
import boto3
from ui.logger import Logger

OPENAI_COMPATIBLE_PROVIDERS: Dict[str, Dict[str, object]] = {
    "qwen": {
        "env_keys": ["DASHSCOPE_API_KEY", "QWEN_API_KEY"],
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "timeout": 100,
    },
    "kimi": {
        "env_keys": ["MOONSHOT_API_KEY", "KIMI_API_KEY"],
        "base_url": "https://api.moonshot.cn/v1",
        "timeout": 180,
    },
    "doubao": {
        "env_keys": ["ARK_API_KEY", "DOUBAO_API_KEY", "VOLCENGINE_API_KEY"],
        "base_url": "https://ark.cn-beijing.volces.com/api/v3",
        "timeout": 120,
    },
}

MODEL_FAMILY_TOKENIZER: Dict[str, str] = {
    "openai-reasoning": "o200k_base",
    "openai-gpt": "cl100k_base",
    "deepseek": "o200k_base",
    "qwen": "o200k_base",
    "kimi": "o200k_base",
    "doubao": "o200k_base",
    "claude": "cl100k_base",
    "gemini": "o200k_base",
    "unknown": "cl100k_base",
}

MODEL_NAME_ALIASES: Dict[str, str] = {
    "doubao-seed-2.0-mini": "doubao-seed-2-0-mini-250821",
    "doubao-seed-2-0-mini": "doubao-seed-2-0-mini-250821",
}


class LLM:
    """
    An online inference model using different LLMs:
    - Gemini
    - OpenAI: GPT-3.5, GPT-4, o3-mini
    - DeepSeek: V3, R1
    - Qwen
    - Kimi / Moonshot
    - Claude: 3.5 and 3.7
    """

    def __init__(
        self,
        online_model_name: str,
        logger: Logger,
        temperature: float = 0.0,
        system_role: str = "You are an experienced programmer and good at understanding programs written in mainstream programming languages.",
        max_output_length: int = 4096,
    ) -> None:
        self.online_model_name = self._resolve_model_alias(online_model_name)
        self.normalized_model_name = self.online_model_name.strip().lower()
        self.model_family = self._identify_model_family(self.online_model_name)
        self.token_count_mode = "model_family_estimated"
        self.token_encoding_name = MODEL_FAMILY_TOKENIZER.get(
            self.model_family, MODEL_FAMILY_TOKENIZER["unknown"]
        )
        self.encoding = self._build_token_encoder(self.token_encoding_name)
        self.temperature = temperature
        self.systemRole = system_role
        self.logger = logger
        self.max_output_length = max_output_length
        return

    def infer(
        self, message: str, is_measure_cost: bool = False
    ) -> Tuple[str, int, int, Optional[Dict[str, object]]]:
        self.logger.print_log(self.online_model_name, "is running")
        output = ""
        usage_info: Optional[Dict[str, object]] = None
        if self.model_family == "gemini":
            output, usage_info = self.infer_with_gemini(message)
        elif self.model_family == "qwen":
            output, usage_info = self.infer_with_qwen_model(message)
        elif self.model_family == "doubao":
            output, usage_info = self.infer_with_doubao_model(message)
        elif self.model_family == "kimi":
            output, usage_info = self.infer_with_kimi_model(message)
        elif self.model_family == "openai-gpt":
            output, usage_info = self.infer_with_openai_model(message)
        elif self.model_family == "openai-reasoning":
            output, usage_info = self.infer_with_o3_mini_model(message)
        elif self.model_family == "claude":
            output, usage_info = self.infer_with_claude_key(message)
            # output = self.infer_with_claude_aws_bedrock(message)
        elif self.model_family == "deepseek":
            output, usage_info = self.infer_with_deepseek_model(message)
        else:
            raise ValueError(
                f"Unsupported model name: {self.online_model_name} "
                f"(resolved family={self.model_family})"
            )

        input_token_cost = (
            0
            if not is_measure_cost
            else (
                int(usage_info["prompt_tokens"])
                if usage_info is not None
                and usage_info.get("token_count_mode") == "provider_usage"
                else self._count_tokens(self.systemRole) + self._count_tokens(message)
            )
        )
        output_token_cost = (
            0
            if not is_measure_cost
            else (
                int(usage_info["completion_tokens"])
                if usage_info is not None
                and usage_info.get("token_count_mode") == "provider_usage"
                else self._count_tokens(output)
            )
        )
        return output, input_token_cost, output_token_cost, usage_info

    def _identify_model_family(self, model_name: str) -> str:
        normalized_name = model_name.strip().lower()
        if "gemini" in normalized_name:
            return "gemini"
        if "qwen" in normalized_name:
            return "qwen"
        if "doubao" in normalized_name:
            return "doubao"
        if "kimi" in normalized_name or "moonshot" in normalized_name:
            return "kimi"
        if "deepseek" in normalized_name:
            return "deepseek"
        if "claude" in normalized_name:
            return "claude"
        if normalized_name.startswith("o1") or normalized_name.startswith("o3") or normalized_name.startswith("o4"):
            return "openai-reasoning"
        if "gpt" in normalized_name:
            return "openai-gpt"
        return "unknown"

    def _resolve_model_alias(self, model_name: str) -> str:
        normalized_name = model_name.strip().lower()
        return MODEL_NAME_ALIASES.get(normalized_name, model_name)

    def _build_token_encoder(self, encoding_name: str):
        try:
            return tiktoken.get_encoding(encoding_name)
        except Exception:
            return tiktoken.get_encoding(MODEL_FAMILY_TOKENIZER["unknown"])

    def _count_tokens(self, text: str) -> int:
        if text is None or text == "":
            return 0
        try:
            return len(self.encoding.encode(text))
        except Exception:
            return len(self._build_token_encoder(MODEL_FAMILY_TOKENIZER["unknown"]).encode(text))

    def _normalize_api_key(self, api_key: str) -> str:
        return api_key.split(":")[0].strip()

    def _get_usage_field(self, usage_obj, field_name: str, default=0):
        if usage_obj is None:
            return default
        if isinstance(usage_obj, dict):
            return usage_obj.get(field_name, default)
        return getattr(usage_obj, field_name, default)

    def _extract_usage_from_response(self, response) -> Optional[Dict[str, object]]:
        usage = getattr(response, "usage", None)
        if usage is None:
            return None

        completion_details = self._get_usage_field(
            usage, "completion_tokens_details", None
        )
        prompt_tokens = int(self._get_usage_field(usage, "prompt_tokens", 0) or 0)
        completion_tokens = int(
            self._get_usage_field(usage, "completion_tokens", 0) or 0
        )
        total_tokens = int(
            self._get_usage_field(
                usage,
                "total_tokens",
                prompt_tokens + completion_tokens,
            )
            or (prompt_tokens + completion_tokens)
        )
        prompt_cache_hit_tokens = int(
            self._get_usage_field(usage, "prompt_cache_hit_tokens", 0) or 0
        )
        prompt_cache_miss_tokens = int(
            self._get_usage_field(usage, "prompt_cache_miss_tokens", 0) or 0
        )
        reasoning_tokens = int(
            self._get_usage_field(completion_details, "reasoning_tokens", 0) or 0
        )

        return {
            "token_count_mode": "provider_usage",
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "prompt_cache_hit_tokens": prompt_cache_hit_tokens,
            "prompt_cache_miss_tokens": prompt_cache_miss_tokens,
            "reasoning_tokens": reasoning_tokens,
            "token_encoding_name": self.token_encoding_name,
            "model_family": self.model_family,
            "model_name": self.online_model_name,
        }

    def run_with_timeout(self, func, timeout):
        """Run a function with timeout that works in multiple threads"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(func)
            try:
                return future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                ("Operation timed out")
                return ""
            except Exception as e:
                self.logger.print_log(f"Operation failed: {e}")
                return ""

    def infer_with_gemini(
        self, message: str
    ) -> Tuple[str, Optional[Dict[str, object]]]:
        """Infer using the Gemini model from Google Generative AI"""
        gemini_model = genai.GenerativeModel("gemini-pro")

        def call_api():
            message_with_role = self.systemRole + "\n" + message
            safety_settings = [
                {
                    "category": "HARM_CATEGORY_DANGEROUS",
                    "threshold": "BLOCK_NONE",
                },
                # ...existing safety settings...
            ]
            response = gemini_model.generate_content(
                message_with_role,
                safety_settings=safety_settings,
                generation_config=genai.types.GenerationConfig(
                    temperature=self.temperature
                ),
            )
            return response.text, None

        tryCnt = 0
        while tryCnt < 5:
            tryCnt += 1
            try:
                output = self.run_with_timeout(call_api, timeout=50)
                if output:
                    self.logger.print_log("Inference succeeded...")
                    return output
            except Exception as e:
                self.logger.print_log(f"API error: {e}")
            time.sleep(2)

        return "", None

    def _build_model_input(self, message: str) -> List[Dict[str, str]]:
        return [
            {"role": "system", "content": self.systemRole},
            {"role": "user", "content": message},
        ]

    def _get_required_api_key(self, env_keys: List[str], provider_name: str) -> str:
        for env_key in env_keys:
            value = os.environ.get(env_key)
            if value:
                return value
        raise EnvironmentError(
            f"Please set one of {', '.join(env_keys)} to use the {provider_name} model."
        )

    def _infer_with_openai_compatible_model(
        self,
        message: str,
        api_key: str,
        base_url: str,
        timeout: int,
        include_temperature: bool = True,
    ) -> Tuple[str, Optional[Dict[str, object]]]:
        model_input = self._build_model_input(message)

        def call_api():
            client = OpenAI(api_key=api_key, base_url=base_url)
            request_kwargs = {
                "model": self.online_model_name,
                "messages": model_input,
            }
            if include_temperature:
                request_kwargs["temperature"] = self.temperature
            response = client.chat.completions.create(**request_kwargs)
            return (
                response.choices[0].message.content,
                self._extract_usage_from_response(response),
            )

        tryCnt = 0
        while tryCnt < 5:
            tryCnt += 1
            try:
                output = self.run_with_timeout(call_api, timeout=timeout)
                if output:
                    return output
            except Exception as e:
                self.logger.print_log(f"API error: {e}")
            time.sleep(2)

        return "", None

    def infer_with_qwen_model(
        self, message: str
    ) -> Tuple[str, Optional[Dict[str, object]]]:
        """Infer using a Qwen model via Alibaba Cloud Model Studio."""
        provider_config = OPENAI_COMPATIBLE_PROVIDERS["qwen"]
        api_key = self._get_required_api_key(
            provider_config["env_keys"], "Qwen / DashScope"
        )
        return self._infer_with_openai_compatible_model(
            message=message,
            api_key=api_key,
            base_url=provider_config["base_url"],
            timeout=provider_config["timeout"],
        )

    def infer_with_kimi_model(
        self, message: str
    ) -> Tuple[str, Optional[Dict[str, object]]]:
        """Infer using a Kimi model via Moonshot AI."""
        provider_config = OPENAI_COMPATIBLE_PROVIDERS["kimi"]
        api_key = self._get_required_api_key(
            provider_config["env_keys"], "Kimi / Moonshot"
        )
        return self._infer_with_openai_compatible_model(
            message=message,
            api_key=api_key,
            base_url=provider_config["base_url"],
            timeout=provider_config["timeout"],
        )

    def infer_with_doubao_model(
        self, message: str
    ) -> Tuple[str, Optional[Dict[str, object]]]:
        """Infer using a Doubao model via Volcengine Ark OpenAI-compatible API."""
        provider_config = OPENAI_COMPATIBLE_PROVIDERS["doubao"]
        api_key = self._get_required_api_key(
            provider_config["env_keys"], "Doubao / Volcengine Ark"
        )
        return self._infer_with_openai_compatible_model(
            message=message,
            api_key=api_key,
            base_url=provider_config["base_url"],
            timeout=provider_config["timeout"],
        )

    def infer_with_openai_model(
        self, message
    ) -> Tuple[str, Optional[Dict[str, object]]]:
        """Infer using the OpenAI model"""
        api_key = self._normalize_api_key(
            self._get_required_api_key(["OPENAI_API_KEY"], "OpenAI")
        )
        model_input = self._build_model_input(message)

        def call_api():
            client = OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model=self.online_model_name,
                messages=model_input,
                temperature=self.temperature,
            )
            return (
                response.choices[0].message.content,
                self._extract_usage_from_response(response),
            )

        tryCnt = 0
        while tryCnt < 5:
            tryCnt += 1
            try:
                output = self.run_with_timeout(call_api, timeout=100)
                if output:
                    return output
            except Exception as e:
                self.logger.print_log(f"API error: {e}")
            time.sleep(2)

        return "", None

    def infer_with_o3_mini_model(
        self, message
    ) -> Tuple[str, Optional[Dict[str, object]]]:
        """Infer using the o3-mini model"""
        api_key = self._normalize_api_key(
            self._get_required_api_key(["OPENAI_API_KEY"], "OpenAI")
        )
        model_input = self._build_model_input(message)

        def call_api():
            client = OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model=self.online_model_name, messages=model_input
            )
            return (
                response.choices[0].message.content,
                self._extract_usage_from_response(response),
            )

        tryCnt = 0
        while tryCnt < 5:
            tryCnt += 1
            try:
                output = self.run_with_timeout(call_api, timeout=100)
                if output:
                    return output
            except Exception as e:
                self.logger.print_log(f"API error: {e}")
            time.sleep(2)

        return "", None

    def infer_with_deepseek_model(
        self, message
    ) -> Tuple[str, Optional[Dict[str, object]]]:
        """
        Infer using the DeepSeek model
        """
        api_key = self._get_required_api_key(["DEEPSEEK_API_KEY2"], "DeepSeek")
        model_input = self._build_model_input(message)

        def call_api():
            client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")
            response = client.chat.completions.create(
                model=self.online_model_name,
                messages=model_input,
                temperature=self.temperature,
            )
            return (
                response.choices[0].message.content,
                self._extract_usage_from_response(response),
            )

        tryCnt = 0
        while tryCnt < 5:
            tryCnt += 1
            try:
                output = self.run_with_timeout(call_api, timeout=300)
                if output:
                    return output
            except Exception as e:
                self.logger.print_log(f"API error: {e}")
            time.sleep(2)

        return "", None

    def infer_with_claude_aws_bedrock(
        self, message
    ) -> Tuple[str, Optional[Dict[str, object]]]:
        """Infer using the Claude model via AWS Bedrock"""
        timeout = 500
        model_input = [
            {
                "role": "assistant",
                "content": self.systemRole,
            },
            {"role": "user", "content": message},
        ]

        if "3.5" in self.online_model_name:
            model_id = "anthropic.claude-3-5-sonnet-20241022-v2:0"
            body = json.dumps(
                {
                    "messages": model_input,
                    "max_tokens": self.max_output_length,
                    "anthropic_version": "bedrock-2023-05-31",
                    "temperature": self.temperature,
                    "top_k": 50,
                }
            )
        if "3.7" in self.online_model_name:
            model_id = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
            body = json.dumps(
                {
                    "messages": model_input,
                    "max_tokens": self.max_output_length,
                    "thinking": {
                        "type": "enabled",
                        "budget_tokens": 2048,
                    },
                    "anthropic_version": "bedrock-2023-05-31",
                }
            )

        def call_api():
            client = boto3.client(
                "bedrock-runtime",
                region_name="us-west-2",
                config=Config(read_timeout=timeout),
            )

            response = (
                client.invoke_model(
                    modelId=model_id, contentType="application/json", body=body
                )["body"]
                .read()
                .decode("utf-8")
            )

            response = json.loads(response)

            if "3.5" in self.online_model_name:
                result = response["content"][0]["text"]
            if "3.7" in self.online_model_name:
                result = response["content"][1]["text"]
            return result, None

        tryCnt = 0
        while tryCnt < 5:
            tryCnt += 1
            try:
                output = self.run_with_timeout(call_api, timeout=timeout)
                if output:
                    return output
            except concurrent.futures.TimeoutError:
                self.logger.print_log(
                    f"Timeout occurred, increasing timeout for next attempt"
                )
                timeout = min(timeout * 1.5, 900)
            except Exception as e:
                self.logger.print_log(f"API error: {str(e)}")
            time.sleep(2)

        return "", None

    def infer_with_claude_key(
        self, message
    ) -> Tuple[str, Optional[Dict[str, object]]]:
        """Infer using the Claude model via API key, with thinking mode for 3.7"""
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "Please set the ANTHROPIC_API_KEY environment variable to use Claude models."
            )

        # Prepare messages - Claude prefers user messages over assistant system messages
        model_input = [{"role": "user", "content": f"{self.systemRole}\n\n{message}"}]

        def call_api():
            client = anthropic.Anthropic(api_key=api_key)

            # Determine model and settings based on version
            if "3.7" in self.online_model_name:
                # Claude 3.7 with thinking mode enabled by default
                model_name = "claude-3-7-sonnet-20250219"
                api_params = {
                    "model": model_name,
                    "messages": model_input,
                    "max_tokens": self.max_output_length,
                    "temperature": self.temperature,
                    "thinking": {"type": "enabled", "budget_tokens": 2048},
                }
            else:
                # Claude 3.5 standard mode
                model_name = "claude-3-5-sonnet-20241022"
                api_params = {
                    "model": model_name,
                    "messages": model_input,
                    "max_tokens": self.max_output_length,
                    "temperature": self.temperature,
                    # No thinking parameter for 3.5
                }

            # Make the API call
            response = client.messages.create(**api_params)

            # Extract response text based on model type
            if (
                "3.7" in self.online_model_name
                and hasattr(response, "content")
                and len(response.content) > 1
            ):
                # For Claude 3.7 with thinking mode, get the final response (skip thinking content)
                return response.content[-1].text, None
            else:
                # For Claude 3.5 or any standard response
                return response.content[0].text, None

        tryCnt = 0
        max_retries = 5
        while tryCnt < max_retries:
            tryCnt += 1
            try:
                output = self.run_with_timeout(call_api, timeout=100)
                if output:
                    self.logger.print_log(
                        f"Claude API call successful with {self.online_model_name}"
                    )
                    return output
            except Exception as e:
                self.logger.print_log(
                    f"Claude API error (attempt {tryCnt}/{max_retries}): {e}"
                )
                if tryCnt == max_retries:
                    self.logger.print_log("Max retries reached for Claude API")
            time.sleep(2)
        return "", None
