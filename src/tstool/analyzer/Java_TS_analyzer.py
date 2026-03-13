import re
import sys
from os import path
from typing import Dict, List, Optional, Set, Tuple
import threading
import tree_sitter

sys.path.append(path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))

from .TS_analyzer import *
from memory.syntactic.function import *
from memory.syntactic.value import *


class Java_TSAnalyzer(TSAnalyzer):
    """
    TSAnalyzer for Java source files using tree-sitter.
    Implements Java-specific parsing and analysis.
    """

    def __init__(
        self,
        code_in_files: Dict[str, str],
        language_name: str,
        max_symbolic_workers_num: int = 10,
    ) -> None:
        self.function_sig_to_id: Dict[Tuple[str, int, str], Set[int]] = {}
        self.function_metadata: Dict[int, Dict[str, object]] = {}
        self.file_package_map: Dict[str, str] = {}
        self.file_import_map: Dict[str, Set[str]] = {}
        self.local_type_env_cache: Dict[int, Dict[str, str]] = {}
        self._function_register_lock = threading.Lock()
        super().__init__(code_in_files, language_name, max_symbolic_workers_num)

    def extract_function_info(
        self, file_path: str, source_code: str, tree: tree_sitter.Tree
    ) -> None:
        """
        Parse method declarations as function definitions and attach signatures.
        """
        package_name = self._extract_package_name(tree.root_node, source_code)
        imports = self._extract_imports(tree.root_node, source_code)
        self.file_package_map[file_path] = package_name
        self.file_import_map[file_path] = imports

        # Some benchmark snippets (e.g., JLeaks) concatenate multiple versions
        # in one physical file, producing duplicated method bodies. We dedup
        # methods in-file by (uid + normalized method code) to avoid exploding
        # function/source duplicates.
        seen_method_fingerprints: Set[Tuple[str, str]] = set()

        all_function_definition_nodes = find_nodes_by_type(
            tree.root_node, "method_declaration"
        )
        for node in all_function_definition_nodes:
            function_name = self._extract_method_name(node, source_code)
            if function_name == "":
                continue
            owner_class = self._extract_owner_class(node, source_code)
            param_types = self._extract_parameter_types(node, source_code)
            function_uid = self._build_function_uid(
                package_name, owner_class, function_name, param_types
            )
            method_code = source_code[node.start_byte : node.end_byte]
            method_body_fingerprint = self._normalize_method_code_for_dedup(
                method_code
            )
            method_fingerprint_key = (function_uid, method_body_fingerprint)
            if method_fingerprint_key in seen_method_fingerprints:
                continue
            seen_method_fingerprints.add(method_fingerprint_key)

            start_line_number = source_code[: node.start_byte].count("\n") + 1
            end_line_number = source_code[: node.end_byte].count("\n") + 1

            with self._function_register_lock:
                function_id = len(self.functionRawDataDic) + 1
                self.functionRawDataDic[function_id] = (
                    function_name,
                    start_line_number,
                    end_line_number,
                    node,
                )
                self.functionToFile[function_id] = file_path

                if function_name not in self.functionNameToId:
                    self.functionNameToId[function_name] = set()
                self.functionNameToId[function_name].add(function_id)

                sig_key = (function_name, len(param_types), owner_class)
                if sig_key not in self.function_sig_to_id:
                    self.function_sig_to_id[sig_key] = set()
                self.function_sig_to_id[sig_key].add(function_id)

                self.function_metadata[function_id] = {
                    "owner_class": owner_class,
                    "param_types": param_types,
                    "function_uid": function_uid,
                    "package_name": package_name,
                }
        return

    def _normalize_method_code_for_dedup(self, method_code: str) -> str:
        # Keep it lightweight and deterministic.
        normalized = re.sub(r"\s+", "", method_code)
        return normalized.strip()

    def extract_global_info(
        self, file_path: str, source_code: str, tree: tree_sitter.Tree
    ) -> None:
        """
        Parse the global (macro) information in a Java source file.
        Currently not implemented.
        """
        return

    def extract_meta_data_in_single_function(
        self, current_function: Function
    ) -> Function:
        current_function = super().extract_meta_data_in_single_function(current_function)
        metadata = self.function_metadata.get(current_function.function_id, {})
        current_function.owner_class = str(metadata.get("owner_class", ""))
        current_function.function_uid = str(metadata.get("function_uid", ""))
        param_types = metadata.get("param_types", [])
        if isinstance(param_types, list):
            current_function.param_types = [str(item) for item in param_types]
        current_function.package_name = str(metadata.get("package_name", ""))
        return current_function

    def get_callee_name_at_call_site(
        self, node: tree_sitter.Node, source_code: str
    ) -> str:
        """
        Get the callee (method) name at the call site.
        """
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            return source_code[name_node.start_byte : name_node.end_byte]

        child_texts = [
            source_code[child.start_byte : child.end_byte] for child in node.children
        ]
        if "." in child_texts:
            dot_index = child_texts.index(".")
            if dot_index + 1 < len(child_texts):
                return child_texts[dot_index + 1]
        for child in node.children:
            if child.type == "identifier":
                return source_code[child.start_byte : child.end_byte]
        return ""

    def get_callee_function_ids_at_callsite(
        self, current_function: Function, call_site_node: tree_sitter.Node
    ) -> List[int]:
        """
        Resolve Java callees with signature + receiver + package/import tie-breakers.
        """
        file_name = current_function.file_path
        source_code = self.code_in_files[file_name]
        callee_name = self.get_callee_name_at_call_site(call_site_node, source_code)
        if callee_name == "":
            return []

        arg_count = len(self.get_arguments_at_callsite(current_function, call_site_node))
        candidate_ids: List[int] = []

        for (name, arity, _owner_class), ids in self.function_sig_to_id.items():
            if name == callee_name and arity == arg_count:
                candidate_ids.extend(list(ids))

        if not candidate_ids:
            return super().get_callee_function_ids_at_callsite(
                current_function, call_site_node
            )

        receiver_type = self._infer_receiver_type(
            current_function, call_site_node, source_code
        )
        if receiver_type is not None:
            by_receiver = [
                callee_id
                for callee_id in candidate_ids
                if self._owner_matches_receiver(
                    self.function_env[callee_id].owner_class, receiver_type
                )
            ]
            if by_receiver:
                candidate_ids = by_receiver
            else:
                # Receiver type is known but does not match any project-defined
                # method owner. This is very likely a library/framework call
                # (e.g., properties.load(...)); do not force-map it to an
                # unrelated user method just because name/arity matches.
                return []

        arg_types = self._infer_argument_types(current_function, call_site_node)
        candidate_ids = self._filter_by_argument_types(candidate_ids, arg_types)
        candidate_ids = self._filter_candidates_by_context(
            current_function, candidate_ids, receiver_type
        )
        return sorted(list(set(candidate_ids)))

    def get_callsites_by_callee_name(
        self, current_function: Function, callee_name: str
    ) -> List[tree_sitter.Node]:
        """
        Find call site nodes for the given callee name.
        """
        results = []
        file_content = self.code_in_files[current_function.file_path]
        call_site_nodes = find_nodes_by_type(
            current_function.parse_tree_root_node, "method_invocation"
        )
        for call_site in call_site_nodes:
            if (
                self.get_callee_name_at_call_site(call_site, file_content)
                == callee_name
            ):
                results.append(call_site)
        return results

    def get_arguments_at_callsite(
        self, current_function: Function, call_site_node: tree_sitter.Node
    ) -> Set[Value]:
        """
        Get arguments from a call site in a function.
        :param current_function: the function to be analyzed
        :param call_site_node: the node of the call site
        :return: the arguments
        """
        arguments: Set[Value] = set([])
        file_name = current_function.file_path
        source_code = self.code_in_files[file_name]
        for sub_node in call_site_node.children:
            if sub_node.type == "argument_list":
                arg_list = sub_node.children[1:-1]
                for element in arg_list:
                    if element.type != ",":
                        line_number = source_code[: element.start_byte].count("\n") + 1
                        arguments.add(
                            Value(
                                source_code[element.start_byte : element.end_byte],
                                line_number,
                                ValueLabel.ARG,
                                file_name,
                                len(arguments),
                            )
                        )
        return arguments

    def get_parameters_in_single_function(
        self, current_function: Function
    ) -> Set[Value]:
        """
        Find the parameters of a function.
        :param current_function: The function to be analyzed.
        :return: A set of parameters as values
        """
        if current_function.paras is not None:
            return current_function.paras
        current_function.paras = set([])
        file_content = self.code_in_files[current_function.file_path]
        parameters = find_nodes_by_type(
            current_function.parse_tree_root_node, "formal_parameter"
        )
        index = 0
        for parameter_node in parameters:
            name_node = parameter_node.child_by_field_name("name")
            if name_node is None:
                for sub_node in parameter_node.children:
                    if sub_node.type == "identifier":
                        name_node = sub_node
                        break
            if name_node is not None:
                parameter_name = file_content[name_node.start_byte : name_node.end_byte]
                line_number = file_content[: name_node.start_byte].count("\n") + 1
                current_function.paras.add(
                    Value(
                        parameter_name,
                        line_number,
                        ValueLabel.PARA,
                        current_function.file_path,
                        index,
                    )
                )
                index += 1
        return current_function.paras

    def get_return_values_in_single_function(
        self, current_function: Function
    ) -> Set[Value]:
        """
        Find the return values of a function.
        :param current_function: The function to be analyzed.
        :return: A set of return values
        """
        if current_function.retvals is not None:
            return current_function.retvals

        current_function.retvals = set([])
        file_content = self.code_in_files[current_function.file_path]
        retnodes = find_nodes_by_type(
            current_function.parse_tree_root_node, "return_statement"
        )
        for retnode in retnodes:
            line_number = file_content[: retnode.start_byte].count("\n") + 1
            restmts_str = file_content[retnode.start_byte : retnode.end_byte]
            returned_value = restmts_str.replace("return", "").strip()
            current_function.retvals.add(
                Value(
                    returned_value,
                    line_number,
                    ValueLabel.RET,
                    current_function.file_path,
                    0,
                )
            )
        return current_function.retvals

    def get_if_statements(
        self, function: Function, source_code: str
    ) -> Dict[Tuple, Tuple]:
        """
        Find if-statements in the Java method.
        Returns a dictionary mapping a (start_line, end_line) tuple to the if-statement info.
        """
        if_statement_nodes = find_nodes_by_type(
            function.parse_tree_root_node, "if_statement"
        )
        if_statements = {}
        for if_node in if_statement_nodes:
            condition_str = ""
            condition_start_line = 0
            condition_end_line = 0
            true_branch_start_line = 0
            true_branch_end_line = 0
            else_branch_start_line = 0
            else_branch_end_line = 0

            block_num = 0
            for sub_target in if_node.children:
                if sub_target.type == "parenthesized_expression":
                    condition_start_line = (
                        source_code[: sub_target.start_byte].count("\n") + 1
                    )
                    condition_end_line = (
                        source_code[: sub_target.end_byte].count("\n") + 1
                    )
                    condition_str = source_code[
                        sub_target.start_byte : sub_target.end_byte
                    ]
                if sub_target.type == "block":
                    lower_lines = []
                    upper_lines = []
                    for sub_sub in sub_target.children:
                        if sub_sub.type not in {"{", "}"}:
                            lower_lines.append(
                                source_code[: sub_sub.start_byte].count("\n") + 1
                            )
                            upper_lines.append(
                                source_code[: sub_sub.end_byte].count("\n") + 1
                            )
                    if lower_lines and upper_lines:
                        if block_num == 0:
                            true_branch_start_line = min(lower_lines)
                            true_branch_end_line = max(upper_lines)
                            block_num += 1
                        elif block_num == 1:
                            else_branch_start_line = min(lower_lines)
                            else_branch_end_line = max(upper_lines)
                            block_num += 1
                if sub_target.type == "expression_statement":
                    true_branch_start_line = (
                        source_code[: sub_target.start_byte].count("\n") + 1
                    )
                    true_branch_end_line = (
                        source_code[: sub_target.end_byte].count("\n") + 1
                    )

            if_statement_start_line = source_code[: if_node.start_byte].count("\n") + 1
            if_statement_end_line = source_code[: if_node.end_byte].count("\n") + 1
            line_scope = (if_statement_start_line, if_statement_end_line)
            info = (
                condition_start_line,
                condition_end_line,
                condition_str,
                (true_branch_start_line, true_branch_end_line),
                (else_branch_start_line, else_branch_end_line),
            )
            if_statements[line_scope] = info
        return if_statements

    def get_loop_statements(
        self, function: Function, source_code: str
    ) -> Dict[Tuple, Tuple]:
        """
        Find loop statements in the Java method.
        Returns a dictionary mapping (start_line, end_line) to loop statement information.
        """
        loop_statements = {}
        root_node = function.parse_tree_root_node
        for_statement_nodes = find_nodes_by_type(root_node, "for_statement")
        for_statement_nodes.extend(
            find_nodes_by_type(root_node, "enhanced_for_statement")
        )
        while_statement_nodes = find_nodes_by_type(root_node, "while_statement")

        for loop_node in for_statement_nodes:
            loop_start_line = source_code[: loop_node.start_byte].count("\n") + 1
            loop_end_line = source_code[: loop_node.end_byte].count("\n") + 1

            header_line_start = 0
            header_line_end = 0
            header_str = ""
            loop_body_start_line = 0
            loop_body_end_line = 0

            header_start_byte = 0
            header_end_byte = 0

            for child in loop_node.children:
                if child.type == "(":
                    header_line_start = source_code[: child.start_byte].count("\n") + 1
                    header_start_byte = child.end_byte
                if child.type == ")":
                    header_line_end = source_code[: child.end_byte].count("\n") + 1
                    header_end_byte = child.start_byte
                    header_str = source_code[header_start_byte:header_end_byte]
                if child.type == "block":
                    lower_lines = []
                    upper_lines = []
                    for sub in child.children:
                        if sub.type not in {"{", "}"}:
                            lower_lines.append(
                                source_code[: sub.start_byte].count("\n") + 1
                            )
                            upper_lines.append(
                                source_code[: sub.end_byte].count("\n") + 1
                            )
                    if lower_lines and upper_lines:
                        loop_body_start_line = min(lower_lines)
                        loop_body_end_line = max(upper_lines)
                if child.type == "expression_statement":
                    loop_body_start_line = (
                        source_code[: child.start_byte].count("\n") + 1
                    )
                    loop_body_end_line = source_code[: child.end_byte].count("\n") + 1
            loop_statements[(loop_start_line, loop_end_line)] = (
                header_line_start,
                header_line_end,
                header_str,
                loop_body_start_line,
                loop_body_end_line,
            )

        for loop_node in while_statement_nodes:
            loop_start_line = source_code[: loop_node.start_byte].count("\n") + 1
            loop_end_line = source_code[: loop_node.end_byte].count("\n") + 1

            header_line_start = 0
            header_line_end = 0
            header_str = ""
            loop_body_start_line = 0
            loop_body_end_line = 0

            for child in loop_node.children:
                if child.type == "parenthesized_expression":
                    header_line_start = source_code[: child.start_byte].count("\n") + 1
                    header_line_end = source_code[: child.end_byte].count("\n") + 1
                    header_str = source_code[child.start_byte : child.end_byte]
                if child.type == "block":
                    lower_lines = []
                    upper_lines = []
                    for sub in child.children:
                        if sub.type not in {"{", "}"}:
                            lower_lines.append(
                                source_code[: sub.start_byte].count("\n") + 1
                            )
                            upper_lines.append(
                                source_code[: sub.end_byte].count("\n") + 1
                            )
                    if lower_lines and upper_lines:
                        loop_body_start_line = min(lower_lines)
                        loop_body_end_line = max(upper_lines)
            loop_statements[(loop_start_line, loop_end_line)] = (
                header_line_start,
                header_line_end,
                header_str,
                loop_body_start_line,
                loop_body_end_line,
            )
        return loop_statements

    def _extract_package_name(self, root_node: tree_sitter.Node, source_code: str) -> str:
        package_nodes = find_nodes_by_type(root_node, "package_declaration")
        if len(package_nodes) == 0:
            return ""
        package_text = source_code[
            package_nodes[0].start_byte : package_nodes[0].end_byte
        ]
        return package_text.replace("package", "").replace(";", "").strip()

    def _extract_imports(self, root_node: tree_sitter.Node, source_code: str) -> Set[str]:
        imports: Set[str] = set()
        import_nodes = find_nodes_by_type(root_node, "import_declaration")
        for import_node in import_nodes:
            import_text = source_code[import_node.start_byte : import_node.end_byte]
            import_text = import_text.replace("import", "").replace(";", "").strip()
            if import_text.startswith("static "):
                import_text = import_text[len("static ") :].strip()
            if import_text != "":
                imports.add(import_text)
        return imports

    def _extract_method_name(self, method_node: tree_sitter.Node, source_code: str) -> str:
        name_node = method_node.child_by_field_name("name")
        if name_node is not None:
            return source_code[name_node.start_byte : name_node.end_byte]
        for child in method_node.children:
            if child.type == "identifier":
                return source_code[child.start_byte : child.end_byte]
        return ""

    def _extract_owner_class(self, node: tree_sitter.Node, source_code: str) -> str:
        owner_names: List[str] = []
        parent = node.parent
        while parent is not None:
            if parent.type in {
                "class_declaration",
                "interface_declaration",
                "enum_declaration",
                "record_declaration",
                "annotation_type_declaration",
            }:
                class_name = self._extract_type_identifier(parent, source_code)
                if class_name:
                    owner_names.append(class_name)
            parent = parent.parent
        owner_names.reverse()
        return ".".join(owner_names)

    def _extract_type_identifier(
        self, node: tree_sitter.Node, source_code: str
    ) -> Optional[str]:
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            return source_code[name_node.start_byte : name_node.end_byte]
        for child in node.children:
            if child.type in {"identifier", "type_identifier"}:
                return source_code[child.start_byte : child.end_byte]
        return None

    def _extract_parameter_types(
        self, method_node: tree_sitter.Node, source_code: str
    ) -> List[str]:
        parameter_types: List[str] = []
        parameters_node = method_node.child_by_field_name("parameters")
        if parameters_node is None:
            for child in method_node.children:
                if child.type == "formal_parameters":
                    parameters_node = child
                    break
        if parameters_node is None:
            return parameter_types
        for child in parameters_node.children:
            if child.type not in {"formal_parameter", "spread_parameter"}:
                continue
            parameter_types.append(self._extract_declared_type(child, source_code))
        return parameter_types

    def _build_function_uid(
        self,
        package_name: str,
        owner_class: str,
        function_name: str,
        param_types: List[str],
    ) -> str:
        owner = owner_class
        if package_name != "" and owner_class != "":
            owner = f"{package_name}.{owner_class}"
        elif package_name != "":
            owner = package_name
        params = ",".join(param_types)
        if owner != "":
            return f"{owner}.{function_name}({params})"
        return f"{function_name}({params})"

    def _build_local_type_env(self, current_function: Function) -> Dict[str, str]:
        if current_function.function_id in self.local_type_env_cache:
            return self.local_type_env_cache[current_function.function_id]

        source_code = self.code_in_files[current_function.file_path]
        env: Dict[str, str] = {}

        parameter_nodes = find_nodes_by_type(
            current_function.parse_tree_root_node, "formal_parameter"
        )
        for parameter_node in parameter_nodes:
            type_name = self._extract_declared_type(parameter_node, source_code)
            name_node = parameter_node.child_by_field_name("name")
            if name_node is None:
                for sub_node in parameter_node.children:
                    if sub_node.type == "identifier":
                        name_node = sub_node
                        break
            if name_node is not None:
                name = source_code[name_node.start_byte : name_node.end_byte]
                if name != "":
                    env[name] = type_name

        local_decl_nodes = find_nodes_by_type(
            current_function.parse_tree_root_node, "local_variable_declaration"
        )
        for decl_node in local_decl_nodes:
            type_name = self._extract_declared_type(decl_node, source_code)
            declarators = find_nodes_by_type(decl_node, "variable_declarator")
            for declarator in declarators:
                name_node = declarator.child_by_field_name("name")
                if name_node is None:
                    for sub_node in declarator.children:
                        if sub_node.type == "identifier":
                            name_node = sub_node
                            break
                if name_node is None:
                    continue
                name = source_code[name_node.start_byte : name_node.end_byte]
                if name != "":
                    env[name] = type_name

        self.local_type_env_cache[current_function.function_id] = env
        return env

    def _infer_receiver_type(
        self,
        current_function: Function,
        call_site_node: tree_sitter.Node,
        source_code: str,
    ) -> Optional[str]:
        receiver_node = call_site_node.child_by_field_name("object")
        if receiver_node is None:
            return current_function.owner_class if current_function.owner_class != "" else None

        receiver_text = source_code[
            receiver_node.start_byte : receiver_node.end_byte
        ].strip()
        if receiver_text in {"this", "super"}:
            return current_function.owner_class if current_function.owner_class != "" else None

        local_type_env = self._build_local_type_env(current_function)
        if receiver_text in local_type_env:
            return self._normalize_type(local_type_env[receiver_text])

        if "." in receiver_text:
            prefix = receiver_text.split(".")[0]
            if prefix in local_type_env:
                return self._normalize_type(local_type_env[prefix])

        if receiver_text != "" and receiver_text[0].isupper():
            return self._normalize_type(receiver_text)
        return None

    def _infer_argument_types(
        self, current_function: Function, call_site_node: tree_sitter.Node
    ) -> List[Optional[str]]:
        source_code = self.code_in_files[current_function.file_path]
        local_type_env = self._build_local_type_env(current_function)
        arg_types: List[Optional[str]] = []

        argument_list_node = None
        for child in call_site_node.children:
            if child.type == "argument_list":
                argument_list_node = child
                break
        if argument_list_node is None:
            return arg_types

        for arg_node in argument_list_node.children:
            if arg_node.type in {",", "(", ")"}:
                continue
            arg_text = source_code[arg_node.start_byte : arg_node.end_byte].strip()
            inferred_type: Optional[str] = None

            if arg_node.type in {"decimal_integer_literal", "hex_integer_literal"}:
                inferred_type = "int"
            elif arg_node.type in {"decimal_floating_point_literal"}:
                inferred_type = "double"
            elif arg_node.type == "string_literal":
                inferred_type = "String"
            elif arg_node.type in {"true", "false", "boolean_literal"}:
                inferred_type = "boolean"
            elif arg_node.type == "null_literal":
                inferred_type = None
            elif arg_node.type == "identifier" and arg_text in local_type_env:
                inferred_type = local_type_env[arg_text]
            elif arg_node.type == "object_creation_expression":
                inferred_type = self._extract_object_creation_type(arg_node, source_code)

            if inferred_type is None:
                arg_types.append(None)
            else:
                arg_types.append(self._normalize_type(inferred_type))
        return arg_types

    def _filter_by_argument_types(
        self, candidate_ids: List[int], arg_types: List[Optional[str]]
    ) -> List[int]:
        if len(arg_types) == 0 or len(candidate_ids) <= 1:
            return candidate_ids

        best_ids: List[int] = []
        best_score = -1

        for candidate_id in candidate_ids:
            candidate = self.function_env[candidate_id]
            if len(candidate.param_types) == 0:
                continue
            score = 0
            consistent = True
            for idx, arg_type in enumerate(arg_types):
                if arg_type is None or idx >= len(candidate.param_types):
                    continue
                para_type = self._normalize_type(candidate.param_types[idx])
                if para_type == arg_type:
                    score += 1
                elif para_type != "Object":
                    consistent = False
                    break
            if not consistent:
                continue
            if score > best_score:
                best_score = score
                best_ids = [candidate_id]
            elif score == best_score:
                best_ids.append(candidate_id)
        if len(best_ids) > 0:
            return best_ids
        return candidate_ids

    def _filter_candidates_by_context(
        self,
        current_function: Function,
        candidate_ids: List[int],
        receiver_type: Optional[str],
    ) -> List[int]:
        if len(candidate_ids) <= 1:
            return candidate_ids

        if receiver_type is not None:
            exact_owner = [
                candidate_id
                for candidate_id in candidate_ids
                if self._normalize_type(self.function_env[candidate_id].owner_class)
                == self._normalize_type(receiver_type)
            ]
            if len(exact_owner) > 0:
                return self._select_single_candidate_deterministically(exact_owner)

        same_owner = [
            candidate_id
            for candidate_id in candidate_ids
            if self.function_env[candidate_id].owner_class == current_function.owner_class
        ]
        if len(same_owner) > 0:
            return self._select_single_candidate_deterministically(same_owner)

        current_package = self.file_package_map.get(current_function.file_path, "")
        imports = self.file_import_map.get(current_function.file_path, set())
        imported_classes = {
            import_item.split(".")[-1]
            for import_item in imports
            if not import_item.endswith(".*")
        }
        wildcard_import_packages = {
            import_item[:-2].strip()
            for import_item in imports
            if import_item.endswith(".*")
        }

        imported_matches = [
            candidate_id
            for candidate_id in candidate_ids
            if self.function_env[candidate_id].owner_class.split(".")[-1]
            in imported_classes
        ]
        if len(imported_matches) > 0:
            return self._select_single_candidate_deterministically(imported_matches)

        wildcard_matches = [
            candidate_id
            for candidate_id in candidate_ids
            if self._is_candidate_in_wildcard_import_packages(
                self.function_env[candidate_id], wildcard_import_packages
            )
        ]
        if len(wildcard_matches) > 0:
            return self._select_single_candidate_deterministically(wildcard_matches)

        same_package = [
            candidate_id
            for candidate_id in candidate_ids
            if self.function_env[candidate_id].package_name == current_package
        ]
        if len(same_package) > 0:
            return self._select_single_candidate_deterministically(same_package)

        return self._select_single_candidate_deterministically(candidate_ids)

    def _owner_matches_receiver(self, owner_class: str, receiver_type: str) -> bool:
        normalized_owner = self._normalize_type(owner_class)
        normalized_receiver = self._normalize_type(receiver_type)
        if normalized_owner == "" or normalized_receiver == "":
            return False
        return normalized_owner == normalized_receiver

    def _is_candidate_in_wildcard_import_packages(
        self, candidate: Function, wildcard_import_packages: Set[str]
    ) -> bool:
        if len(wildcard_import_packages) == 0:
            return False
        candidate_package = candidate.package_name.strip()
        if candidate_package == "":
            return False
        for wildcard_pkg in wildcard_import_packages:
            if wildcard_pkg == "":
                continue
            if candidate_package == wildcard_pkg or candidate_package.startswith(
                wildcard_pkg + "."
            ):
                return True
        return False

    def _select_single_candidate_deterministically(
        self, candidate_ids: List[int]
    ) -> List[int]:
        if len(candidate_ids) <= 1:
            return candidate_ids
        normalized = sorted(set(candidate_ids))
        return [normalized[0]]

    def _extract_declared_type(self, node: tree_sitter.Node, source_code: str) -> str:
        type_node = node.child_by_field_name("type")
        if type_node is None:
            for child in node.children:
                if "type" in child.type:
                    type_node = child
                    break
        if type_node is None:
            for child in node.children:
                if child.type in {
                    "identifier",
                    "type_identifier",
                    "generic_type",
                    "integral_type",
                    "floating_point_type",
                    "boolean_type",
                    "void_type",
                    "scoped_type_identifier",
                }:
                    type_node = child
                    break
        if type_node is None:
            return ""
        raw_type = source_code[type_node.start_byte : type_node.end_byte]
        return self._normalize_type(raw_type)

    def _extract_object_creation_type(
        self, node: tree_sitter.Node, source_code: str
    ) -> str:
        type_node = node.child_by_field_name("type")
        if type_node is None:
            for child in node.children:
                if "type" in child.type:
                    type_node = child
                    break
        if type_node is None:
            return ""
        return self._normalize_type(source_code[type_node.start_byte : type_node.end_byte])

    def _normalize_type(self, type_name: Optional[str]) -> str:
        if type_name is None:
            return ""
        name = type_name.strip()
        if name == "":
            return ""
        name = re.sub(r"@\w+", "", name)
        name = re.sub(r"<.*?>", "", name)
        name = name.replace("[]", "")
        name = re.sub(r"\s+", "", name)
        if "." in name:
            name = name.split(".")[-1]
        return name
