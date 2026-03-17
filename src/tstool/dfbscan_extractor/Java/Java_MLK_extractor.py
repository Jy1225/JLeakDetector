import re
from typing import Dict, List, Optional, Set

from tstool.analyzer.Java_TS_analyzer import *
from tstool.analyzer.TS_analyzer import *

from ..dfbscan_extractor import *


class Java_MLK_Extractor(DFBScanExtractor):
    """
    Java memory/resource leak extractor focused on AutoCloseable resources.
    """

    RESOURCE_SUFFIXES = (
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
        "ThreadPool",
        "Transaction",
        "EntityManager",
        "SessionFactory",
        "SqlSession",
        "Cursor",
        "Subscription",
        "Process",
    )

    RESOURCE_TYPE_WHITELIST = {
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
        "PushbackInputStream",
        "PushbackReader",
        "LineNumberReader",
        "Socket",
        "ServerSocket",
        "DatagramSocket",
        "MulticastSocket",
        "SocketChannel",
        "ServerSocketChannel",
        "DatagramChannel",
        "AsynchronousSocketChannel",
        "AsynchronousServerSocketChannel",
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
        "Future",
        "CompletableFuture",
        "EntityManager",
        "EntityManagerFactory",
        "SessionFactory",
        "Session",
        "Transaction",
        "UserTransaction",
        "SqlSession",
        "SqlSessionManager",
        "Cursor",
        "WatchKey",
        "Subscription",
        "Disposable",
        "KafkaConsumer",
        "KafkaProducer",
        "JMSContext",
        "JMSConsumer",
        "EventLoopGroup",
        "ManagedChannel",
        "Process",
        "ProcessBuilder",
        "ReentrantLock",
        "ReadWriteLock",
        "ReentrantReadWriteLock",
        "Lock",
        "StampedLock",
        "Semaphore",
    }

    # In-memory wrappers are excluded from external-resource leak scope.
    RESOURCE_TYPE_EXCLUDELIST = {
        "ByteArrayInputStream",
        "ByteArrayOutputStream",
        "CharArrayReader",
        "CharArrayWriter",
        "StringReader",
        "StringWriter",
    }

    FACTORY_METHOD_NAMES = {
        "open",
        "openStream",
        "getInputStream",
        "getErrorStream",
        "getOutputStream",
        "getWriter",
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
        "getRandomAccessFile",
        "openConnection",
        "writeAttribute",
        "encode",
        "newFixedThreadPool",
        "newCachedThreadPool",
        "newSingleThreadExecutor",
        "newSingleThreadScheduledExecutor",
        "newScheduledThreadPool",
        "newWorkStealingPool",
        "newVirtualThreadPerTaskExecutor",
        "newThreadPerTaskExecutor",
        "createTempFile",
        "createTempDirectory",
        "beginTransaction",
        "startTransaction",
        "getTransaction",
        "openSession",
        "getSession",
        "createEntityManager",
        "createEntityManagerFactory",
        "openCursor",
        "subscribe",
        "exec",
        "start",
        "spawn",
    }

    TEMP_RESOURCE_FACTORY_METHOD_NAMES = {
        "createTempFile",
        "createTempDirectory",
    }

    TYPE_OPTIONAL_FACTORY_METHOD_NAMES = (
        TEMP_RESOURCE_FACTORY_METHOD_NAMES
        | {
            "beginTransaction",
            "startTransaction",
            "getTransaction",
            "openSession",
            "getSession",
            "createEntityManager",
            "createEntityManagerFactory",
            "openCursor",
            # High-confidence resource factory APIs frequently assigned to fields
            # or wrapped immediately where local variable type is unavailable.
            "newInputStream",
            "newOutputStream",
            "newBufferedReader",
            "newBufferedWriter",
            "getInputStream",
            "getOutputStream",
            "getWriter",
            "getResourceAsStream",
            "getRandomAccessFile",
            "writeAttribute",
            "encode",
        }
    )

    HIGH_CONFIDENCE_FACTORY_METHOD_NAMES = {
        "open",
        "openStream",
        "getInputStream",
        "getOutputStream",
        "getWriter",
        "newInputStream",
        "newOutputStream",
        "newBufferedReader",
        "newBufferedWriter",
        "getResourceAsStream",
        "getRandomAccessFile",
        "writeAttribute",
        "encode",
    }

    ARG_CONTEXT_RESOURCE_CONSUMER_METHOD_NAMES = {
        "load",
        "read",
        "parse",
        "copy",
        "transferTo",
        "consume",
        "decode",
        "encode",
        "setEntity",
        "setContent",
    }

    CLOSE_METHOD_NAMES = {
        "close",
        "closeQuietly",
        "closeSilently",
        "closeIgnoringExceptions",
        "closeWhileHandlingException",
        "closeUnchecked",
        "abort",
        "disconnect",
        "shutdown",
        "shutdownNow",
        "unlock",
        "tryUnlock",
        "release",
        "delete",
        "deleteIfExists",
        "deleteOnExit",
        "stop",
        "destroy",
        "destroyForcibly",
        "waitFor",
        "dispose",
        "terminate",
        "commit",
        "rollback",
        "end",
        "endTransaction",
        "cancel",
        "unsubscribe",
        "unregister",
        "invalidate",
        "purge",
    }

    ACQUIRE_METHOD_NAMES = {
        "lock",
        "tryLock",
        "lockInterruptibly",
        "acquire",
        "acquireUninterruptibly",
        "begin",
        "beginTransaction",
        "startTransaction",
        "getTransaction",
        "openSession",
        "getSession",
        "createEntityManager",
        "createEntityManagerFactory",
        "openCursor",
        "subscribe",
        "exec",
        "start",
        "spawn",
    }

    ACQUIRE_FALLBACK_PATTERNS = (
        ".lock(",
        ".trylock(",
        ".acquire(",
        ".begintransaction(",
        ".starttransaction(",
        ".runtime.getruntime().exec(",
    )

    def extract_sources(self, function: Function) -> List[Value]:
        sources: List[Value] = []
        sources.extend(self._extract_new_resource_sources(function))
        sources.extend(self._extract_factory_resource_sources(function))
        sources.extend(self._extract_return_context_factory_sources(function))
        sources.extend(self._extract_argument_context_factory_sources(function))
        sources.extend(self._extract_acquire_sources(function))
        sources.extend(self._extract_twr_sources(function))
        if len(sources) == 0:
            # Fallback for parser/call-graph miss cases on snippets:
            # do lightweight line-level pattern mining only when AST-based
            # extraction yields no source in this function.
            sources.extend(self._extract_line_pattern_sources(function))
        return self._dedup_source_values(sources)

    def extract_sinks(self, function: Function) -> List[Value]:
        sinks: List[Value] = []
        sinks.extend(self._extract_explicit_close_sinks(function))
        sinks.extend(self._extract_twr_implicit_sinks(function))
        return self._dedup_values(sinks)

    def _extract_new_resource_sources(self, function: Function) -> List[Value]:
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        sources: List[Value] = []
        nodes = find_nodes_by_type(function.parse_tree_root_node, "object_creation_expression")
        for node in nodes:
            type_name = self._extract_creation_type_name(node, source_code)
            if not self._is_resource_type(type_name):
                continue
            # Avoid duplicate reporting for nested wrappers such as:
            # new BufferedReader(new InputStreamReader(...))
            if self._is_wrapped_inner_creation(node, source_code):
                continue
            sources.append(
                Value(
                    source_code[node.start_byte : node.end_byte],
                    self._line_of(node, source_code),
                    ValueLabel.SRC,
                    function.file_path,
                )
            )
        return sources

    def _extract_factory_resource_sources(self, function: Function) -> List[Value]:
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        local_type_map = self._build_local_type_map(function, source_code)
        sources: List[Value] = []
        invocations = find_nodes_by_type(function.parse_tree_root_node, "method_invocation")
        for node in invocations:
            method_name = self._get_invocation_name(node, source_code)
            if method_name not in self.FACTORY_METHOD_NAMES:
                continue

            if not self._is_resource_factory_return(node, source_code, local_type_map):
                continue

            sources.append(
                Value(
                    source_code[node.start_byte : node.end_byte],
                    self._line_of(node, source_code),
                    ValueLabel.SRC,
                    function.file_path,
                )
            )
        return sources

    def _extract_return_context_factory_sources(self, function: Function) -> List[Value]:
        """
        Fallback source extraction for return-context factories:
          return Files.newOutputStream(path);
          return loader.getResourceAsStream(name);
        """
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        sources: List[Value] = []
        invocations = find_nodes_by_type(function.parse_tree_root_node, "method_invocation")
        for node in invocations:
            method_name = self._get_invocation_name(node, source_code)
            if method_name not in self.FACTORY_METHOD_NAMES:
                continue
            if not self._is_high_confidence_factory_method(method_name):
                continue
            if not self._is_factory_in_return_context(node, function, source_code):
                continue
            sources.append(
                Value(
                    source_code[node.start_byte : node.end_byte],
                    self._line_of(node, source_code),
                    ValueLabel.SRC,
                    function.file_path,
                )
            )
        return sources

    def _extract_argument_context_factory_sources(self, function: Function) -> List[Value]:
        """
        Fallback source extraction for argument-context factories:
          load(Files.newInputStream(path));
          new BufferedReader(loader.getResourceAsStream(...));
        """
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        sources: List[Value] = []
        invocations = find_nodes_by_type(function.parse_tree_root_node, "method_invocation")
        for node in invocations:
            method_name = self._get_invocation_name(node, source_code)
            if method_name not in self.FACTORY_METHOD_NAMES:
                continue
            if not self._is_high_confidence_factory_method(method_name):
                continue
            if not self._is_factory_in_argument_context(node, source_code):
                continue
            sources.append(
                Value(
                    source_code[node.start_byte : node.end_byte],
                    self._line_of(node, source_code),
                    ValueLabel.SRC,
                    function.file_path,
                )
            )
        return sources

    def _extract_twr_sources(self, function: Function) -> List[Value]:
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        sources: List[Value] = []
        try_nodes = self._find_try_with_resources_nodes(function.parse_tree_root_node)
        for try_node in try_nodes:
            resource_decls = find_nodes_by_type(try_node, "local_variable_declaration")
            for decl in resource_decls:
                declared_type = self._extract_declared_type_from_decl(decl, source_code)
                if not self._is_resource_type(declared_type):
                    continue
                sources.append(
                    Value(
                        source_code[decl.start_byte : decl.end_byte],
                        self._line_of(decl, source_code),
                        ValueLabel.SRC,
                        function.file_path,
                    )
                )
        return sources

    def _extract_acquire_sources(self, function: Function) -> List[Value]:
        """
        Extract non-AutoCloseable resource acquire points, e.g.:
          lock.lock();
          semaphore.acquire();
        """
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        local_type_map = self._build_local_type_map(function, source_code)
        sources: List[Value] = []
        invocations = find_nodes_by_type(function.parse_tree_root_node, "method_invocation")
        for node in invocations:
            method_name = self._get_invocation_name(node, source_code)
            if method_name not in self.ACQUIRE_METHOD_NAMES:
                continue
            if not self._is_acquire_on_resource_receiver(node, source_code, local_type_map):
                continue
            sources.append(
                Value(
                    source_code[node.start_byte : node.end_byte],
                    self._line_of(node, source_code),
                    ValueLabel.SRC,
                    function.file_path,
                )
            )
        return sources

    def _extract_explicit_close_sinks(self, function: Function) -> List[Value]:
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        sinks: List[Value] = []
        nodes = find_nodes_by_type(function.parse_tree_root_node, "method_invocation")
        for node in nodes:
            method_name = self._get_invocation_name(node, source_code)
            if method_name not in self.CLOSE_METHOD_NAMES:
                continue
            sinks.append(
                Value(
                    source_code[node.start_byte : node.end_byte],
                    self._line_of(node, source_code),
                    ValueLabel.SINK,
                    function.file_path,
                )
            )
        return sinks

    def _extract_twr_implicit_sinks(self, function: Function) -> List[Value]:
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        sinks: List[Value] = []
        try_nodes = self._find_try_with_resources_nodes(function.parse_tree_root_node)
        for try_node in try_nodes:
            resource_decls = find_nodes_by_type(try_node, "local_variable_declaration")
            for decl in resource_decls:
                declared_type = self._extract_declared_type_from_decl(decl, source_code)
                if not self._is_resource_type(declared_type):
                    continue
                sinks.append(
                    Value(
                        "implicit_close",
                        self._line_of(try_node, source_code),
                        ValueLabel.SINK,
                        function.file_path,
                    )
                )
        return sinks

    def _is_resource_type(self, type_name: str) -> bool:
        normalized = type_name.strip()
        if normalized == "":
            return False
        if normalized in self.RESOURCE_TYPE_EXCLUDELIST:
            return False
        if normalized in self.RESOURCE_TYPE_WHITELIST:
            return True
        for suffix in self.RESOURCE_SUFFIXES:
            if normalized.endswith(suffix):
                return True
        return False

    def _get_invocation_name(self, node: Node, source_code: str) -> str:
        if isinstance(self.ts_analyzer, Java_TSAnalyzer):
            return self.ts_analyzer.get_callee_name_at_call_site(node, source_code)
        child_texts = [source_code[child.start_byte : child.end_byte] for child in node.children]
        if "." in child_texts:
            dot_index = child_texts.index(".")
            if dot_index + 1 < len(child_texts):
                return child_texts[dot_index + 1]
        return child_texts[0] if len(child_texts) > 0 else ""

    def _dedup_values(self, values: List[Value]) -> List[Value]:
        unique: Dict[str, Value] = {}
        for value in values:
            unique[str(value)] = value
        return list(unique.values())

    def _dedup_source_values(self, values: List[Value]) -> List[Value]:
        """
        Semantic dedup for sources:
        - Collapse syntactic variants on the same line, e.g.
          `final OutputStream out = Files.newOutputStream(...)`
          and `Files.newOutputStream(...)`.
        - Keep the more informative textual form when collision happens.
        """
        unique: Dict[Tuple[str, int, str], Value] = {}
        for value in values:
            normalized_expr = self._normalize_source_expr(value.name)
            key = (value.file, value.line_number, normalized_expr)
            prev = unique.get(key)
            if prev is None:
                unique[key] = value
                continue
            if len(value.name) > len(prev.name):
                unique[key] = value
        return list(unique.values())

    def _normalize_source_expr(self, expr: str) -> str:
        normalized = expr.strip().rstrip(";")
        assign_match = re.match(r"^[^=]+=\s*(.+)$", normalized)
        if assign_match is not None and "==" not in normalized:
            normalized = assign_match.group(1).strip()
        if normalized.startswith("return "):
            normalized = normalized[len("return ") :].strip()
        normalized = re.sub(r"\s+", "", normalized)
        return normalized

    def _line_of(self, node: Node, source_code: str) -> int:
        return source_code[: node.start_byte].count("\n") + 1

    def _extract_creation_type_name(self, node: Node, source_code: str) -> str:
        type_node = node.child_by_field_name("type")
        if type_node is None:
            for child in node.children:
                if "type" in child.type:
                    type_node = child
                    break
        if type_node is None:
            return ""
        raw_type = source_code[type_node.start_byte : type_node.end_byte]
        return self._normalize_type(raw_type)

    def _normalize_type(self, raw_type: str) -> str:
        normalized = raw_type.strip()
        if normalized == "":
            return ""
        if "<" in normalized:
            normalized = normalized.split("<")[0]
        if "." in normalized:
            normalized = normalized.split(".")[-1]
        normalized = normalized.replace("[]", "")
        return normalized.strip()

    def _is_wrapped_inner_creation(self, node: Node, source_code: str) -> bool:
        """
        Return True when this creation expression is an inner constructor argument
        of another resource creation expression.
        """
        parent = node.parent
        while parent is not None:
            if parent.type == "object_creation_expression":
                outer_type = self._extract_creation_type_name(parent, source_code)
                return self._is_resource_type(outer_type)
            parent = parent.parent
        return False

    def _build_local_type_map(self, function: Function, source_code: str) -> Dict[str, str]:
        local_type_map: Dict[str, str] = {}
        formal_params = find_nodes_by_type(function.parse_tree_root_node, "formal_parameter")
        for param in formal_params:
            type_name = self._extract_declared_type_from_decl(param, source_code)
            name_node = param.child_by_field_name("name")
            if name_node is None:
                for sub_node in param.children:
                    if sub_node.type == "identifier":
                        name_node = sub_node
                        break
            if name_node is not None:
                local_type_map[
                    source_code[name_node.start_byte : name_node.end_byte]
                ] = type_name

        local_decls = find_nodes_by_type(
            function.parse_tree_root_node, "local_variable_declaration"
        )
        for decl in local_decls:
            type_name = self._extract_declared_type_from_decl(decl, source_code)
            declarators = find_nodes_by_type(decl, "variable_declarator")
            for declarator in declarators:
                name_node = declarator.child_by_field_name("name")
                if name_node is None:
                    for child in declarator.children:
                        if child.type == "identifier":
                            name_node = child
                            break
                if name_node is None:
                    continue
                local_type_map[
                    source_code[name_node.start_byte : name_node.end_byte]
                ] = type_name
        return local_type_map

    def _extract_declared_type_from_decl(self, decl: Node, source_code: str) -> str:
        type_node = decl.child_by_field_name("type")
        if type_node is None:
            for child in decl.children:
                if "type" in child.type:
                    type_node = child
                    break
        if type_node is None:
            return ""
        return self._normalize_type(source_code[type_node.start_byte : type_node.end_byte])

    def _is_resource_factory_return(
        self,
        invocation_node: Node,
        source_code: str,
        local_type_map: Dict[str, str],
    ) -> bool:
        parent = invocation_node.parent
        while parent is not None and parent.type in {"parenthesized_expression"}:
            parent = parent.parent

        if parent is None:
            return False

        method_name = self._get_invocation_name(invocation_node, source_code)
        allow_without_type = method_name in self.TYPE_OPTIONAL_FACTORY_METHOD_NAMES

        if parent.type == "variable_declarator":
            var_name = ""
            for child in parent.children:
                if child.type == "identifier":
                    var_name = source_code[child.start_byte : child.end_byte]
                    break
            if allow_without_type:
                return var_name.strip() != ""
            return self._is_resource_type(local_type_map.get(var_name, ""))

        if parent.type == "assignment_expression":
            left = parent.child_by_field_name("left")
            if left is None and len(parent.children) > 0:
                left = parent.children[0]
            if left is None:
                return False
            left_name = source_code[left.start_byte : left.end_byte].strip()
            if allow_without_type:
                return left_name != ""
            left_type = local_type_map.get(left_name, "")
            if self._is_resource_type(left_type):
                return True
            base_name = left_name.split(".", 1)[0].strip()
            if self._is_resource_type(local_type_map.get(base_name, "")):
                return True
            if left_name.startswith("this."):
                field_name = left_name.split(".", 1)[1].strip()
                field_type = self._lookup_field_type(invocation_node, field_name, source_code)
                if self._is_resource_type(field_type):
                    return True
            return False

        if parent.type == "return_statement":
            if allow_without_type:
                return True
            return self._method_returns_resource_like(invocation_node, source_code)

        if parent.type == "argument_list":
            if self._is_factory_in_argument_context(invocation_node, source_code):
                return True

        return False

    def _is_acquire_on_resource_receiver(
        self,
        invocation_node: Node,
        source_code: str,
        local_type_map: Dict[str, str],
    ) -> bool:
        invocation_text = source_code[
            invocation_node.start_byte : invocation_node.end_byte
        ].strip()
        if invocation_text == "":
            return False

        receiver_match = re.match(
            r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\s*\(",
            invocation_text,
        )
        if receiver_match is not None:
            receiver_name = receiver_match.group(1).strip()
            receiver_type = local_type_map.get(receiver_name, "")
            if self._is_resource_type(receiver_type):
                return True

        # Fallback: keep acquisition patterns even without local type.
        lowered = invocation_text.lower()
        if any(pattern in lowered for pattern in self.ACQUIRE_FALLBACK_PATTERNS):
            return True
        return False

    def _find_try_with_resources_nodes(self, root_node: Node) -> List[Node]:
        candidates: List[Node] = []
        for node_type in ["try_with_resources_statement", "try_statement"]:
            candidates.extend(find_nodes_by_type(root_node, node_type))
        results: List[Node] = []
        for node in candidates:
            has_resource = len(find_nodes_by_type(node, "resource_specification")) > 0
            if has_resource:
                results.append(node)
        return results

    def _extract_line_pattern_sources(self, function: Function) -> List[Value]:
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        sources: List[Value] = []

        factory_name_pattern = "|".join(
            sorted(
                set(
                    list(self.HIGH_CONFIDENCE_FACTORY_METHOD_NAMES)
                    + [
                        "newInputStream",
                        "newOutputStream",
                        "newBufferedReader",
                        "newBufferedWriter",
                        "getInputStream",
                        "getOutputStream",
                        "getWriter",
                        "getResourceAsStream",
                        "getRandomAccessFile",
                        "writeAttribute",
                        "encode",
                    ]
                ),
                key=lambda item: (len(item), item),
                reverse=True,
            )
        )
        factory_regex = re.compile(
            rf"\.\s*(?:{factory_name_pattern})\s*\(",
            re.IGNORECASE,
        )
        new_regex = re.compile(
            r"\bnew\s+([A-Za-z_][A-Za-z0-9_$.<>]*)\s*\(",
        )

        for line_number in range(
            function.start_line_number, function.end_line_number + 1
        ):
            line_text = self.ts_analyzer.get_content_by_line_number(
                line_number, function.file_path
            )
            if line_text == "":
                continue
            code_part = line_text.split("//", 1)[0].strip()
            if code_part == "":
                continue

            matched = False
            for match in new_regex.finditer(code_part):
                raw_type = match.group(1)
                normalized_type = self._normalize_type(raw_type)
                if not self._is_resource_type(normalized_type):
                    continue
                matched = True
                sources.append(
                    Value(
                        code_part,
                        line_number,
                        ValueLabel.SRC,
                        function.file_path,
                    )
                )
                break

            if matched:
                continue

            if factory_regex.search(code_part) is None:
                continue

            # Keep factory fallback conservative: require dataflow-ish context.
            if (
                "=" not in code_part
                and not code_part.strip().startswith("return ")
                and not re.search(r"\w+\s*\(.*\.\s*[A-Za-z_][A-Za-z0-9_]*\s*\(", code_part)
            ):
                continue

            sources.append(
                Value(
                    code_part,
                    line_number,
                    ValueLabel.SRC,
                    function.file_path,
                )
            )

        return sources

    def _is_high_confidence_factory_method(self, method_name: str) -> bool:
        return method_name in self.HIGH_CONFIDENCE_FACTORY_METHOD_NAMES

    def _unwrap_parent_expr(self, node: Optional[Node]) -> Optional[Node]:
        current = node
        while current is not None and current.type in {
            "parenthesized_expression",
            "cast_expression",
            "type_cast_expression",
        }:
            current = current.parent
        return current

    def _is_factory_in_return_context(
        self, invocation_node: Node, function: Function, source_code: str
    ) -> bool:
        parent = self._unwrap_parent_expr(invocation_node.parent)
        if parent is None or parent.type != "return_statement":
            return False
        # Constructors do not have return type; for methods we prefer explicit
        # resource return type, but still keep high-confidence factories.
        method_name = self._get_invocation_name(invocation_node, source_code)
        return self._method_returns_resource_like(invocation_node, source_code) or (
            method_name in self.HIGH_CONFIDENCE_FACTORY_METHOD_NAMES
        )

    def _is_factory_in_argument_context(self, invocation_node: Node, source_code: str) -> bool:
        parent = self._unwrap_parent_expr(invocation_node.parent)
        if parent is None or parent.type != "argument_list":
            return False

        container = parent.parent
        if container is None:
            return False

        if container.type == "object_creation_expression":
            created_type = self._extract_creation_type_name(container, source_code)
            return self._is_resource_type(created_type)

        if container.type == "method_invocation":
            container_name = self._get_invocation_name(container, source_code)
            if container_name in self.ARG_CONTEXT_RESOURCE_CONSUMER_METHOD_NAMES:
                return True
        return False

    def _method_returns_resource_like(self, invocation_node: Node, source_code: str) -> bool:
        function_node = invocation_node
        while function_node is not None and function_node.type not in {
            "method_declaration",
            "constructor_declaration",
        }:
            function_node = function_node.parent

        if function_node is None:
            return False
        if function_node.type == "constructor_declaration":
            return False
        type_node = function_node.child_by_field_name("type")
        if type_node is None:
            return False
        return_type = self._normalize_type(source_code[type_node.start_byte : type_node.end_byte])
        return self._is_resource_type(return_type)

    def _lookup_field_type(
        self, invocation_node: Node, field_name: str, source_code: str
    ) -> str:
        # Root node does not carry path; use best-effort cache by source hash.
        file_cache: Dict[str, Dict[str, str]] = self.__dict__.setdefault(
            "_field_type_cache", {}
        )
        cache_key = str(hash(source_code))
        if cache_key not in file_cache:
            field_map: Dict[str, str] = {}
            pattern = re.compile(
                r"\b([A-Za-z_][A-Za-z0-9_$.<>\\[\\]]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;|,)"
            )
            for match in pattern.finditer(source_code):
                type_name = self._normalize_type(match.group(1))
                name = match.group(2)
                if name not in field_map:
                    field_map[name] = type_name
            file_cache[cache_key] = field_map
        return file_cache[cache_key].get(field_name, "")
