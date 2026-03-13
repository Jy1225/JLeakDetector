import re
from typing import Dict, List, Set

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
        "ReentrantLock",
        "ReadWriteLock",
        "ReentrantReadWriteLock",
        "Lock",
        "StampedLock",
        "Semaphore",
    }

    # In-memory wrappers are excluded from external-resource leak scope.
    RESOURCE_TYPE_EXCLUDELIST = {
        # "ByteArrayInputStream",
        # "ByteArrayOutputStream",
        # "CharArrayReader",
        # "CharArrayWriter",
        # "StringReader",
        # "StringWriter",
    }

    FACTORY_METHOD_NAMES = {
        "open",
        "openStream",
        "getInputStream",
        "getErrorStream",
        "getOutputStream",
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
        "openConnection",
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
    }

    TEMP_RESOURCE_FACTORY_METHOD_NAMES = {
        "createTempFile",
        "createTempDirectory",
    }

    CLOSE_METHOD_NAMES = {
        "close",
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
    }

    ACQUIRE_METHOD_NAMES = {
        "lock",
        "tryLock",
        "lockInterruptibly",
        "acquire",
        "acquireUninterruptibly",
    }

    def extract_sources(self, function: Function) -> List[Value]:
        sources: List[Value] = []
        sources.extend(self._extract_new_resource_sources(function))
        sources.extend(self._extract_factory_resource_sources(function))
        sources.extend(self._extract_acquire_sources(function))
        sources.extend(self._extract_twr_sources(function))
        return self._dedup_values(sources)

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
        allow_without_type = method_name in self.TEMP_RESOURCE_FACTORY_METHOD_NAMES

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
            return self._is_resource_type(local_type_map.get(left_name, ""))

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

        # Fallback: keep lock/semaphore acquisition patterns even without local type.
        lowered = invocation_text.lower()
        if ".lock(" in lowered or ".trylock(" in lowered or ".acquire(" in lowered:
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
