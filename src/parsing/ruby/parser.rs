//! Ruby parser implementation
//!
//! Uses tree-sitter-ruby for parsing Ruby source code, extracting classes, modules,
//! methods, constants, and tracking visibility, mixins, and metaprogramming.

use crate::parsing::parser::check_recursion_depth;
use crate::parsing::{
    HandledNode, Import, LanguageParser, MethodCall, NodeTracker, NodeTrackingState, ParserContext,
    ScopeType,
};
use crate::types::SymbolCounter;
use crate::{FileId, Range, Symbol, SymbolKind, Visibility};
use std::any::Any;
use tree_sitter::{Node, Parser, Tree};

/// Ruby visibility state
#[derive(Debug, Clone, Copy, PartialEq)]
enum RubyVisibility {
    Public,
    Private,
    Protected,
}

/// Ruby language parser
pub struct RubyParser {
    parser: Parser,
    context: ParserContext,
    node_tracker: NodeTrackingState,
    /// Stack of (class/module name, visibility) for nested definitions
    class_stack: Vec<(String, RubyVisibility)>,
}

fn range_from_node(node: &Node) -> Range {
    let start = node.start_position();
    let end = node.end_position();
    Range::new(
        start.row as u32,
        start.column as u16,
        end.row as u32,
        end.column as u16,
    )
}

impl RubyParser {
    /// Create a new Ruby parser
    pub fn new() -> Result<Self, String> {
        let mut parser = Parser::new();
        let lang = tree_sitter_ruby::LANGUAGE;
        parser
            .set_language(&lang.into())
            .map_err(|e| format!("Failed to set Ruby language: {e}"))?;

        Ok(Self {
            parser,
            context: ParserContext::new(),
            node_tracker: NodeTrackingState::new(),
            class_stack: Vec::new(),
        })
    }

    /// Get the current module path from the class stack
    fn current_module_path(&self) -> String {
        self.class_stack
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join("::")
    }

    /// Get the current visibility state
    fn current_visibility(&self) -> RubyVisibility {
        self.class_stack
            .last()
            .map(|(_, vis)| *vis)
            .unwrap_or(RubyVisibility::Public)
    }

    /// Build the full module path for a symbol
    fn build_module_path(&self, base_module_path: &str) -> String {
        let stack_path = self.current_module_path();
        if base_module_path.is_empty() && stack_path.is_empty() {
            String::new()
        } else if base_module_path.is_empty() {
            stack_path
        } else if stack_path.is_empty() {
            base_module_path.to_string()
        } else {
            format!("{base_module_path}::{stack_path}")
        }
    }

    fn create_symbol(
        &self,
        id: crate::types::SymbolId,
        name: String,
        kind: SymbolKind,
        file_id: FileId,
        range: Range,
        signature: Option<String>,
        doc_comment: Option<String>,
        module_path: &str,
        visibility: Visibility,
    ) -> Symbol {
        let mut symbol = Symbol::new(id, name, kind, file_id, range);

        if let Some(sig) = signature {
            symbol = symbol.with_signature(sig);
        }
        if let Some(doc) = doc_comment {
            symbol = symbol.with_doc(doc);
        }
        if !module_path.is_empty() {
            symbol = symbol.with_module_path(module_path);
        }
        symbol = symbol.with_visibility(visibility);
        symbol.scope_context = Some(self.context.current_scope_context());

        symbol
    }

    /// Parse Ruby source code and extract all symbols
    pub fn parse_code(
        &mut self,
        code: &str,
        file_id: FileId,
        symbol_counter: &mut SymbolCounter,
    ) -> Vec<Symbol> {
        self.context = ParserContext::new();
        self.class_stack.clear();
        let mut symbols = Vec::new();

        if let Some(tree) = self.parser.parse(code, None) {
            let root_node = tree.root_node();
            self.extract_symbols_from_node(
                root_node,
                code,
                file_id,
                symbol_counter,
                &mut symbols,
                "",
                0,
            );
        }

        symbols
    }

    fn extract_symbols_from_node(
        &mut self,
        node: Node,
        code: &str,
        file_id: FileId,
        counter: &mut SymbolCounter,
        symbols: &mut Vec<Symbol>,
        module_path: &str,
        depth: usize,
    ) {
        if !check_recursion_depth(depth, node) {
            return;
        }

        match node.kind() {
            "program" => {
                self.register_handled_node("program", node.kind_id());
                for child in node.children(&mut node.walk()) {
                    self.extract_symbols_from_node(
                        child,
                        code,
                        file_id,
                        counter,
                        symbols,
                        module_path,
                        depth + 1,
                    );
                }
            }
            "class" => {
                self.register_node_recursively(node);
                self.process_class(node, code, file_id, counter, symbols, module_path, depth);
            }
            "module" => {
                self.register_node_recursively(node);
                self.process_module(node, code, file_id, counter, symbols, module_path, depth);
            }
            "method" => {
                self.register_node_recursively(node);
                self.process_method(node, code, file_id, counter, symbols, module_path);
            }
            "singleton_method" => {
                self.register_node_recursively(node);
                self.process_singleton_method(node, code, file_id, counter, symbols, module_path);
            }
            "assignment" => {
                self.register_handled_node("assignment", node.kind_id());
                self.process_assignment(node, code, file_id, counter, symbols, module_path);
            }
            "call" => {
                self.register_handled_node("call", node.kind_id());
                self.process_call_node(node, code, file_id, counter, symbols, module_path, depth);
            }
            "scope_resolution" => {
                self.register_handled_node("scope_resolution", node.kind_id());
            }
            "if" | "unless" | "while" | "until" | "for" | "case" => {
                self.register_handled_node(node.kind(), node.kind_id());
                self.context.enter_scope(ScopeType::Block);
                for child in node.children(&mut node.walk()) {
                    self.extract_symbols_from_node(
                        child,
                        code,
                        file_id,
                        counter,
                        symbols,
                        module_path,
                        depth + 1,
                    );
                }
                self.context.exit_scope();
            }
            "begin" | "do_block" | "block" => {
                self.register_handled_node(node.kind(), node.kind_id());
                self.context.enter_scope(ScopeType::Block);
                for child in node.children(&mut node.walk()) {
                    self.extract_symbols_from_node(
                        child,
                        code,
                        file_id,
                        counter,
                        symbols,
                        module_path,
                        depth + 1,
                    );
                }
                self.context.exit_scope();
            }
            "lambda" => {
                self.register_handled_node("lambda", node.kind_id());
            }
            "comment" => {
                self.register_handled_node("comment", node.kind_id());
            }
            "body_statement" => {
                self.register_handled_node("body_statement", node.kind_id());
                for child in node.children(&mut node.walk()) {
                    // Bare visibility modifiers appear as plain identifier nodes
                    if child.kind() == "identifier" {
                        let text = &code[child.byte_range()];
                        match text {
                            "private" | "protected" | "public" => {
                                self.process_visibility_modifier_bare(text);
                                self.register_handled_node("identifier", child.kind_id());
                                continue;
                            }
                            _ => {}
                        }
                    }
                    self.extract_symbols_from_node(
                        child,
                        code,
                        file_id,
                        counter,
                        symbols,
                        module_path,
                        depth + 1,
                    );
                }
            }
            _ => {
                for child in node.children(&mut node.walk()) {
                    self.extract_symbols_from_node(
                        child,
                        code,
                        file_id,
                        counter,
                        symbols,
                        module_path,
                        depth + 1,
                    );
                }
            }
        }
    }

    fn process_class(
        &mut self,
        node: Node,
        code: &str,
        file_id: FileId,
        counter: &mut SymbolCounter,
        symbols: &mut Vec<Symbol>,
        module_path: &str,
        depth: usize,
    ) {
        let name = self.extract_class_name(node, code);
        if name.is_empty() {
            return;
        }

        let full_module_path = self.build_module_path(module_path);
        let range = range_from_node(&node);
        let doc_comment = self.extract_ruby_doc_comment(&node, code);

        // Build signature
        let mut signature = format!("class {name}");
        if let Some(superclass) = self.extract_superclass(node, code) {
            signature = format!("class {name} < {superclass}");
        }

        let symbol = self.create_symbol(
            counter.next_id(),
            name.clone(),
            SymbolKind::Class,
            file_id,
            range,
            Some(signature),
            doc_comment,
            &full_module_path,
            Visibility::Public,
        );
        symbols.push(symbol);

        // Enter class scope
        self.class_stack.push((name, RubyVisibility::Public));
        self.context.enter_scope(ScopeType::hoisting_function());

        // Process class body
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_symbols_from_node(
                body,
                code,
                file_id,
                counter,
                symbols,
                module_path,
                depth + 1,
            );
        }

        self.context.exit_scope();
        self.class_stack.pop();
    }

    fn process_module(
        &mut self,
        node: Node,
        code: &str,
        file_id: FileId,
        counter: &mut SymbolCounter,
        symbols: &mut Vec<Symbol>,
        module_path: &str,
        depth: usize,
    ) {
        let name = self.extract_module_name(node, code);
        if name.is_empty() {
            return;
        }

        let full_module_path = self.build_module_path(module_path);
        let range = range_from_node(&node);
        let doc_comment = self.extract_ruby_doc_comment(&node, code);

        let symbol = self.create_symbol(
            counter.next_id(),
            name.clone(),
            SymbolKind::Module,
            file_id,
            range,
            Some(format!("module {name}")),
            doc_comment,
            &full_module_path,
            Visibility::Public,
        );
        symbols.push(symbol);

        // Enter module scope
        self.class_stack.push((name, RubyVisibility::Public));
        self.context.enter_scope(ScopeType::hoisting_function());

        // Process module body
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_symbols_from_node(
                body,
                code,
                file_id,
                counter,
                symbols,
                module_path,
                depth + 1,
            );
        }

        self.context.exit_scope();
        self.class_stack.pop();
    }

    fn process_method(
        &mut self,
        node: Node,
        code: &str,
        file_id: FileId,
        counter: &mut SymbolCounter,
        symbols: &mut Vec<Symbol>,
        module_path: &str,
    ) {
        let name_node = match node.child_by_field_name("name") {
            Some(n) => n,
            None => return,
        };
        let name = code[name_node.byte_range()].to_string();
        let full_module_path = self.build_module_path(module_path);
        let range = range_from_node(&node);
        let doc_comment = self.extract_ruby_doc_comment(&node, code);

        let visibility = match self.current_visibility() {
            RubyVisibility::Public => Visibility::Public,
            RubyVisibility::Private => Visibility::Private,
            RubyVisibility::Protected => Visibility::Module,
        };

        let signature = self.extract_method_signature(node, code);

        let symbol = self.create_symbol(
            counter.next_id(),
            name,
            SymbolKind::Method,
            file_id,
            range,
            Some(signature),
            doc_comment,
            &full_module_path,
            visibility,
        );
        symbols.push(symbol);
    }

    fn process_singleton_method(
        &mut self,
        node: Node,
        code: &str,
        file_id: FileId,
        counter: &mut SymbolCounter,
        symbols: &mut Vec<Symbol>,
        module_path: &str,
    ) {
        let name_node = match node.child_by_field_name("name") {
            Some(n) => n,
            None => return,
        };
        let name = code[name_node.byte_range()].to_string();
        let full_module_path = self.build_module_path(module_path);
        let range = range_from_node(&node);
        let doc_comment = self.extract_ruby_doc_comment(&node, code);

        let signature = format!("def self.{}{}", name, self.extract_params_text(node, code));

        let symbol = self.create_symbol(
            counter.next_id(),
            name,
            SymbolKind::Function,
            file_id,
            range,
            Some(signature),
            doc_comment,
            &full_module_path,
            Visibility::Public,
        );
        symbols.push(symbol);
    }

    fn process_assignment(
        &mut self,
        node: Node,
        code: &str,
        file_id: FileId,
        counter: &mut SymbolCounter,
        symbols: &mut Vec<Symbol>,
        module_path: &str,
    ) {
        let left = match node.child_by_field_name("left") {
            Some(n) => n,
            None => return,
        };

        let name_text = code[left.byte_range()].to_string();
        let full_module_path = self.build_module_path(module_path);
        let range = range_from_node(&node);

        // Constant assignment (UPPER_CASE or CamelCase starting with uppercase)
        if left.kind() == "constant" || name_text.chars().next().is_some_and(|c| c.is_uppercase()) {
            let symbol = self.create_symbol(
                counter.next_id(),
                name_text,
                SymbolKind::Constant,
                file_id,
                range,
                None,
                None,
                &full_module_path,
                Visibility::Public,
            );
            symbols.push(symbol);
        }
    }

    fn process_call_node(
        &mut self,
        node: Node,
        code: &str,
        file_id: FileId,
        counter: &mut SymbolCounter,
        symbols: &mut Vec<Symbol>,
        module_path: &str,
        depth: usize,
    ) {
        let method_name = match node.child_by_field_name("method") {
            Some(n) => code[n.byte_range()].to_string(),
            None => return,
        };

        match method_name.as_str() {
            "attr_accessor" | "attr_reader" | "attr_writer" => {
                self.process_attr_metaprogramming(
                    node,
                    code,
                    file_id,
                    counter,
                    symbols,
                    module_path,
                    &method_name,
                );
            }
            "private" | "protected" | "public" => {
                self.process_visibility_modifier(node, code, &method_name);
            }
            "include" | "extend" | "prepend" => {
                // Tracked via find_implementations
            }
            _ => {}
        }

        // Still process children for nested definitions
        if let Some(args) = node.child_by_field_name("arguments") {
            for child in args.children(&mut args.walk()) {
                self.extract_symbols_from_node(
                    child,
                    code,
                    file_id,
                    counter,
                    symbols,
                    module_path,
                    depth + 1,
                );
            }
        }
    }

    fn process_attr_metaprogramming(
        &mut self,
        node: Node,
        code: &str,
        file_id: FileId,
        counter: &mut SymbolCounter,
        symbols: &mut Vec<Symbol>,
        module_path: &str,
        attr_type: &str,
    ) {
        let full_module_path = self.build_module_path(module_path);
        let visibility = match self.current_visibility() {
            RubyVisibility::Public => Visibility::Public,
            RubyVisibility::Private => Visibility::Private,
            RubyVisibility::Protected => Visibility::Module,
        };

        let args = match node.child_by_field_name("arguments") {
            Some(n) => n,
            None => return,
        };

        for child in args.children(&mut args.walk()) {
            let attr_name = match child.kind() {
                "simple_symbol" => {
                    let text = code[child.byte_range()].to_string();
                    text.trim_start_matches(':').to_string()
                }
                "string" | "bare_string" => {
                    let text = code[child.byte_range()].to_string();
                    text.trim_matches(|c| c == '"' || c == '\'').to_string()
                }
                _ => continue,
            };

            if attr_name.is_empty() {
                continue;
            }

            let range = range_from_node(&child);

            // Generate reader method
            if attr_type == "attr_accessor" || attr_type == "attr_reader" {
                let symbol = self.create_symbol(
                    counter.next_id(),
                    attr_name.clone(),
                    SymbolKind::Method,
                    file_id,
                    range,
                    Some(format!("{attr_type} :{attr_name}")),
                    None,
                    &full_module_path,
                    visibility,
                );
                symbols.push(symbol);
            }

            // Generate writer method
            if attr_type == "attr_accessor" || attr_type == "attr_writer" {
                let writer_name = format!("{attr_name}=");
                let symbol = self.create_symbol(
                    counter.next_id(),
                    writer_name,
                    SymbolKind::Method,
                    file_id,
                    range,
                    Some(format!("{attr_type} :{attr_name}")),
                    None,
                    &full_module_path,
                    visibility,
                );
                symbols.push(symbol);
            }
        }
    }

    fn process_visibility_modifier_bare(&mut self, modifier: &str) {
        let new_visibility = match modifier {
            "private" => RubyVisibility::Private,
            "protected" => RubyVisibility::Protected,
            "public" => RubyVisibility::Public,
            _ => return,
        };
        if let Some(last) = self.class_stack.last_mut() {
            last.1 = new_visibility;
        }
    }

    fn process_visibility_modifier(&mut self, node: Node, code: &str, modifier: &str) {
        let new_visibility = match modifier {
            "private" => RubyVisibility::Private,
            "protected" => RubyVisibility::Protected,
            "public" => RubyVisibility::Public,
            _ => return,
        };

        // Check if this is a bare visibility modifier (no arguments) or with method argument
        let has_args = node
            .child_by_field_name("arguments")
            .map(|args| {
                let text = code[args.byte_range()].trim().to_string();
                !text.is_empty() && text != "()" && text != "(" && text != ")"
            })
            .unwrap_or(false);

        if !has_args {
            // Bare modifier: changes default visibility for subsequent methods
            if let Some(last) = self.class_stack.last_mut() {
                last.1 = new_visibility;
            }
        }
        // If it has arguments like `private :method_name`, it's a per-method modifier.
        // We don't retroactively change visibility here for simplicity.
    }

    fn extract_class_name(&self, node: Node, code: &str) -> String {
        if let Some(name_node) = node.child_by_field_name("name") {
            return code[name_node.byte_range()].to_string();
        }
        String::new()
    }

    fn extract_module_name(&self, node: Node, code: &str) -> String {
        if let Some(name_node) = node.child_by_field_name("name") {
            return code[name_node.byte_range()].to_string();
        }
        String::new()
    }

    fn extract_superclass(&self, node: Node, code: &str) -> Option<String> {
        if let Some(superclass_node) = node.child_by_field_name("superclass") {
            // The superclass field is a wrapper node containing "< ClassName"
            // We need to find the constant or scope_resolution child inside it
            for child in superclass_node.children(&mut superclass_node.walk()) {
                if matches!(child.kind(), "constant" | "scope_resolution") {
                    return Some(code[child.byte_range()].to_string());
                }
            }
            // Fallback: trim the "< " prefix
            let text = code[superclass_node.byte_range()].trim().to_string();
            let text = text.strip_prefix('<').unwrap_or(&text).trim().to_string();
            if !text.is_empty() {
                return Some(text);
            }
        }
        None
    }

    fn extract_method_signature(&self, node: Node, code: &str) -> String {
        let name = node
            .child_by_field_name("name")
            .map(|n| &code[n.byte_range()])
            .unwrap_or("unknown");

        let params = self.extract_params_text(node, code);
        format!("def {name}{params}")
    }

    fn extract_params_text(&self, node: Node, code: &str) -> String {
        if let Some(params_node) = node.child_by_field_name("parameters") {
            code[params_node.byte_range()].to_string()
        } else {
            String::new()
        }
    }

    fn extract_ruby_doc_comment(&self, node: &Node, code: &str) -> Option<String> {
        let mut doc_lines = Vec::new();
        let mut current = node.prev_sibling();

        while let Some(sibling) = current {
            if sibling.kind() == "comment" {
                let comment_text = &code[sibling.byte_range()];
                // Ruby comments start with #
                if let Some(content) = comment_text.strip_prefix('#') {
                    let content = content.trim_start_matches(' ');
                    doc_lines.insert(0, content.to_string());
                    current = sibling.prev_sibling();
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        if !doc_lines.is_empty() {
            let filtered: Vec<String> = doc_lines.into_iter().filter(|l| !l.is_empty()).collect();
            if !filtered.is_empty() {
                return Some(filtered.join("\n"));
            }
        }

        None
    }

    fn register_node_recursively(&mut self, node: Node) {
        let mut stack = vec![(node, 0)];
        const MAX_DEPTH: usize = 1000;

        while let Some((current_node, depth)) = stack.pop() {
            if depth > MAX_DEPTH {
                continue;
            }

            self.node_tracker
                .register_handled_node(current_node.kind(), current_node.kind_id());

            for child in current_node.children(&mut current_node.walk()) {
                stack.push((child, depth + 1));
            }
        }
    }

    fn extract_method_calls_from_tree(&self, tree: &Tree, code: &str) -> Vec<MethodCall> {
        let mut calls = Vec::new();
        let mut stack = vec![tree.root_node()];

        while let Some(node) = stack.pop() {
            if node.kind() == "call" {
                if let Some(method_node) = node.child_by_field_name("method") {
                    let method_name = code[method_node.byte_range()].to_string();
                    let range = range_from_node(&node);

                    let receiver = node
                        .child_by_field_name("receiver")
                        .map(|n| code[n.byte_range()].to_string());

                    let is_static = receiver.as_ref().is_some_and(|r| {
                        r == "self" || r.chars().next().is_some_and(|c| c.is_uppercase())
                    });

                    calls.push(MethodCall {
                        caller: String::new(),
                        method_name,
                        receiver,
                        is_static,
                        range,
                        caller_range: Some(range),
                    });
                }
            }

            for child in node.children(&mut node.walk()) {
                stack.push(child);
            }
        }

        calls
    }

    fn find_calls_in_node<'a>(
        &mut self,
        node: Node,
        code: &'a str,
        calls: &mut Vec<(&'a str, &'a str, Range)>,
        current_function: &mut Option<&'a str>,
    ) {
        match node.kind() {
            "method" | "singleton_method" => {
                self.register_handled_node(node.kind(), node.kind_id());
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name_text = &code[name_node.byte_range()];
                    let old_function = *current_function;
                    *current_function = Some(name_text);
                    for child in node.children(&mut node.walk()) {
                        self.find_calls_in_node(child, code, calls, current_function);
                    }
                    *current_function = old_function;
                }
            }
            "call" => {
                self.register_handled_node("call", node.kind_id());
                if let Some(method_node) = node.child_by_field_name("method") {
                    let callee = &code[method_node.byte_range()];
                    let range = range_from_node(&node);
                    let caller = (*current_function).unwrap_or("<module>");
                    calls.push((caller, callee, range));
                }
                for child in node.children(&mut node.walk()) {
                    self.find_calls_in_node(child, code, calls, current_function);
                }
            }
            _ => {
                for child in node.children(&mut node.walk()) {
                    self.find_calls_in_node(child, code, calls, current_function);
                }
            }
        }
    }
}

impl NodeTracker for RubyParser {
    fn get_handled_nodes(&self) -> &std::collections::HashSet<HandledNode> {
        self.node_tracker.get_handled_nodes()
    }

    fn register_handled_node(&mut self, node_kind: &str, node_id: u16) {
        self.node_tracker.register_handled_node(node_kind, node_id);
    }
}

impl LanguageParser for RubyParser {
    fn parse(
        &mut self,
        code: &str,
        file_id: FileId,
        symbol_counter: &mut SymbolCounter,
    ) -> Vec<Symbol> {
        self.parse_code(code, file_id, symbol_counter)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn extract_doc_comment(&self, node: &Node, code: &str) -> Option<String> {
        self.extract_ruby_doc_comment(node, code)
    }

    fn find_calls<'a>(&mut self, code: &'a str) -> Vec<(&'a str, &'a str, Range)> {
        let tree = match self.parser.parse(code, None) {
            Some(tree) => tree,
            None => return Vec::new(),
        };

        let mut calls = Vec::new();
        let root_node = tree.root_node();
        let mut current_function: Option<&'a str> = None;

        self.find_calls_in_node(root_node, code, &mut calls, &mut current_function);
        calls
    }

    fn find_method_calls(&mut self, code: &str) -> Vec<MethodCall> {
        let tree = match self.parser.parse(code, None) {
            Some(tree) => tree,
            None => return Vec::new(),
        };

        self.extract_method_calls_from_tree(&tree, code)
    }

    fn find_implementations<'a>(&mut self, code: &'a str) -> Vec<(&'a str, &'a str, Range)> {
        let tree = match self.parser.parse(code, None) {
            Some(tree) => tree,
            None => return Vec::new(),
        };

        let mut results = Vec::new();
        let mut stack: Vec<(Node, Option<&'a str>)> = vec![(tree.root_node(), None)];

        while let Some((node, current_class)) = stack.pop() {
            match node.kind() {
                "class" | "module" => {
                    let name = node
                        .child_by_field_name("name")
                        .map(|n| &code[n.byte_range()]);

                    if let Some(body) = node.child_by_field_name("body") {
                        for child in body.children(&mut body.walk()) {
                            stack.push((child, name));
                        }
                    }
                }
                "call" => {
                    if let (Some(class_name), Some(method_node)) =
                        (current_class, node.child_by_field_name("method"))
                    {
                        let method_name = &code[method_node.byte_range()];
                        if matches!(method_name, "include" | "extend" | "prepend") {
                            if let Some(args) = node.child_by_field_name("arguments") {
                                for arg in args.children(&mut args.walk()) {
                                    if matches!(arg.kind(), "constant" | "scope_resolution") {
                                        let mixin_name = &code[arg.byte_range()];
                                        let range = range_from_node(&node);
                                        results.push((class_name, mixin_name, range));
                                    }
                                }
                            }
                        }
                    }
                    for child in node.children(&mut node.walk()) {
                        stack.push((child, current_class));
                    }
                }
                _ => {
                    for child in node.children(&mut node.walk()) {
                        stack.push((child, current_class));
                    }
                }
            }
        }

        results
    }

    fn find_extends<'a>(&mut self, code: &'a str) -> Vec<(&'a str, &'a str, Range)> {
        let tree = match self.parser.parse(code, None) {
            Some(tree) => tree,
            None => return Vec::new(),
        };

        let mut results = Vec::new();
        let mut stack = vec![tree.root_node()];

        while let Some(node) = stack.pop() {
            if node.kind() == "class" {
                if let (Some(name_node), Some(superclass_node)) = (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("superclass"),
                ) {
                    let name = &code[name_node.byte_range()];
                    // superclass is a wrapper node containing "< ClassName"
                    // Find the constant or scope_resolution child inside
                    let mut superclass_str = None;
                    for child in superclass_node.children(&mut superclass_node.walk()) {
                        if matches!(child.kind(), "constant" | "scope_resolution") {
                            superclass_str = Some(&code[child.byte_range()]);
                            break;
                        }
                    }
                    if let Some(superclass) = superclass_str {
                        let range = range_from_node(&node);
                        results.push((name, superclass, range));
                    }
                }
            }

            for child in node.children(&mut node.walk()) {
                stack.push(child);
            }
        }

        results
    }

    fn find_uses<'a>(&mut self, code: &'a str) -> Vec<(&'a str, &'a str, Range)> {
        let tree = match self.parser.parse(code, None) {
            Some(tree) => tree,
            None => return Vec::new(),
        };

        let mut results = Vec::new();
        let mut stack: Vec<(Node, Option<&'a str>)> = vec![(tree.root_node(), None)];

        while let Some((node, context)) = stack.pop() {
            match node.kind() {
                "class" | "module" | "method" | "singleton_method" => {
                    let name = node
                        .child_by_field_name("name")
                        .map(|n| &code[n.byte_range()]);
                    let ctx = name.or(context);
                    for child in node.children(&mut node.walk()) {
                        stack.push((child, ctx));
                    }
                }
                "constant" | "scope_resolution" => {
                    if let Some(ctx) = context {
                        let const_name = &code[node.byte_range()];
                        let range = range_from_node(&node);
                        results.push((ctx, const_name, range));
                    }
                }
                _ => {
                    for child in node.children(&mut node.walk()) {
                        stack.push((child, context));
                    }
                }
            }
        }

        results
    }

    fn find_defines<'a>(&mut self, _code: &'a str) -> Vec<(&'a str, &'a str, Range)> {
        Vec::new()
    }

    fn find_imports(&mut self, code: &str, file_id: FileId) -> Vec<Import> {
        let tree = match self.parser.parse(code, None) {
            Some(tree) => tree,
            None => return Vec::new(),
        };

        let mut imports = Vec::new();
        let mut stack = vec![tree.root_node()];

        while let Some(node) = stack.pop() {
            if node.kind() == "call" {
                if let Some(method_node) = node.child_by_field_name("method") {
                    let method_name = &code[method_node.byte_range()];

                    if method_name == "require" || method_name == "require_relative" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            for arg in args.children(&mut args.walk()) {
                                if arg.kind() == "string" || arg.kind() == "string_content" {
                                    let full_text = code[arg.byte_range()].to_string();
                                    let path = full_text
                                        .trim_matches(|c| c == '"' || c == '\'')
                                        .to_string();
                                    if !path.is_empty() {
                                        imports.push(Import {
                                            path,
                                            alias: None,
                                            file_id,
                                            is_glob: false,
                                            is_type_only: false,
                                        });
                                    }
                                } else if arg.kind() == "argument_list" {
                                    for inner_arg in arg.children(&mut arg.walk()) {
                                        if inner_arg.kind() == "string" {
                                            let full_text =
                                                code[inner_arg.byte_range()].to_string();
                                            let path = full_text
                                                .trim_matches(|c| c == '"' || c == '\'')
                                                .to_string();
                                            if !path.is_empty() {
                                                imports.push(Import {
                                                    path,
                                                    alias: None,
                                                    file_id,
                                                    is_glob: false,
                                                    is_type_only: false,
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            for child in node.children(&mut node.walk()) {
                stack.push(child);
            }
        }

        imports
    }

    fn language(&self) -> crate::parsing::Language {
        crate::parsing::Language::Ruby
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_class() {
        let mut parser = RubyParser::new().unwrap();
        let code = r#"
class User
  def initialize(name)
    @name = name
  end

  def greet
    "Hello, #{@name}"
  end
end
"#;

        let file_id = FileId::new(1).unwrap();
        let mut counter = SymbolCounter::new();
        let symbols = parser.parse_code(code, file_id, &mut counter);

        let class = symbols.iter().find(|s| s.name.as_ref() == "User");
        assert!(class.is_some());
        assert_eq!(class.unwrap().kind, SymbolKind::Class);

        let init = symbols.iter().find(|s| s.name.as_ref() == "initialize");
        assert!(init.is_some());
        assert_eq!(init.unwrap().kind, SymbolKind::Method);

        let greet = symbols.iter().find(|s| s.name.as_ref() == "greet");
        assert!(greet.is_some());
    }

    #[test]
    fn test_parse_module() {
        let mut parser = RubyParser::new().unwrap();
        let code = r#"
module Serializable
  def to_json
    # serialize
  end
end
"#;

        let file_id = FileId::new(1).unwrap();
        let mut counter = SymbolCounter::new();
        let symbols = parser.parse_code(code, file_id, &mut counter);

        let module = symbols.iter().find(|s| s.name.as_ref() == "Serializable");
        assert!(module.is_some());
        assert_eq!(module.unwrap().kind, SymbolKind::Module);
    }

    #[test]
    fn test_parse_singleton_method() {
        let mut parser = RubyParser::new().unwrap();
        let code = r#"
class Config
  def self.load(path)
    new(path)
  end
end
"#;

        let file_id = FileId::new(1).unwrap();
        let mut counter = SymbolCounter::new();
        let symbols = parser.parse_code(code, file_id, &mut counter);

        let load = symbols.iter().find(|s| s.name.as_ref() == "load");
        assert!(load.is_some());
        assert_eq!(load.unwrap().kind, SymbolKind::Function);
    }

    #[test]
    fn test_parse_attr_accessor() {
        let mut parser = RubyParser::new().unwrap();
        let code = r#"
class Person
  attr_accessor :name, :age
  attr_reader :id
end
"#;

        let file_id = FileId::new(1).unwrap();
        let mut counter = SymbolCounter::new();
        let symbols = parser.parse_code(code, file_id, &mut counter);

        // attr_accessor generates reader + writer
        let name_reader = symbols.iter().find(|s| s.name.as_ref() == "name");
        assert!(name_reader.is_some());
        let name_writer = symbols.iter().find(|s| s.name.as_ref() == "name=");
        assert!(name_writer.is_some());

        let age_reader = symbols.iter().find(|s| s.name.as_ref() == "age");
        assert!(age_reader.is_some());

        // attr_reader generates only reader
        let id_reader = symbols.iter().find(|s| s.name.as_ref() == "id");
        assert!(id_reader.is_some());
        let id_writer = symbols.iter().find(|s| s.name.as_ref() == "id=");
        assert!(id_writer.is_none());
    }

    #[test]
    fn test_parse_visibility() {
        let mut parser = RubyParser::new().unwrap();
        let code = r#"
class Service
  def public_method
  end

  private

  def private_method
  end

  protected

  def protected_method
  end
end
"#;

        let file_id = FileId::new(1).unwrap();
        let mut counter = SymbolCounter::new();
        let symbols = parser.parse_code(code, file_id, &mut counter);

        let public_m = symbols.iter().find(|s| s.name.as_ref() == "public_method");
        assert_eq!(public_m.unwrap().visibility, Visibility::Public);

        let private_m = symbols.iter().find(|s| s.name.as_ref() == "private_method");
        assert_eq!(private_m.unwrap().visibility, Visibility::Private);

        let protected_m = symbols
            .iter()
            .find(|s| s.name.as_ref() == "protected_method");
        // Ruby protected maps to Visibility::Module (closest semantic equivalent)
        assert_eq!(protected_m.unwrap().visibility, Visibility::Module);
    }

    #[test]
    fn test_parse_nested_modules() {
        let mut parser = RubyParser::new().unwrap();
        let code = r#"
module Curriculum
  module Operations
    class CreateCourseTask
      def call
      end
    end
  end
end
"#;

        let file_id = FileId::new(1).unwrap();
        let mut counter = SymbolCounter::new();
        let symbols = parser.parse_code(code, file_id, &mut counter);

        let task = symbols
            .iter()
            .find(|s| s.name.as_ref() == "CreateCourseTask");
        assert!(task.is_some());
        let task = task.unwrap();
        assert_eq!(task.kind, SymbolKind::Class);
        assert_eq!(task.module_path.as_deref(), Some("Curriculum::Operations"));
    }

    #[test]
    fn test_find_imports() {
        use crate::parsing::LanguageParser;

        let mut parser = RubyParser::new().unwrap();
        let code = r#"
require "json"
require_relative "lib/helpers"
"#;

        let file_id = FileId::new(1).unwrap();
        let imports = parser.find_imports(code, file_id);

        assert!(imports.iter().any(|i| i.path == "json"));
        assert!(imports.iter().any(|i| i.path == "lib/helpers"));
    }

    #[test]
    fn test_find_extends() {
        use crate::parsing::LanguageParser;

        let mut parser = RubyParser::new().unwrap();
        let code = r#"
class Dog < Animal
  def bark
  end
end
"#;

        let extends = parser.find_extends(code);
        assert_eq!(extends.len(), 1);
        assert_eq!(extends[0].0, "Dog");
        assert_eq!(extends[0].1, "Animal");
    }

    #[test]
    fn test_find_implementations_mixin() {
        use crate::parsing::LanguageParser;

        let mut parser = RubyParser::new().unwrap();
        let code = r#"
class User
  include Comparable
  extend ClassMethods
end
"#;

        let impls = parser.find_implementations(code);
        assert!(
            impls
                .iter()
                .any(|(cls, mixin, _)| *cls == "User" && *mixin == "Comparable")
        );
        assert!(
            impls
                .iter()
                .any(|(cls, mixin, _)| *cls == "User" && *mixin == "ClassMethods")
        );
    }

    #[test]
    fn test_find_calls() {
        use crate::parsing::LanguageParser;

        let mut parser = RubyParser::new().unwrap();
        let code = r#"
class Calculator
  def add(a, b)
    validate(a, b)
    a + b
  end

  def validate(a, b)
    raise "Invalid" unless a.is_a?(Numeric)
  end
end
"#;

        let calls = parser.find_calls(code);
        let add_calls: Vec<_> = calls.iter().filter(|(c, _, _)| *c == "add").collect();
        assert!(add_calls.iter().any(|(_, callee, _)| *callee == "validate"));
    }

    #[test]
    fn test_doc_comment_extraction() {
        let mut parser = RubyParser::new().unwrap();
        let code = r#"
# This is a documented class
# with multiple lines
class Documented
end
"#;

        let file_id = FileId::new(1).unwrap();
        let mut counter = SymbolCounter::new();
        let symbols = parser.parse_code(code, file_id, &mut counter);

        let class = symbols.iter().find(|s| s.name.as_ref() == "Documented");
        assert!(class.is_some());
        let doc = class.unwrap().doc_comment.as_ref();
        assert!(doc.is_some());
        assert!(doc.unwrap().contains("documented class"));
    }

    #[test]
    fn test_constant_extraction() {
        let mut parser = RubyParser::new().unwrap();
        let code = r#"
class Config
  VERSION = "1.0.0"
  MAX_RETRIES = 3
end
"#;

        let file_id = FileId::new(1).unwrap();
        let mut counter = SymbolCounter::new();
        let symbols = parser.parse_code(code, file_id, &mut counter);

        let version = symbols.iter().find(|s| s.name.as_ref() == "VERSION");
        assert!(version.is_some());
        assert_eq!(version.unwrap().kind, SymbolKind::Constant);
    }
}
