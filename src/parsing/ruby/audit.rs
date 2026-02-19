//! Ruby parser audit module
//!
//! Tracks which AST nodes the parser handles vs what's available in the grammar.

use super::RubyParser;
use crate::io::format::format_utc_timestamp;
use crate::parsing::NodeTracker;
use crate::types::FileId;
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use tree_sitter::{Node, Parser};

#[derive(Error, Debug)]
pub enum AuditError {
    #[error("Failed to read file: {0}")]
    FileRead(#[from] std::io::Error),

    #[error("Failed to set language: {0}")]
    LanguageSetup(String),

    #[error("Failed to parse code")]
    ParseFailure,

    #[error("Failed to create parser: {0}")]
    ParserCreation(String),
}

pub struct RubyParserAudit {
    pub grammar_nodes: HashMap<String, u16>,
    pub implemented_nodes: HashSet<String>,
    pub extracted_symbol_kinds: HashSet<String>,
}

impl RubyParserAudit {
    pub fn audit_file(file_path: &str) -> Result<Self, AuditError> {
        let code = std::fs::read_to_string(file_path)?;
        Self::audit_code(&code)
    }

    pub fn audit_code(code: &str) -> Result<Self, AuditError> {
        let mut parser = Parser::new();
        let language = tree_sitter_ruby::LANGUAGE.into();
        parser
            .set_language(&language)
            .map_err(|e| AuditError::LanguageSetup(e.to_string()))?;

        let tree = parser.parse(code, None).ok_or(AuditError::ParseFailure)?;

        let mut grammar_nodes = HashMap::new();
        discover_nodes(tree.root_node(), &mut grammar_nodes);

        let mut ruby_parser =
            RubyParser::new().map_err(|e| AuditError::ParserCreation(e.to_string()))?;
        let file_id = FileId(1);
        let mut symbol_counter = crate::types::SymbolCounter::new();
        let symbols = ruby_parser.parse_code(code, file_id, &mut symbol_counter);

        let mut extracted_symbol_kinds = HashSet::new();
        for symbol in &symbols {
            extracted_symbol_kinds.insert(format!("{:?}", symbol.kind));
        }

        let implemented_nodes: HashSet<String> = ruby_parser
            .get_handled_nodes()
            .iter()
            .map(|handled_node| handled_node.name.clone())
            .collect();

        Ok(Self {
            grammar_nodes,
            implemented_nodes,
            extracted_symbol_kinds,
        })
    }

    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str("# Ruby Parser Symbol Extraction Coverage Report\n\n");
        report.push_str(&format!("*Generated: {}*\n\n", format_utc_timestamp()));

        let key_nodes = vec![
            "program",
            "class",
            "module",
            "method",
            "singleton_method",
            "assignment",
            "call",
            "scope_resolution",
            "if",
            "unless",
            "while",
            "until",
            "for",
            "begin",
            "block",
            "do_block",
            "lambda",
            "comment",
        ];

        let key_implemented = key_nodes
            .iter()
            .filter(|n| self.implemented_nodes.contains(**n))
            .count();

        report.push_str("## Summary\n");
        report.push_str(&format!(
            "- Key nodes: {}/{} ({}%)\n",
            key_implemented,
            key_nodes.len(),
            (key_implemented * 100) / key_nodes.len()
        ));
        report.push_str(&format!(
            "- Symbol kinds extracted: {}\n",
            self.extracted_symbol_kinds.len()
        ));

        report.push_str("## Coverage Table\n\n");
        report.push_str("| Node Type | ID | Status |\n");
        report.push_str("|-----------|-----|--------|\n");

        let mut gaps = Vec::new();
        let mut missing = Vec::new();

        for node_name in &key_nodes {
            let status = if let Some(id) = self.grammar_nodes.get(*node_name) {
                if self.implemented_nodes.contains(*node_name) {
                    format!("{id} | implemented")
                } else {
                    gaps.push(node_name);
                    format!("{id} | gap")
                }
            } else {
                missing.push(node_name);
                "- | not found".to_string()
            };
            report.push_str(&format!("| {node_name} | {status} |\n"));
        }

        if gaps.is_empty() && missing.is_empty() {
            report.push_str("\nExcellent coverage! All key nodes are implemented.\n");
        }

        report
    }
}

fn discover_nodes(node: Node, registry: &mut HashMap<String, u16>) {
    let mut stack = vec![node];

    while let Some(current_node) = stack.pop() {
        registry.insert(current_node.kind().to_string(), current_node.kind_id());

        let mut cursor = current_node.walk();
        for child in current_node.children(&mut cursor) {
            stack.push(child);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_simple_ruby() {
        let code = r#"
# A simple Ruby class
class User
  attr_accessor :name

  def initialize(name)
    @name = name
  end

  def greet
    "Hello, #{@name}"
  end
end
"#;

        let audit = RubyParserAudit::audit_code(code).unwrap();

        assert!(audit.grammar_nodes.contains_key("class"));
        assert!(audit.grammar_nodes.contains_key("method"));
        assert!(audit.extracted_symbol_kinds.contains("Class"));
        assert!(audit.extracted_symbol_kinds.contains("Method"));
    }
}
