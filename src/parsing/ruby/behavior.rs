//! Ruby-specific language behavior implementation

use crate::Visibility;
use crate::parsing::LanguageBehavior;
use crate::parsing::behavior_state::{BehaviorState, StatefulBehavior};
use crate::parsing::resolution::{InheritanceResolver, ResolutionScope};
use crate::types::FileId;
use std::path::{Path, PathBuf};
use tree_sitter::Language;

use super::resolution::{RubyInheritanceResolver, RubyResolutionContext};

/// Ruby language behavior implementation
#[derive(Clone)]
pub struct RubyBehavior {
    state: BehaviorState,
}

impl RubyBehavior {
    pub fn new() -> Self {
        Self {
            state: BehaviorState::new(),
        }
    }
}

impl Default for RubyBehavior {
    fn default() -> Self {
        Self::new()
    }
}

impl StatefulBehavior for RubyBehavior {
    fn state(&self) -> &BehaviorState {
        &self.state
    }
}

impl LanguageBehavior for RubyBehavior {
    fn language_id(&self) -> crate::parsing::registry::LanguageId {
        crate::parsing::registry::LanguageId::new("ruby")
    }

    fn format_module_path(&self, base_path: &str, _symbol_name: &str) -> String {
        base_path.to_string()
    }

    fn get_language(&self) -> Language {
        tree_sitter_ruby::LANGUAGE.into()
    }

    fn module_separator(&self) -> &'static str {
        "::"
    }

    fn format_path_as_module(&self, components: &[&str]) -> Option<String> {
        if components.is_empty() {
            return Some(String::new());
        }
        // Convert path components to CamelCase Ruby convention
        let parts: Vec<String> = components.iter().map(|c| to_camel_case(c)).collect();
        Some(parts.join("::"))
    }

    fn module_path_from_file(
        &self,
        file_path: &Path,
        project_root: &Path,
        extensions: &[&str],
    ) -> Option<String> {
        use crate::parsing::paths::strip_extension;

        let relative_path = if file_path.is_absolute() {
            file_path.strip_prefix(project_root).ok()?
        } else {
            file_path
        };

        let path = relative_path.to_str()?;
        let path_clean = path.trim_start_matches("./");
        let module_path = strip_extension(path_clean, extensions);

        // Convert path separators to :: and components to CamelCase
        let parts: Vec<&str> = module_path.split(['/', '\\']).collect();
        let camel_parts: Vec<String> = parts.iter().map(|p| to_camel_case(p)).collect();
        let result = camel_parts.join("::");

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    fn parse_visibility(&self, signature: &str) -> Visibility {
        let trimmed = signature.trim();
        if trimmed.starts_with("private") {
            return Visibility::Private;
        }
        if trimmed.starts_with("protected") {
            return Visibility::Module;
        }
        Visibility::Public
    }

    fn supports_traits(&self) -> bool {
        false
    }

    fn supports_inherent_methods(&self) -> bool {
        true
    }

    fn create_resolution_context(&self, file_id: FileId) -> Box<dyn ResolutionScope> {
        Box::new(RubyResolutionContext::new(file_id))
    }

    fn create_inheritance_resolver(&self) -> Box<dyn InheritanceResolver> {
        Box::new(RubyInheritanceResolver::new())
    }

    fn inheritance_relation_name(&self) -> &'static str {
        "extends"
    }

    fn map_relationship(&self, language_specific: &str) -> crate::relationship::RelationKind {
        use crate::relationship::RelationKind;

        match language_specific {
            "extends" => RelationKind::Extends,
            "includes" | "implements" => RelationKind::Implements,
            "uses" => RelationKind::Uses,
            "calls" => RelationKind::Calls,
            "defines" => RelationKind::Defines,
            _ => RelationKind::References,
        }
    }

    fn register_file(&self, path: PathBuf, file_id: FileId, module_path: String) {
        self.register_file_with_state(path, file_id, module_path);
    }

    fn add_import(&self, import: crate::parsing::Import) {
        self.add_import_with_state(import);
    }

    fn get_imports_for_file(&self, file_id: FileId) -> Vec<crate::parsing::Import> {
        self.get_imports_from_state(file_id)
    }

    fn is_resolvable_symbol(&self, symbol: &crate::Symbol) -> bool {
        use crate::SymbolKind;
        use crate::symbol::ScopeContext;

        let module_level_symbol = matches!(
            symbol.kind,
            SymbolKind::Function
                | SymbolKind::Class
                | SymbolKind::Module
                | SymbolKind::Constant
                | SymbolKind::Method
        );

        if module_level_symbol {
            return true;
        }

        if let Some(ref scope_context) = symbol.scope_context {
            match scope_context {
                ScopeContext::Module | ScopeContext::Global | ScopeContext::Package => true,
                ScopeContext::Local { .. } | ScopeContext::Parameter => false,
                ScopeContext::ClassMember { .. } => {
                    matches!(symbol.visibility, Visibility::Public)
                }
            }
        } else {
            false
        }
    }

    fn get_module_path_for_file(&self, file_id: FileId) -> Option<String> {
        self.state.get_module_path(file_id)
    }

    fn configure_symbol(&self, symbol: &mut crate::Symbol, module_path: Option<&str>) {
        if let Some(path) = module_path {
            symbol.module_path = Some(path.to_string().into());
        }

        if let Some(ref sig) = symbol.signature {
            symbol.visibility = self.parse_visibility(sig);
        }
    }

    fn import_matches_symbol(
        &self,
        import_path: &str,
        symbol_module_path: &str,
        _importing_module: Option<&str>,
    ) -> bool {
        if import_path == symbol_module_path {
            return true;
        }

        // Convert require path (e.g., "curriculum/operations") to module path ("Curriculum::Operations")
        let parts: Vec<&str> = import_path.split('/').collect();
        let camel_parts: Vec<String> = parts.iter().map(|p| to_camel_case(p)).collect();
        let normalized = camel_parts.join("::");

        normalized == symbol_module_path
    }
}

/// Convert a snake_case or lowercase string to CamelCase
fn to_camel_case(s: &str) -> String {
    s.split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(c) => {
                    let upper: String = c.to_uppercase().collect();
                    upper + chars.as_str()
                }
                None => String::new(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Visibility;
    use std::path::Path;

    #[test]
    fn test_module_separator() {
        let behavior = RubyBehavior::new();
        assert_eq!(behavior.module_separator(), "::");
    }

    #[test]
    fn test_to_camel_case() {
        assert_eq!(to_camel_case("create_course_task"), "CreateCourseTask");
        assert_eq!(to_camel_case("user"), "User");
        assert_eq!(to_camel_case("api_controller"), "ApiController");
    }

    #[test]
    fn test_module_path_from_file() {
        let behavior = RubyBehavior::new();
        let project_root = Path::new("/home/user/project");
        let extensions = &["rb"];

        let file_path = Path::new("/home/user/project/app/models/user.rb");
        assert_eq!(
            behavior.module_path_from_file(file_path, project_root, extensions),
            Some("App::Models::User".to_string())
        );

        let file_path =
            Path::new("/home/user/project/modules/curriculum/operations/create_course_task.rb");
        assert_eq!(
            behavior.module_path_from_file(file_path, project_root, extensions),
            Some("Modules::Curriculum::Operations::CreateCourseTask".to_string())
        );
    }

    #[test]
    fn test_format_path_as_module() {
        let behavior = RubyBehavior::new();

        assert_eq!(
            behavior.format_path_as_module(&["curriculum", "operations"]),
            Some("Curriculum::Operations".to_string())
        );
        assert_eq!(
            behavior.format_path_as_module(&["user_controller"]),
            Some("UserController".to_string())
        );
    }

    #[test]
    fn test_parse_visibility() {
        let behavior = RubyBehavior::new();

        assert_eq!(
            behavior.parse_visibility("def public_method"),
            Visibility::Public
        );
        assert_eq!(
            behavior.parse_visibility("private def secret"),
            Visibility::Private
        );
        assert_eq!(
            behavior.parse_visibility("protected def internal"),
            Visibility::Module
        );
    }

    #[test]
    fn test_supports_traits() {
        let behavior = RubyBehavior::new();
        assert!(!behavior.supports_traits());
    }

    #[test]
    fn test_supports_inherent_methods() {
        let behavior = RubyBehavior::new();
        assert!(behavior.supports_inherent_methods());
    }

    #[test]
    fn test_import_matches_symbol() {
        let behavior = RubyBehavior::new();

        assert!(behavior.import_matches_symbol(
            "curriculum/operations",
            "Curriculum::Operations",
            None
        ));
        assert!(behavior.import_matches_symbol("json", "json", None));
        assert!(!behavior.import_matches_symbol("foo", "bar", None));
    }
}
