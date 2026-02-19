//! Ruby language definition and registration

use crate::parsing::{
    LanguageBehavior, LanguageDefinition, LanguageId, LanguageParser, LanguageRegistry,
};
use crate::{IndexError, IndexResult, Settings};
use std::sync::Arc;

use super::{RubyBehavior, RubyParser};

/// Ruby language definition
pub struct RubyLanguage;

impl LanguageDefinition for RubyLanguage {
    fn id(&self) -> LanguageId {
        LanguageId::new("ruby")
    }

    fn name(&self) -> &'static str {
        "Ruby"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["rb", "rake", "gemspec", "ru"]
    }

    fn create_parser(&self, _settings: &Settings) -> IndexResult<Box<dyn LanguageParser>> {
        let parser = RubyParser::new().map_err(|e| IndexError::General(e.to_string()))?;
        Ok(Box::new(parser))
    }

    fn create_behavior(&self) -> Box<dyn LanguageBehavior> {
        Box::new(RubyBehavior::new())
    }

    fn default_enabled(&self) -> bool {
        true
    }

    fn is_enabled(&self, settings: &Settings) -> bool {
        settings
            .languages
            .get(self.id().as_str())
            .map(|config| config.enabled)
            .unwrap_or(self.default_enabled())
    }
}

/// Register Ruby language with the registry
pub(crate) fn register(registry: &mut LanguageRegistry) {
    registry.register(Arc::new(RubyLanguage));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ruby_language_id() {
        let lang = RubyLanguage;
        assert_eq!(lang.id(), LanguageId::new("ruby"));
    }

    #[test]
    fn test_ruby_language_name() {
        let lang = RubyLanguage;
        assert_eq!(lang.name(), "Ruby");
    }

    #[test]
    fn test_ruby_file_extensions() {
        let lang = RubyLanguage;
        assert_eq!(lang.extensions(), &["rb", "rake", "gemspec", "ru"]);
    }

    #[test]
    fn test_ruby_enabled_by_default() {
        let lang = RubyLanguage;
        assert!(lang.default_enabled());
    }

    #[test]
    fn test_ruby_enabled_with_default_settings() {
        let lang = RubyLanguage;
        let settings = Settings::default();
        assert!(lang.is_enabled(&settings));
    }

    #[test]
    fn test_ruby_parser_creation() {
        let lang = RubyLanguage;
        let settings = Settings::default();

        let parser_result = lang.create_parser(&settings);
        assert!(parser_result.is_ok(), "Ruby parser creation should succeed");

        let parser = parser_result.unwrap();
        assert_eq!(parser.language(), crate::parsing::Language::Ruby);
    }

    #[test]
    fn test_ruby_behavior_creation() {
        let lang = RubyLanguage;
        let behavior = lang.create_behavior();

        assert_eq!(behavior.module_separator(), "::");
        assert!(behavior.supports_inherent_methods());
        assert!(!behavior.supports_traits());
    }

    #[test]
    fn test_ruby_language_registry_registration() {
        use crate::parsing::LanguageRegistry;

        let mut registry = LanguageRegistry::new();
        register(&mut registry);

        let ruby_id = LanguageId::new("ruby");
        assert!(registry.get(ruby_id).is_some());
    }

    #[test]
    fn test_ruby_file_extension_recognition() {
        use crate::parsing::LanguageRegistry;

        let mut registry = LanguageRegistry::new();
        register(&mut registry);

        let detected = registry.get_by_extension("rb");
        assert!(detected.is_some());
        assert_eq!(detected.unwrap().id(), LanguageId::new("ruby"));

        let detected_rake = registry.get_by_extension("rake");
        assert!(detected_rake.is_some());
    }
}
