//! Ruby/Rails project resolution provider
//!
//! Resolves Ruby project structure using Zeitwerk conventions and Rails autoloading.
//! Handles config/application.rb parsing for custom autoload paths.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::config::Settings;
use crate::project_resolver::{
    ResolutionResult, Sha256Hash,
    memo::ResolutionMemo,
    persist::{ResolutionIndex, ResolutionPersistence, ResolutionRules},
    provider::ProjectResolutionProvider,
    sha::compute_file_sha,
};

/// Ruby project resolution provider
///
/// Handles Rails/Zeitwerk autoloading conventions for resolving Ruby constants
/// to file paths.
pub struct RubyProvider {
    #[allow(dead_code)]
    memo: ResolutionMemo<HashMap<PathBuf, Sha256Hash>>,
}

impl Default for RubyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl RubyProvider {
    pub fn new() -> Self {
        Self {
            memo: ResolutionMemo::new(),
        }
    }

    fn extract_config_paths(&self, settings: &Settings) -> Vec<PathBuf> {
        settings
            .languages
            .get("ruby")
            .map(|config| config.config_files.clone())
            .unwrap_or_default()
    }

    fn is_ruby_enabled(&self, settings: &Settings) -> bool {
        settings
            .languages
            .get("ruby")
            .map(|config| config.enabled)
            .unwrap_or(true)
    }
}

impl ProjectResolutionProvider for RubyProvider {
    fn language_id(&self) -> &'static str {
        "ruby"
    }

    fn is_enabled(&self, settings: &Settings) -> bool {
        self.is_ruby_enabled(settings)
    }

    fn config_paths(&self, settings: &Settings) -> Vec<PathBuf> {
        self.extract_config_paths(settings)
    }

    fn compute_shas(&self, configs: &[PathBuf]) -> ResolutionResult<HashMap<PathBuf, Sha256Hash>> {
        let mut shas = HashMap::with_capacity(configs.len());

        for config_path in configs {
            if config_path.exists() {
                let sha = compute_file_sha(config_path)?;
                shas.insert(config_path.clone(), sha);
            }
        }

        Ok(shas)
    }

    fn rebuild_cache(&self, settings: &Settings) -> ResolutionResult<()> {
        let config_paths = self.config_paths(settings);

        let codanna_dir = std::path::Path::new(crate::init::local_dir_name());
        let persistence = ResolutionPersistence::new(codanna_dir);

        let mut index = persistence
            .load("ruby")
            .unwrap_or_else(|_| ResolutionIndex::new());

        for config_path in &config_paths {
            if config_path.exists() {
                let sha = compute_file_sha(config_path)?;

                if index.needs_rebuild(config_path, &sha) {
                    index.update_sha(config_path, &sha);

                    // Read the config file and extract autoload paths
                    let content = std::fs::read_to_string(config_path).unwrap_or_default();
                    let autoload_paths =
                        crate::parsing::ruby::zeitwerk::extract_autoload_paths(&content);

                    // Build resolution rules: autoload paths as path mappings
                    let mut paths = HashMap::new();
                    for autoload_path in &autoload_paths {
                        let pattern = format!("{}/**/*.rb", autoload_path.display());
                        paths.insert("*".to_string(), vec![pattern]);
                    }

                    // Add standard Rails paths if this looks like a Rails app
                    if content.contains("Rails::Application")
                        || content.contains("Rails.application")
                    {
                        let rails_paths =
                            crate::parsing::ruby::zeitwerk::default_rails_autoload_paths();
                        for rails_path in &rails_paths {
                            let pattern = format!("{}/**/*.rb", rails_path.display());
                            paths
                                .entry("*".to_string())
                                .or_insert_with(Vec::new)
                                .push(pattern);
                        }
                    }

                    index.set_rules(
                        config_path,
                        ResolutionRules {
                            base_url: None,
                            paths,
                        },
                    );

                    // Add file mappings
                    if let Some(parent) = config_path.parent() {
                        let pattern = format!("{}/**/*.rb", parent.display());
                        index.add_mapping(&pattern, config_path);
                    }
                }
            }
        }

        persistence.save("ruby", &index)?;

        Ok(())
    }

    fn select_affected_files(&self, settings: &Settings) -> Vec<PathBuf> {
        let config_paths = self.extract_config_paths(settings);
        let mut affected = Vec::new();

        for config in config_paths {
            if let Some(parent) = config.parent() {
                affected.push(parent.to_path_buf());
            }
        }

        // Also include standard Rails directories
        affected.extend([
            PathBuf::from("app"),
            PathBuf::from("lib"),
            PathBuf::from("modules"),
        ]);

        affected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LanguageConfig;

    fn create_test_settings(config_files: Vec<PathBuf>) -> Settings {
        let mut settings = Settings::default();
        let ruby_config = LanguageConfig {
            enabled: true,
            extensions: vec!["rb".to_string()],
            parser_options: HashMap::new(),
            config_files,
            projects: Vec::new(),
        };
        settings.languages.insert("ruby".to_string(), ruby_config);
        settings
    }

    #[test]
    fn ruby_provider_has_correct_language_id() {
        let provider = RubyProvider::new();
        assert_eq!(provider.language_id(), "ruby");
    }

    #[test]
    fn ruby_provider_enabled_by_default() {
        let provider = RubyProvider::new();
        let settings = Settings::default();
        assert!(provider.is_enabled(&settings));
    }

    #[test]
    fn ruby_provider_respects_enabled_flag() {
        let provider = RubyProvider::new();
        let mut settings = Settings::default();

        let ruby_config = LanguageConfig {
            enabled: false,
            extensions: vec!["rb".to_string()],
            parser_options: HashMap::new(),
            config_files: vec![],
            projects: Vec::new(),
        };
        settings.languages.insert("ruby".to_string(), ruby_config);

        assert!(!provider.is_enabled(&settings));
    }

    #[test]
    fn extracts_config_paths_from_settings() {
        let provider = RubyProvider::new();
        let config_files = vec![PathBuf::from("config/application.rb")];
        let settings = create_test_settings(config_files.clone());

        let paths = provider.config_paths(&settings);
        assert_eq!(paths.len(), 1);
        assert!(paths.contains(&PathBuf::from("config/application.rb")));
    }

    #[test]
    fn skips_non_existent_files_in_sha_computation() {
        let provider = RubyProvider::new();
        let non_existent = PathBuf::from("/definitely/does/not/exist/application.rb");
        let paths = vec![non_existent];

        let result = provider.compute_shas(&paths);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn select_affected_files_includes_standard_dirs() {
        let provider = RubyProvider::new();
        let settings = create_test_settings(vec![PathBuf::from("config/application.rb")]);

        let affected = provider.select_affected_files(&settings);
        assert!(affected.iter().any(|p| p == &PathBuf::from("app")));
        assert!(affected.iter().any(|p| p == &PathBuf::from("lib")));
    }
}
