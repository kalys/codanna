//! Zeitwerk naming convention engine
//!
//! Implements Rails/Zeitwerk autoloading conventions for resolving Ruby constants
//! to file paths and vice versa. Pure static analysis, no Rails boot required.

use std::path::{Path, PathBuf};

/// Convert a Ruby constant name to a file path using Zeitwerk conventions.
///
/// # Examples
/// - `"UserController"` → `"user_controller.rb"`
/// - `"Curriculum::Operations::CreateCourseTask"` → `"curriculum/operations/create_course_task.rb"`
pub fn constant_to_path(constant: &str, autoload_roots: &[PathBuf]) -> Option<PathBuf> {
    let relative = constant_to_relative_path(constant);

    if let Some(root) = autoload_roots.first() {
        Some(root.join(&relative))
    } else {
        Some(PathBuf::from(relative))
    }
}

/// Convert a constant to a relative file path (without checking autoload roots).
///
/// `"Curriculum::Operations::CreateCourseTask"` → `"curriculum/operations/create_course_task.rb"`
pub fn constant_to_relative_path(constant: &str) -> String {
    let segments: Vec<String> = constant.split("::").map(to_snake_case).collect();
    format!("{}.rb", segments.join("/"))
}

/// Convert a file path to a Ruby constant name using Zeitwerk conventions.
///
/// # Examples
/// - `"modules/curriculum/operations/create_course_task.rb"` with root `"modules"` →
///   `"Curriculum::Operations::CreateCourseTask"`
/// - `"app/models/user.rb"` with root `"app/models"` → `"User"`
pub fn path_to_constant(path: &Path, autoload_root: &Path) -> Option<String> {
    let relative = path.strip_prefix(autoload_root).ok()?;
    let path_str = relative.to_str()?;

    // Strip .rb extension
    let without_ext = path_str.strip_suffix(".rb")?;

    let segments: Vec<String> = without_ext
        .split('/')
        .filter(|s| !s.is_empty())
        .map(to_camel_case)
        .collect();

    if segments.is_empty() {
        None
    } else {
        Some(segments.join("::"))
    }
}

/// Convert CamelCase to snake_case (Zeitwerk inflection).
///
/// # Examples
/// - `"UserController"` → `"user_controller"`
/// - `"CreateCourseTask"` → `"create_course_task"`
/// - `"HTMLParser"` → `"html_parser"` (acronym handling)
fn to_snake_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 4);
    let chars: Vec<char> = s.chars().collect();

    for (i, &c) in chars.iter().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                let prev = chars[i - 1];
                let next = chars.get(i + 1);
                // Insert underscore before uppercase if:
                // 1. Previous char is lowercase: `userC` → `user_c`
                // 2. Previous char is uppercase AND next is lowercase: `HTMLParser` → `html_parser`
                if prev.is_lowercase()
                    || (prev.is_uppercase() && next.is_some_and(|n| n.is_lowercase()))
                {
                    result.push('_');
                }
            }
            result.push(c.to_lowercase().next().unwrap_or(c));
        } else {
            result.push(c);
        }
    }

    result
}

/// Convert snake_case to CamelCase.
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

/// Standard Rails autoload paths
pub fn default_rails_autoload_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("app/models"),
        PathBuf::from("app/controllers"),
        PathBuf::from("app/services"),
        PathBuf::from("app/jobs"),
        PathBuf::from("app/mailers"),
        PathBuf::from("app/helpers"),
        PathBuf::from("app/channels"),
        PathBuf::from("app/views"),
        PathBuf::from("app/serializers"),
        PathBuf::from("app/policies"),
        PathBuf::from("app/decorators"),
        PathBuf::from("app/validators"),
        PathBuf::from("lib"),
    ]
}

/// Extract custom autoload paths from a Rails application.rb content.
///
/// Looks for patterns like:
/// - `config.autoload_paths << "#{root}/modules"`
/// - `config.autoload_paths += %w[modules lib/extensions]`
/// - `config.autoload_lib(ignore: %w[tasks])`
pub fn extract_autoload_paths(content: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // config.autoload_paths << "path"
        if trimmed.contains("autoload_paths") && trimmed.contains("<<") {
            if let Some(path) = extract_quoted_path(trimmed) {
                paths.push(PathBuf::from(path));
            }
        }

        // config.autoload_paths += %w[path1 path2]
        if trimmed.contains("autoload_paths") && trimmed.contains("%w") {
            if let Some(start) = trimmed.find("%w[") {
                let after = &trimmed[start + 3..];
                if let Some(end) = after.find(']') {
                    let items = &after[..end];
                    for item in items.split_whitespace() {
                        paths.push(PathBuf::from(item));
                    }
                }
            }
        }

        // config.autoload_lib(...)
        if trimmed.contains("autoload_lib") {
            paths.push(PathBuf::from("lib"));
        }
    }

    paths
}

/// Extract a path from a string, handling #{root}/path patterns
fn extract_quoted_path(line: &str) -> Option<String> {
    // Find quoted string
    let start = line.find('"').or_else(|| line.find('\''))?;
    let quote_char = line.as_bytes()[start] as char;
    let after_quote = &line[start + 1..];
    let end = after_quote.find(quote_char)?;
    let raw = &after_quote[..end];

    // Strip #{root}/ or #{Rails.root}/ prefix
    let cleaned = if let Some(rest) = raw.strip_prefix("#{root}/") {
        rest.to_string()
    } else if let Some(rest) = raw.strip_prefix("#{Rails.root}/") {
        rest.to_string()
    } else {
        raw.to_string()
    };

    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("UserController"), "user_controller");
        assert_eq!(to_snake_case("CreateCourseTask"), "create_course_task");
        assert_eq!(to_snake_case("HTMLParser"), "html_parser");
        assert_eq!(to_snake_case("User"), "user");
        assert_eq!(to_snake_case("API"), "api");
        assert_eq!(to_snake_case("APIController"), "api_controller");
    }

    #[test]
    fn test_to_camel_case() {
        assert_eq!(to_camel_case("user_controller"), "UserController");
        assert_eq!(to_camel_case("create_course_task"), "CreateCourseTask");
        assert_eq!(to_camel_case("user"), "User");
        assert_eq!(to_camel_case("api"), "Api");
    }

    #[test]
    fn test_constant_to_relative_path() {
        assert_eq!(constant_to_relative_path("User"), "user.rb");
        assert_eq!(
            constant_to_relative_path("UserController"),
            "user_controller.rb"
        );
        assert_eq!(
            constant_to_relative_path("Curriculum::Operations::CreateCourseTask"),
            "curriculum/operations/create_course_task.rb"
        );
    }

    #[test]
    fn test_constant_to_path_with_root() {
        let roots = vec![PathBuf::from("modules")];
        let result = constant_to_path("Curriculum::Operations::CreateCourseTask", &roots);
        assert_eq!(
            result,
            Some(PathBuf::from(
                "modules/curriculum/operations/create_course_task.rb"
            ))
        );
    }

    #[test]
    fn test_constant_to_path_no_roots() {
        let roots: Vec<PathBuf> = vec![];
        let result = constant_to_path("User", &roots);
        assert_eq!(result, Some(PathBuf::from("user.rb")));
    }

    #[test]
    fn test_path_to_constant() {
        let root = Path::new("modules");
        let path = Path::new("modules/curriculum/operations/create_course_task.rb");
        assert_eq!(
            path_to_constant(path, root),
            Some("Curriculum::Operations::CreateCourseTask".to_string())
        );

        let root = Path::new("app/models");
        let path = Path::new("app/models/user.rb");
        assert_eq!(path_to_constant(path, root), Some("User".to_string()));
    }

    #[test]
    fn test_path_to_constant_nested() {
        let root = Path::new("app/controllers");
        let path = Path::new("app/controllers/api/v1/users_controller.rb");
        assert_eq!(
            path_to_constant(path, root),
            Some("Api::V1::UsersController".to_string())
        );
    }

    #[test]
    fn test_roundtrip() {
        let original = "Curriculum::Operations::CreateCourseTask";
        let relative = constant_to_relative_path(original);
        let root = Path::new("");
        let path = Path::new(&relative);
        let back = path_to_constant(path, root);
        assert_eq!(back, Some(original.to_string()));
    }

    #[test]
    fn test_extract_autoload_paths_append() {
        let content = r##"
module MyApp
  class Application < Rails::Application
    config.autoload_paths << "#{root}/modules"
    config.autoload_paths << "#{root}/lib/extensions"
  end
end
"##;
        let paths = extract_autoload_paths(content);
        assert!(paths.contains(&PathBuf::from("modules")));
        assert!(paths.contains(&PathBuf::from("lib/extensions")));
    }

    #[test]
    fn test_extract_autoload_paths_word_array() {
        let content = r#"
config.autoload_paths += %w[modules lib/extensions]
"#;
        let paths = extract_autoload_paths(content);
        assert!(paths.contains(&PathBuf::from("modules")));
        assert!(paths.contains(&PathBuf::from("lib/extensions")));
    }

    #[test]
    fn test_extract_autoload_lib() {
        let content = r#"
config.autoload_lib(ignore: %w[tasks])
"#;
        let paths = extract_autoload_paths(content);
        assert!(paths.contains(&PathBuf::from("lib")));
    }
}
