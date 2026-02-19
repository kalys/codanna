//! Ruby language parser implementation
//!
//! This module provides Ruby language support for Codanna's code intelligence system,
//! enabling symbol extraction, relationship tracking, and semantic analysis of Ruby codebases.
//!
//! ## Key Features
//!
//! ### Symbol Extraction
//! - **Classes**: Class declarations with inheritance
//! - **Modules**: Module declarations and nesting
//! - **Methods**: Instance methods, singleton methods, and attr_* metaprogramming
//! - **Constants**: Constant assignments
//! - **Variables**: Instance, class, and global variables
//!
//! ### Ruby-Specific Language Features
//! - **Visibility**: public/private/protected state machine
//! - **Mixins**: include/extend/prepend tracking
//! - **Metaprogramming**: attr_accessor/attr_reader/attr_writer
//! - **Nested Namespaces**: Module::Class nesting with scope resolution
//! - **Zeitwerk**: Rails autoloading convention support

pub mod audit;
pub mod behavior;
pub mod definition;
pub mod parser;
pub mod resolution;
pub mod zeitwerk;

pub use behavior::RubyBehavior;
pub use definition::RubyLanguage;
pub use parser::RubyParser;
pub use resolution::{RubyInheritanceResolver, RubyResolutionContext};

pub(crate) use definition::register;
