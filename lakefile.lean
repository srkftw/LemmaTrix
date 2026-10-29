import Lake
open Lake DSL
package LemmaTrix where
  version := v!"0.1.0"
  moreLeanArgs := #["-Dcompiler.extract_closed=false"]
@[default_target]
lean_lib Compiler where
  globs := #[.submodules `Compiler]
@[default_target]
lean_lib Guest where
  globs := #[.submodules `Guest]
