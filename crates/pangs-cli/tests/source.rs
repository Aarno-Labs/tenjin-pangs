use serde_json::{json, Value};
use std::{fs, path::PathBuf, process::Command};
use tempfile::TempDir;

fn clang() -> PathBuf {
    PathBuf::from(std::env::var("LLVM_SYS_140_PREFIX").expect("LLVM 14 prefix")).join("bin/clang")
}

fn analyze(code: &str) -> (TempDir, Value) {
    analyze_sources(&[("test.i", code)])
}

fn analyze_sources(sources: &[(&str, &str)]) -> (TempDir, Value) {
    let dir = tempfile::tempdir().unwrap();
    let bc = dir.path().join("test.bc");
    let mut commands = Vec::new();
    let mut modules = Vec::new();
    for (index, (name, code)) in sources.iter().enumerate() {
        let source = dir.path().join(name);
        let module = dir.path().join(format!("{index}.bc"));
        fs::write(&source, code).unwrap();
        let output = Command::new(clang())
            .args(["-x", "c", "-g", "-O0", "-c", "-emit-llvm"])
            .arg(&source)
            .arg("-o")
            .arg(&module)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        modules.push(module);
        commands.push(json!({
            "directory": dir.path(), "file": source,
            "arguments": [clang(), PathBuf::from("-x"), PathBuf::from("c"), source.clone()]
        }));
    }
    let output = Command::new(clang().with_file_name("llvm-link"))
        .args(&modules)
        .arg("-o")
        .arg(&bc)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let db = dir.path().join("commands.json");
    fs::write(&db, serde_json::to_vec(&commands).unwrap()).unwrap();
    let out = dir.path().join("out");
    let output = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("analyze")
        .arg(&bc)
        .arg("--out")
        .arg(&out)
        .args([
            "--dispose",
            "--manifest-only",
            "--no-overrides",
            "--build-mode",
            "executable",
            "--repo-root",
        ])
        .arg(dir.path())
        .arg("--source-compdb")
        .arg(db)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest =
        serde_json::from_slice(&fs::read(out.join("pangs-manifest.json")).unwrap()).unwrap();
    (dir, manifest)
}

fn field(m: &Value) -> &Value {
    m["context_rewrite"]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["llvm_name"] == "g")
        .unwrap()
}

#[test]
fn private_initializer_functions_constrain_storage_not_callback_types() {
    for private in [false, true] {
        let code = format!(
            "int g; {}int foo(int x){{return ++g+x;}} int (*dispatch)(int)=foo;",
            if private { "static " } else { "" }
        );
        let (_, m) = analyze_sources(&[
            (
                "main.i",
                "extern int (*dispatch)(int); int main(void){return dispatch(7);}",
            ),
            ("callbacks.i", &code),
        ]);
        let dispatch = m["context_rewrite"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["llvm_name"] == "dispatch")
            .unwrap();
        assert_eq!(
            dispatch["blockers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|b| b["kind"] == "source-private-initializer-function"),
            private,
            "{dispatch:#}"
        );
        assert_eq!(field(&m)["blockers"], json!([]), "{m:#}");
        assert!(
            m["context_rewrite"]["selected"]["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["llvm_name"] == "g"),
            "{m:#}"
        );
    }
    let (_, m) = analyze("int g; static int foo(int x){return ++g+x;} int (*dispatch)(int)=foo; int main(void){return dispatch(7);}");
    let dispatch = m["context_rewrite"]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["llvm_name"] == "dispatch")
        .unwrap();
    assert_eq!(dispatch["blockers"], json!([]), "{dispatch:#}");
}

#[test]
fn source_only_indirect_chain_adapts_unchanged_producers_and_compiles() {
    let code = "static int g;\nstatic int needs(void){return ++g;}\nstatic int ordinary(void){return 2;}\nstruct Ops { int (*fn)(void); };\nstatic struct Ops ops = {needs};\nstatic int dead(void){ ops.fn = ordinary; return ops.fn(); }\nint main(void){if(0) return dead(); return needs();}\n";
    let (dir, m) = analyze(code);
    let f = field(&m);
    assert_eq!(f["blockers"], json!([]), "{f:#}");
    assert_eq!(f["functions"], json!(["dead", "main", "needs"]));
    assert_eq!(m["context_rewrite"]["source"]["version"], 3);
    let source_metadata = &m["context_rewrite"]["source"];
    for key in ["module_sha256", "compdb_sha256", "compdb_path"] {
        assert!(source_metadata.get(key).is_none(), "{source_metadata}");
    }
    for file in source_metadata["files"].as_array().unwrap() {
        assert!(file.get("sha256").is_none(), "{file}");
    }
    for edit in f["source_edits"].as_array().unwrap() {
        assert!(edit.get("expected").is_none(), "{edit}");
    }
    let plan = serde_json::from_value(f.clone()).unwrap();
    let mut edits = pangs_manifest::compose_source_edits(&[plan]).unwrap();
    edits.sort_by_key(|e| std::cmp::Reverse(e.start));
    let mut rewritten = code.to_owned();
    for edit in edits {
        rewritten.replace_range(edit.start..edit.end, &edit.replacement);
    }
    rewritten.insert_str(0, "struct XjGlobals;\n");
    let source = dir.path().join("test.i");
    fs::write(&source, rewritten).unwrap();
    let check = Command::new(clang())
        .args([
            "-x",
            "c",
            "-fsyntax-only",
            "-Werror=incompatible-function-pointer-types",
        ])
        .arg(source)
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn compound_literal_assignment_connects_callback_fields_and_producers() {
    let code = "static int g;\nstatic int needs(void){return ++g;}\nstatic int ordinary(void){return 2;}\nstruct Ops { int (*fn)(void); };\nstatic struct Ops ops;\nstatic void configure(int choose){ops=(struct Ops){choose?needs:ordinary};}\nint main(void){configure(1);return ops.fn();}\n";
    let (dir, m) = analyze(code);
    let f = field(&m);
    assert_eq!(f["blockers"], json!([]), "{f:#}");
    assert_eq!(f["functions"], json!(["main", "needs"]));
    assert_eq!(f["source_wrappers"].as_array().unwrap().len(), 1);
    assert_eq!(f["source_wrappers"][0]["function"], "ordinary");

    let plan = serde_json::from_value(f.clone()).unwrap();
    let mut edits = pangs_manifest::compose_source_edits(&[plan]).unwrap();
    edits.sort_by_key(|e| std::cmp::Reverse(e.start));
    let mut rewritten = code.to_owned();
    for edit in edits {
        rewritten.replace_range(edit.start..edit.end, &edit.replacement);
    }
    assert!(
        rewritten.contains("choose?needs:ordinary_xjw"),
        "{rewritten}"
    );
    rewritten.insert_str(0, "struct XjGlobals;\n");
    let source = dir.path().join("test.i");
    fs::write(&source, &rewritten).unwrap();
    let check = Command::new(clang())
        .args([
            "-x",
            "c",
            "-fsyntax-only",
            "-Werror=incompatible-function-pointer-types",
        ])
        .arg(source)
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{}\n{rewritten}",
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn context_parameter_and_first_parameter_typedef_edits_compose() {
    let code = "static int g;\ntypedef int (*CB)(int);\nint apply(CB cb, int x);\nint needs(int x){return ++g+x;}\nint apply(CB cb, int x){return cb(x);}\nint main(void){return apply(needs, 1);}\n";
    let (dir, m) = analyze(code);
    let f = field(&m);
    assert_eq!(f["blockers"], json!([]), "{f:#}");
    assert!(
        m["context_rewrite"]["selected"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["llvm_name"] == "g"),
        "{m:#}"
    );
    let mut edits: Vec<pangs_manifest::SourceEdit> =
        serde_json::from_value(m["context_rewrite"]["selected"]["source_edits"].clone()).unwrap();
    edits.sort_by_key(|e| std::cmp::Reverse(e.start));
    let mut rewritten = code.to_owned();
    for edit in edits {
        rewritten.replace_range(edit.start..edit.end, &edit.replacement);
    }
    assert_eq!(
        rewritten
            .matches("apply(struct XjGlobals *xjg, CB__pangs_context cb, int x)")
            .count(),
        2,
        "{rewritten}"
    );
    rewritten.insert_str(0, "struct XjGlobals;\n");
    let source = dir.path().join("test.i");
    fs::write(&source, rewritten).unwrap();
    let check = Command::new(clang())
        .args([
            "-x",
            "c",
            "-fsyntax-only",
            "-Werror=incompatible-function-pointer-types",
        ])
        .arg(source)
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn source_boundaries_and_initializers_block_even_when_ir_elides_them() {
    for (extra, expected) in [
        ("extern int atexit(void (*)(void)); static void cb(void){if(0)++g;} void retained(void){atexit(cb);}", "source-external-callback:atexit"),
        ("static int *p=&g; int retained(void){return *p;}", "source-static-initializer-dependency"),
        ("static void cb(void){if(0)++g;} void retained(void){((void (*)(int))cb)(1);}", "source-callable-cast"),
    ] {
        let (_, m) = analyze(&format!("static int g; {extra} int main(void){{return ++g;}}"));
        let f = field(&m);
        assert!(f["blockers"].as_array().unwrap().iter().any(|b| b["kind"] == expected), "{f:#}");
    }
}

#[test]
fn identical_slot_signatures_do_not_establish_flow() {
    let (_, m) = analyze("static int g; static int a(void){return ++g;} static int b(void){return 0;} static int (*p)(void)=a; static int (*q)(void)=b; int main(void){return p()+q();}");
    let f = field(&m);
    assert!(
        !f["functions"].as_array().unwrap().contains(&json!("b")),
        "{f:#}"
    );
}

#[test]
fn unchanged_function_occurrences_do_not_join_unrelated_uses() {
    let (_, m) = analyze("static int g; int needs(int x){return ++g+x;} int plain(int x){return x;} int direct(void){return plain(1);} int separate(void){int (*q)(int)=plain;return q(2);} int main(int argc,char **argv){int (*p)(int)=argc>1?needs:plain;return p(1)+direct()+separate()+(p==plain);}");
    let f = field(&m);
    assert_eq!(f["blockers"], json!([]), "{f:#}");
    assert_eq!(f["functions"], json!(["main", "needs"]));
    assert_eq!(f["source_wrappers"].as_array().unwrap().len(), 1);
    assert_eq!(f["source_wrappers"][0]["function"], "plain");
    assert_eq!(
        f["source_wrappers"][0]["edits"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["kind"] == "wrapper-use")
            .count(),
        2
    );
}

#[test]
fn wrapper_name_collisions_and_aliases_are_planning_constraints() {
    for (extra, expected) in [
        (
            "int plain_xjw; int plain(int x){return x;}",
            "source-generated-name-collision",
        ),
        (
            "int plain(int); __attribute__((weak)) int plain(int x){return x;}",
            "source-wrapper-symbol-alias",
        ),
        (
            "int plain(int) __asm__(\"needs\");",
            "source-wrapper-symbol-alias",
        ),
        (
            "__attribute__((returns_twice)) int plain(int x){return x;}",
            "source-wrapper-returns-twice",
        ),
    ] {
        let (_, m) = analyze(&format!("static int g; int needs(int x){{return ++g+x;}} {extra} int main(int argc,char **argv){{int (*p)(int)=argc>1?needs:plain;return p(1);}}"));
        assert!(
            field(&m)["blockers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|b| b["kind"] == expected),
            "{}",
            field(&m)
        );
    }
}

#[test]
fn dead_write_is_representation_evidence_not_runtime_write() {
    let (_, m) =
        analyze("static int g=7; void retained(void){if(0)++g;} int main(void){return g;}");
    let g = m["globals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["meta"]["llvm_name"] == "g")
        .unwrap();
    assert_eq!(g["facts"]["written"]["value"], false);
    assert!(g["facts"]["source_obligations"]["observations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|o| o["kind"] == "update" && o["site"]["function"] == "retained"));
    assert_eq!(g["disposition"]["chosen"], "localize", "{g:#}");
    assert!(g["disposition"]["cascade_trace"]
        .to_string()
        .contains("source-retained-assignment"));
}

#[test]
fn retained_function_static_initializer_and_lifecycle_entry_are_blockers() {
    for (body, expected) in [
        ("void retained(void){static int *p=&g; (void)p;}", "source-static-initializer-dependency"),
        ("__attribute__((constructor,used)) static void startup(void){if(0)++g;}", "source-lifecycle-or-opaque-entry"),
        ("int xjg;", "source-context-name-collision"),
        ("static int f(void){return ++g;} static int (*choose(void))(void){return f;} int retained(void){return choose()();}", "source-callable-return-type"),
    ] {
        let (_, m) = analyze(&format!("static int g; {body} int main(void){{return ++g;}}"));
        assert!(field(&m)["blockers"].as_array().unwrap().iter().any(|b| b["kind"] == expected), "{}", field(&m));
    }
}

#[test]
fn typedef_cloning_does_not_change_unrelated_slots() {
    let (_, m) = analyze("static int g; static int a(void){return ++g;} static int b(void){return 0;} typedef int (*CB)(void); static CB p=a; static CB q=b; int main(void){return p()+q();}");
    let f = field(&m);
    assert_eq!(f["blockers"], json!([]), "{f}");
    assert!(!f["functions"].as_array().unwrap().contains(&json!("b")));
    let edits = f["source_edits"].as_array().unwrap();
    assert_eq!(
        edits
            .iter()
            .filter(|e| e["kind"] == "typedef-clone")
            .count(),
        1
    );
    assert_eq!(
        edits.iter().filter(|e| e["kind"] == "typedef-use").count(),
        1
    );
}

#[test]
fn constant_definitions_receive_source_checked_dispositions() {
    let (dir, m) = analyze(
        r#"
static const float stb__midpoints6[64] = {0.007843f, 0.023529f, 1.0f};
extern const float external_table[64];
float refine_block(unsigned q) {
    static const int weights[4] = {3, 0, 2, 1};
    return stb__midpoints6[q & 63] + weights[q & 3] + external_table[q & 63];
}
"#,
    );
    let globals = m["globals"].as_array().unwrap();
    assert_eq!(globals.len(), 2, "{m:#}");
    for (llvm_name, declaration) in [
        ("stb__midpoints6", "stb__midpoints6"),
        ("refine_block.weights", "refine_block:weights"),
    ] {
        let g = globals
            .iter()
            .find(|g| g["meta"]["llvm_name"] == llvm_name)
            .unwrap_or_else(|| panic!("missing {llvm_name}: {m:#}"));
        assert_eq!(g["facts"]["written"]["value"], false, "{g:#}");
        assert_eq!(g["disposition"]["chosen"], "immutable", "{g:#}");
        let source = &g["facts"]["source_obligations"];
        assert_eq!(source["declaration"], declaration, "{g:#}");
        assert_eq!(source["contains_object_pointer"], false);
        assert!(!source["observations"].as_array().unwrap().is_empty());
    }
    assert_eq!(m["context_rewrite"]["selected"]["fields"], json!([]));
    let metrics: Value =
        serde_json::from_slice(&fs::read(dir.path().join("out/metrics.json")).unwrap()).unwrap();
    assert_eq!(metrics["mutable_globals_total"], 0);
    let manifest: pangs_manifest::Manifest = serde_json::from_value(m).unwrap();
    manifest.validate().unwrap();
}

#[test]
fn constant_definitions_still_obey_source_representation_guards() {
    for (code, guard) in [
        (
            "const unsigned g=1u+2u; unsigned read(void){return g;}",
            "source-section-initializer",
        ),
        (
            "static const int values[2]={1,2}; const int *const g=values; int read(unsigned n){return g[n&1];}",
            "source-default-type-not-sync",
        ),
    ] {
        let (_, m) = analyze(code);
        let g = m["globals"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["meta"]["llvm_name"] == "g")
            .unwrap_or_else(|| panic!("missing constant: {m:#}"));
        assert_eq!(g["facts"]["written"]["value"], false, "{g:#}");
        assert_ne!(g["disposition"]["chosen"], "immutable", "{g:#}");
        assert!(g["disposition"]["cascade_trace"].to_string().contains(guard), "{g:#}");
    }
}

#[test]
fn constant_owners_keep_compound_literal_storage_facts() {
    for constant_storage in [false, true] {
        let qualifier = if constant_storage { "const " } else { "" };
        let writer = if constant_storage {
            ""
        } else {
            "void write(int n){*owner=n;}"
        };
        let (_, m) = analyze(&format!(
            "{qualifier}int *const owner=&({qualifier}int){{1}}; int read(void){{return *owner;}} {writer}"
        ));
        let globals = m["globals"].as_array().unwrap();
        assert_eq!(globals.len(), 1, "{m:#}");
        let owner = &globals[0];
        assert_eq!(owner["meta"]["llvm_name"], "owner");
        assert!(owner.get("storage_members").is_some(), "{m:#}");
        assert_eq!(
            owner["storage_members"].as_array().unwrap().len(),
            1,
            "{owner:#}"
        );
        assert_eq!(owner["storage_members"][0]["llvm_name"], ".compoundliteral");
        assert_eq!(m["synthetic_globals"][0]["owner"], owner["key"]);
        assert_eq!(owner["facts"]["written"]["value"], !constant_storage);
        assert!(
            owner["disposition"]["cascade_trace"]
                .to_string()
                .contains("source-default-type-not-sync"),
            "{owner:#}"
        );
        let manifest: pangs_manifest::Manifest = serde_json::from_value(m).unwrap();
        manifest.validate().unwrap();
    }
}

#[test]
fn read_only_array_selection_does_not_require_mutable_rust_storage() {
    let (_, m) =
        analyze("static int g[2]={1,2}; int main(int argc,char **argv){return (g)[argc&1];}");
    let g = m["globals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["meta"]["llvm_name"] == "g")
        .unwrap();
    assert_eq!(g["disposition"]["chosen"], "immutable", "{g:#}");
}

#[test]
fn aggregate_copy_and_opaque_storage_are_explicitly_blocked() {
    for (body, expected) in [
        (
            "struct S {int(*p)(void);}; static void dead(void){struct S x={f},y; y=x;}",
            "source-aggregate-copy",
        ),
        (
            "static void dead(void){void *opaque; opaque=f;}",
            "source-opaque-callable-store",
        ),
        (
            "static int dead(void){int(*p)(void)=f+0; return p();}",
            "source-unmodeled-callable-expression",
        ),
        (
            "struct S {int(*p)(void);}; static void dead(void){struct S x={f}; void *opaque=&x;}",
            "source-opaque-aggregate-cast",
        ),
        (
            "struct S {int(*p)(void);}; struct T {int(*p)(void);}; static int dead(void){struct S x={f}; return ((struct T*)&x)->p();}",
            "source-opaque-aggregate-cast",
        ),
        (
            "struct S {int(*p)(void);}; static void dead(void){struct S x={f}; __asm__ volatile(\"\" : : \"r\"(&x));}",
            "source-inline-assembly",
        ),
        (
            "extern int (*external_slot)(void); static void dead(void){external_slot=f;}",
            "source-external-callable-storage",
        ),
    ] {
        let body = body.replace("static void dead", "void retained").replace("static int dead", "int retained");
        let (_, m) = analyze(&format!(
            "static int g; static int f(void){{return ++g;}} {body} int main(void){{return f();}}"
        ));
        assert!(
            field(&m)["blockers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|b| b["kind"] == expected),
            "{}",
            field(&m)
        );
    }
}

#[test]
fn cross_tu_function_type_disagreement_is_preserved_but_parse_failures_are_fatal() {
    for (second, succeeds) in [
        ("int f(int x){return x;}", true),
        // Separate TUs can deliberately use different source types for one
        // external symbol while retaining a link-compatible machine ABI.
        ("long f(long x){return x;}", true),
        ("int f(int x){return ; BROKEN }", false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.i");
        let b = dir.path().join("b.i");
        fs::write(&a, "extern int f(int); int main(void){return f(1);}").unwrap();
        fs::write(&b, second).unwrap();
        let db = dir.path().join("commands.json");
        // No -x c: exercise the Clang 14 preprocessed-job path.
        fs::write(
            &db,
            serde_json::to_vec(&json!([
                {"directory":dir.path(), "file":a, "arguments":[clang(),a.clone()]},
                {"directory":dir.path(), "file":b, "arguments":[clang(),b.clone()]},
            ]))
            .unwrap(),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_pangs"))
            .args(["validate-source", "--source-compdb"])
            .arg(db)
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            succeeds,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn context_rewrite_preserves_per_tu_function_types() {
    let (_, m) = analyze_sources(&[
        (
            "caller.i",
            "typedef double scalar_t; extern int f(scalar_t *); int main(void){scalar_t x=0; return f(&x);}",
        ),
        (
            "definition.i",
            "typedef float scalar_t; static int g; int f(scalar_t *x){return ++g+(int)*x;}",
        ),
    ]);
    let recipe = field(&m);
    assert_eq!(recipe["blockers"], json!([]), "{recipe:#}");
    assert_eq!(recipe["functions"], json!(["f", "main"]), "{recipe:#}");
    assert!(
        m["context_rewrite"]["selected"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field["llvm_name"] == "g"),
        "{m:#}"
    );
    let signature_files = recipe["source_edits"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|edit| edit["kind"] == "signature")
        .map(|edit| edit["file"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(signature_files, ["caller.i", "definition.i"]);
}

#[test]
fn cross_tu_static_inline_copies_can_have_different_signatures() {
    let first = r#"# 1 "shared.h"
struct XjGlobals { int value; };
static inline int helper(struct XjGlobals *g){return g->value;}
# 1 "a.c"
int a(void){struct XjGlobals g={3}; return helper(&g);}
"#;
    let second = r#"# 1 "shared.h"
struct XjGlobals { int value; };
static inline int helper(void){return 7;}
# 1 "b.c"
int b(void){struct XjGlobals g={3}; return helper()+g.value;}
"#;
    for (other, succeeds) in [
        (second.to_owned(), true),
        // A private function can also share a name with another TU's export.
        (
            second.replace("static inline int helper", "int helper"),
            true,
        ),
        // Independent functions do not exempt shared record types from checks.
        (second.replace("int value", "long value"), false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.i");
        let b = dir.path().join("b.i");
        fs::write(&a, first).unwrap();
        fs::write(&b, other).unwrap();
        let db = dir.path().join("commands.json");
        fs::write(
            &db,
            serde_json::to_vec(&json!([
                {"directory":dir.path(), "file":a, "arguments":[clang(),a.clone()]},
                {"directory":dir.path(), "file":b, "arguments":[clang(),b.clone()]},
            ]))
            .unwrap(),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_pangs"))
            .args(["validate-source", "--source-compdb"])
            .arg(db)
            .output()
            .unwrap();
        let diagnostics = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.success(), succeeds, "{diagnostics}");
        if !succeeds {
            assert!(
                diagnostics.contains("cross-TU record mismatch"),
                "{diagnostics}"
            );
        }
    }
}

#[test]
fn cross_tu_anonymous_records_and_incomplete_arrays() {
    let declaration = "struct S { union {int a; struct {int x;} aa;}; union {int b; struct {int y;} bb;}; }; extern const int table[]; extern struct S object; int retain(void){return object.a + table[0];}";
    for (other, succeeds) in [
        (format!("{declaration} const int table[4]={{0}};"), true),
        (declaration.replace("int y", "long y"), false),
        (declaration.replace("table[]", "table[4]"), true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.i");
        let b = dir.path().join("b.i");
        fs::write(&a, declaration).unwrap();
        fs::write(&b, other).unwrap();
        let db = dir.path().join("commands.json");
        fs::write(
            &db,
            serde_json::to_vec(&json!([
                {"directory":dir.path(), "file":a, "arguments":[clang(),a.clone()]},
                {"directory":dir.path(), "file":b, "arguments":[clang(),b.clone()]},
            ]))
            .unwrap(),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_pangs"))
            .args(["validate-source", "--source-compdb"])
            .arg(db)
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            succeeds,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn external_inline_header_definition_is_not_a_local_callback_boundary() {
    let (_, m) = analyze("static int g; static int f(void){if(0) ++g; return 0;} extern inline __attribute__((gnu_inline)) int run(int(*p)(void)){return p();} int main(void){++g; return run(f);}");
    assert!(field(&m)["blockers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|b| b["kind"] == "source-external-callback:run"));
}

#[test]
fn source_retention_uses_declaration_dependencies_not_llvm_reachability() {
    let (_, m) = analyze(
        r#"
static int g = 7;
static void discarded_write(void){ ++g; }
static void discarded_root(void){ discarded_write(); }
static int never_called(void){ return ++g; }
static void cleanup(int *p){ if(0) ++g; }
static int callback(void){ return g; }
int (*exported_callback)(void) = callback;
__attribute__((used)) static int pinned(void){ return g; }
static inline int unused_inline(void){ return ++g; }
int exported(void){ return g; }
int main(void){ int x __attribute__((cleanup(cleanup))) = 0;
    if(0) return never_called(); return g; }
"#,
    );
    assert_eq!(
        m["context_rewrite"]["source"]["retained_functions"],
        json!([
            "callback",
            "cleanup",
            "exported",
            "main",
            "never_called",
            "pinned"
        ])
    );
    let pruned = m["context_rewrite"]["source"]["pruned_declarations"]
        .as_array()
        .unwrap();
    for name in ["discarded_root", "discarded_write", "unused_inline"] {
        assert!(pruned.iter().any(|d| d["name"] == name), "{pruned:#?}");
    }
}

#[test]
fn discarded_source_writers_do_not_constrain_immutable_storage() {
    let (_, m) = analyze("static int g=7; static void add(void){++g;} static void unused(void){add();} int main(void){return g;}");
    let g = m["globals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["meta"]["llvm_name"] == "g")
        .unwrap();
    assert_eq!(g["facts"]["written"]["value"], false);
    assert!(g["facts"]["source_obligations"]["observations"]
        .as_array()
        .unwrap()
        .iter()
        .all(|o| o["kind"] == "read"));
    assert_eq!(g["disposition"]["chosen"], "immutable");
}

#[test]
fn emitter_folded_syntax_does_not_retain_writers_or_leave_dangling_c_references() {
    let original = r#"
static int g=7;
static int discarded(void){return ++g;}
int main(void){
    __typeof__(discarded()) x=0;
    int a[sizeof(discarded())];
    int untouched[2 * sizeof(int)];
    enum { N=sizeof(discarded()) };
    struct Width { unsigned n:sizeof(discarded()); };
    int y __attribute__((aligned(sizeof(discarded()))))=0;
    return _Generic(g++, int: g, default: discarded()) + x + y + sizeof(a) + sizeof(untouched) + N
        + __builtin_types_compatible_p(__typeof__(discarded()), int);
}
"#;
    for retained_write in [false, true] {
        let code = if retained_write {
            original.replace("return _Generic", "if(0) g=9; return _Generic")
        } else {
            original.to_owned()
        };
        let (dir, m) = analyze(&code);
        assert_eq!(
            m["context_rewrite"]["source"]["retained_functions"],
            json!(["main"])
        );
        let g = m["globals"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["meta"]["llvm_name"] == "g")
            .unwrap();
        assert_eq!(g["facts"]["written"]["value"], false);
        assert_eq!(
            g["disposition"]["chosen"],
            if retained_write {
                "localize"
            } else {
                "immutable"
            },
            "{g:#}"
        );
        let f = field(&m);
        assert_eq!(f["blockers"], json!([]), "{f:#}");
        let mut edits: Vec<pangs_manifest::SourceEdit> =
            serde_json::from_value(f["source_edits"].clone()).unwrap();
        edits.sort_by_key(|e| std::cmp::Reverse(e.start));
        let mut rewritten = code;
        for edit in edits {
            rewritten.replace_range(edit.start..edit.end, &edit.replacement);
        }
        assert!(!rewritten.contains("discarded"), "{rewritten}");
        assert!(!rewritten.contains("_Generic"), "{rewritten}");
        assert!(
            rewritten.contains("untouched[2 * sizeof(int)]"),
            "{rewritten}"
        );
        let source = dir.path().join("normalized.i");
        fs::write(&source, rewritten).unwrap();
        let check = Command::new(clang())
            .args(["-x", "c", "-fsyntax-only"])
            .arg(source)
            .output()
            .unwrap();
        assert!(
            check.status.success(),
            "{}",
            String::from_utf8_lossy(&check.stderr)
        );
    }
}

#[test]
fn localization_preserves_unaffected_constant_array_bounds() {
    let code = "typedef __SIZE_TYPE__ size_t; struct File { char unused2[15 * sizeof(int) - 4 * sizeof(void *) - sizeof(size_t)]; }; static int unrelated(void){return 1;} static int g; int main(void){struct File f; return ++g + sizeof(f);}";
    let (_, m) = analyze(code);
    let f = field(&m);
    assert_eq!(f["blockers"], json!([]), "{f:#}");
    assert!(
        f["source_edits"]
            .as_array()
            .unwrap()
            .iter()
            .all(|edit| edit["kind"] != "prune-expression"),
        "{f:#}"
    );
    let mut edits: Vec<pangs_manifest::SourceEdit> =
        serde_json::from_value(f["source_edits"].clone()).unwrap();
    edits.sort_by_key(|edit| std::cmp::Reverse(edit.start));
    let mut rewritten = code.to_owned();
    for edit in edits {
        rewritten.replace_range(edit.start..edit.end, &edit.replacement);
    }
    assert!(
        rewritten.contains("15 * sizeof(int) - 4 * sizeof(void *) - sizeof(size_t)"),
        "{rewritten}"
    );
    assert!(rewritten.contains("unrelated(void)"), "{rewritten}");
}

#[test]
fn conditional_pruning_dependencies_do_not_join_context_functions() {
    let code = "static int g; int needs(void){return ++g;} int ordinary(void){return 0;} int folded[sizeof(needs()) + sizeof(ordinary())]; int main(void){return needs() + sizeof(folded);}";
    let (_, m) = analyze(code);
    let f = field(&m);
    assert_eq!(f["blockers"], json!([]), "{f:#}");
    assert_eq!(f["functions"], json!(["main", "needs"]), "{f:#}");
    assert!(f["source_edits"]
        .as_array()
        .unwrap()
        .iter()
        .any(|edit| edit["kind"] == "prune-expression"));
}

#[test]
fn localization_recipes_prune_unused_declaration_dependencies() {
    let code = "typedef unsigned long HeaderSize; struct HeaderRecord { HeaderSize size; }; extern void header_function(struct HeaderRecord *); static int g; typedef __typeof__(g) UnusedType; extern UnusedType unused_prototype(void); static int f(void){return ++g;} static int (*unused_slot)(void)=f; static int unused(void){return unused_slot();} int main(void){return f();}";
    let (dir, m) = analyze(code);
    let f = field(&m);
    assert_eq!(f["blockers"], json!([]), "{f:#}");
    assert_eq!(f["functions"], json!(["f", "main"]));
    let mut edits: Vec<pangs_manifest::SourceEdit> =
        serde_json::from_value(f["source_edits"].clone()).unwrap();
    assert!(edits.iter().any(|e| e.kind == "prune-declaration"));
    edits.sort_by_key(|e| std::cmp::Reverse(e.start));
    let mut rewritten = code.to_owned();
    for edit in edits {
        rewritten.replace_range(edit.start..edit.end, &edit.replacement);
    }
    rewritten.insert_str(0, "struct XjGlobals;\n");
    assert!(!rewritten.contains("unused"), "{rewritten}");
    assert!(!rewritten.contains("UnusedType"), "{rewritten}");
    assert!(rewritten.contains("typedef unsigned long HeaderSize;"));
    assert!(rewritten.contains("struct HeaderRecord { HeaderSize size; };"));
    assert!(rewritten.contains("extern void header_function(struct HeaderRecord *);"));
    let source = dir.path().join("pruned.i");
    fs::write(&source, rewritten).unwrap();
    let check = Command::new(clang())
        .args([
            "-x",
            "c",
            "-fsyntax-only",
            "-Werror=incompatible-function-pointer-types",
        ])
        .arg(source)
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn source_representation_guards_cover_pointer_reads_writes_and_initializers() {
    for (code, chosen, guard) in [
        (
            "static int g=7; int main(void){int *p=&g; return *p;}",
            "immutable",
            None,
        ),
        (
            "static int g=7; int main(void){return g+sizeof(++g);}",
            "immutable",
            None,
        ),
        (
            "static int g=7; int main(void){if(0) g=9; return g;}",
            "localize",
            Some("source-retained-assignment"),
        ),
        (
            "static int g=7; int main(void){if(0) (void)sizeof(int[++g]); return g;}",
            "localize",
            Some("source-retained-assignment"),
        ),
        (
            "static char *g[2]={\"a\",\"b\"}; int main(int n,char **v){return g[n&1][0];}",
            "localize",
            Some("source-default-type-not-sync"),
        ),
        (
            "static unsigned g=1u+2u; int main(void){return g;}",
            "localize",
            Some("source-section-initializer"),
        ),
        (
            "static int g=7,h=8; int main(void){if(0)g=9; return g+h;}",
            "unhandled",
            Some("source-retained-assignment"),
        ),
    ] {
        let (_, m) = analyze(code);
        let g = m["globals"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["meta"]["llvm_name"] == "g")
            .unwrap();
        assert_eq!(g["facts"]["written"]["value"], false, "{code}: {g:#}");
        assert_eq!(g["disposition"]["chosen"], chosen, "{code}: {g:#}");
        if let Some(guard) = guard {
            assert!(
                g["disposition"]["cascade_trace"]
                    .to_string()
                    .contains(guard),
                "{g:#}"
            );
        }
    }
}

#[test]
fn pruning_embedded_tags_has_nonoverlapping_edits_and_preserves_retained_tags() {
    let code = "static int g; typedef __typeof__(g) register_t __attribute__((__mode__(__word__))); typedef struct { int unused:sizeof(g); } Unused; typedef struct Retained { int x; } UnusedAlias; int main(void){struct Retained r={1}; return ++g+r.x;}";
    let (dir, m) = analyze(code);
    assert_eq!(field(&m)["blockers"], json!([]), "{m:#}");
    let plan: pangs_manifest::ContextRewriteField =
        serde_json::from_value(field(&m).clone()).unwrap();
    let mut edits = pangs_manifest::compose_source_edits(&[plan]).unwrap();
    edits.sort_by_key(|e| std::cmp::Reverse(e.start));
    let mut rewritten = code.to_owned();
    for edit in edits {
        rewritten.replace_range(edit.start..edit.end, &edit.replacement);
    }
    assert!(!rewritten.contains("} Unused;"));
    assert!(!rewritten.contains("__attribute__"));
    assert!(rewritten.contains("struct Retained { int x; }"));
    let source = dir.path().join("pruned.c");
    fs::write(&source, rewritten).unwrap();
    let check = Command::new(clang())
        .args(["-fsyntax-only"])
        .arg(source)
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
}
