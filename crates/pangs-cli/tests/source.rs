use serde_json::{json, Value};
use std::{fs, path::PathBuf, process::Command};
use tempfile::TempDir;

fn clang() -> PathBuf {
    PathBuf::from(std::env::var("LLVM_SYS_140_PREFIX").expect("LLVM 14 prefix")).join("bin/clang")
}

fn analyze(code: &str) -> (TempDir, Value) {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("test.i");
    let bc = dir.path().join("test.bc");
    fs::write(&source, code).unwrap();
    let output = Command::new(clang())
        .args(["-x", "c", "-g", "-O0", "-c", "-emit-llvm"])
        .arg(&source)
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
    fs::write(
        &db,
        serde_json::to_vec(&json!([{
            "directory": dir.path(), "file": source,
            "arguments": [clang(), PathBuf::from("-x"), PathBuf::from("c"), source.clone()]
        }]))
        .unwrap(),
    )
    .unwrap();
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
fn source_only_indirect_chain_closes_all_producers_and_compiles() {
    let code = "static int g;\nstatic int needs(void){return ++g;}\nstatic int ordinary(void){return 2;}\nstruct Ops { int (*fn)(void); };\nstatic struct Ops ops = {needs};\nstatic int dead(void){ ops.fn = ordinary; return ops.fn(); }\nint main(void){if(0) return dead(); return needs();}\n";
    let (dir, m) = analyze(code);
    let f = field(&m);
    assert_eq!(f["blockers"], json!([]), "{f:#}");
    assert_eq!(f["functions"], json!(["dead", "main", "needs", "ordinary"]));
    assert_eq!(m["context_rewrite"]["source"]["version"], 1);
    let mut edits: Vec<pangs_manifest::SourceEdit> =
        serde_json::from_value(f["source_edits"].clone()).unwrap();
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
fn source_boundaries_and_initializers_block_even_when_ir_elides_them() {
    for (extra, expected) in [
        ("extern int atexit(void (*)(void)); static void cb(void){if(0)++g;} static void unused(void){atexit(cb);}", "source-external-callback:atexit"),
        ("static int *p=&g; static int unused(void){return *p;}", "source-static-initializer-dependency"),
        ("static void cb(void){if(0)++g;} static void unused(void){((void (*)(int))cb)(1);}", "source-callable-cast"),
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
fn dead_write_is_representation_evidence_not_runtime_write() {
    let (_, m) =
        analyze("static int g=7; static void dead(void){if(0)++g;} int main(void){return g;}");
    let g = m["globals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["meta"]["llvm_name"] == "g")
        .unwrap();
    assert_eq!(g["facts"]["written"]["value"], false);
    assert_eq!(
        g["facts"]["source_representation"]["requires_mutable_storage"],
        true
    );
}

#[test]
fn retained_function_static_initializer_and_lifecycle_entry_are_blockers() {
    for (body, expected) in [
        ("static void dead(void){static int *p=&g; (void)p;}", "source-static-initializer-dependency"),
        ("__attribute__((constructor)) static void startup(void){if(0)++g;}", "source-lifecycle-or-opaque-entry"),
        ("static int xjg;", "source-context-name-collision"),
        ("static int f(void){return ++g;} static int (*choose(void))(void){return f;} static int dead(void){return choose()();}", "source-callable-return-type"),
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
fn read_only_array_selection_does_not_require_mutable_rust_storage() {
    let (_, m) =
        analyze("static int g[2]={1,2}; int main(int argc,char **argv){return (g)[argc&1];}");
    let g = m["globals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["meta"]["llvm_name"] == "g")
        .unwrap();
    assert_eq!(
        g["facts"]["source_representation"]["requires_mutable_storage"],
        false
    );
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
fn cross_tu_and_parse_failures_are_fatal_without_an_accepted_plan() {
    for (second, succeeds) in [
        ("int f(int x){return x;}", true),
        ("long f(long x){return x;}", false),
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
fn cross_tu_anonymous_records_and_incomplete_arrays() {
    let declaration = "struct S { union {int a; struct {int x;} aa;}; union {int b; struct {int y;} bb;}; }; extern const int table[];";
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
