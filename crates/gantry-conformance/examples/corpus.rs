//! Offline example runner: `cargo run -p gantry-conformance --example corpus -- PACKAGE_PATH`.
//! The shared module is also exercised by `tests/example_corpus.rs`.

mod support;

/// Runs every declared scenario and reports failures without requiring a model service.
fn main() -> Result<(), String> {
    let mut arguments = std::env::args_os().skip(1);
    let root = arguments
        .next()
        .ok_or("usage: corpus PACKAGE_PATH | --all CORPUS_ROOT")?;
    if root == "--all" {
        let directory = arguments.next().ok_or("--all requires a corpus root")?;
        if arguments.next().is_some() {
            return Err("unexpected extra argument".into());
        }
        let packages = support::discover(std::path::Path::new(&directory))?;
        if packages.is_empty() {
            return Err("no case.json packages found".into());
        }
        let mut failures = Vec::new();
        for package in packages {
            match support::run_package(&package) {
                Ok(reports) => println!("PASS {} ({} scenarios)", package.display(), reports.len()),
                Err(error) => failures.push(error),
            }
        }
        return if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("\n"))
        };
    }
    if arguments.next().is_some() {
        return Err("usage: corpus PACKAGE_PATH".into());
    }
    let reports = support::run_package(std::path::Path::new(&root))?;
    let requests: usize = reports.iter().map(|report| report.requests.len()).sum();
    println!(
        "{} scenario(s) passed, {requests} dispatches: {}",
        reports.len(),
        std::path::Path::new(&root).display()
    );
    Ok(())
}
