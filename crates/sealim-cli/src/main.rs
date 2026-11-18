use std::env;
use std::process::ExitCode;

use sealim_core::PAYLOAD_VERSION;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_version(out: &mut impl std::io::Write) -> std::io::Result<()> {
    writeln!(out, "sealim {VERSION} (payload format v{PAYLOAD_VERSION})")
}

fn print_help(out: &mut impl std::io::Write) -> std::io::Result<()> {
    writeln!(out, "Sealim — offline verification of signed QR payloads")?;
    writeln!(out)?;
    writeln!(out, "Usage:")?;
    writeln!(out, "  sealim --version    Print version information")?;
    writeln!(out, "  sealim --help       Print this help")?;
    Ok(())
}

fn main() -> ExitCode {
    let mut args = env::args();
    let _program = args.next();

    match args.next().as_deref() {
        None => {
            if print_help(&mut std::io::stdout()).is_err() {
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Some("-h") | Some("--help") => {
            if print_help(&mut std::io::stdout()).is_err() {
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Some("-V") | Some("--version") => {
            if print_version(&mut std::io::stdout()).is_err() {
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Some(unknown) => {
            eprintln!("error: unknown argument '{unknown}'");
            eprintln!("Run sealim --help for usage.");
            ExitCode::from(2)
        }
    }
}
