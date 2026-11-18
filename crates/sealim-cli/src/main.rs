mod cmd_inspect;
mod cmd_keygen;
mod cmd_register;
mod cmd_seal;
mod cmd_verify;
mod decode;
mod exit;
mod keys;
mod output;
mod passphrase;
mod qr_input;
mod qrimg;
mod registry;
mod trustout;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use sealim_core::PAYLOAD_VERSION;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "sealim",
    about = "Seal certificates and transcripts with signed QR codes",
    disable_version_flag = true,
    after_help = "Exit codes (verify):\n  0  VALID or VALID_CLAIMS_ONLY\n  1  any other verification result\n  2  usage, I/O, or trust file error\n\nTrust file default: SEALIM_TRUST_FILE environment variable."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate an encrypted issuer key and trust entry
    Keygen {
        #[arg(long, required = true)]
        name: String,

        #[arg(long, required = true)]
        out: PathBuf,

        #[arg(long)]
        passphrase_file: Option<PathBuf>,

        #[arg(long)]
        trust_out: Option<PathBuf>,

        #[arg(long)]
        valid_from: Option<String>,

        #[arg(long)]
        valid_until: Option<String>,

        #[arg(long)]
        force: bool,

        #[arg(long)]
        json: bool,
    },

    /// Sign a document and emit QR text (and optional images)
    Seal {
        #[arg(long, required = true)]
        key: PathBuf,

        #[arg(long)]
        passphrase_file: Option<PathBuf>,

        #[arg(long, required = true)]
        file: PathBuf,

        #[arg(long = "claim", value_name = "KEY=VALUE")]
        claims: Vec<String>,

        #[arg(long)]
        png: Option<PathBuf>,

        #[arg(long)]
        svg: Option<PathBuf>,

        #[arg(long)]
        qr_text: Option<PathBuf>,

        #[arg(long)]
        doc_id: Option<String>,

        #[arg(long)]
        issued_at: Option<u64>,

        #[arg(long)]
        registry: bool,
    },

    /// Verify a QR payload against a trust file and optional document
    Verify {
        #[arg(long, conflicts_with_all = ["qr_file", "image"])]
        qr: Option<String>,

        #[arg(long, conflicts_with_all = ["qr", "image"])]
        qr_file: Option<PathBuf>,

        #[arg(long, conflicts_with_all = ["qr", "qr_file"])]
        image: Option<PathBuf>,

        #[arg(long)]
        file: Option<PathBuf>,

        #[arg(long)]
        trust: Option<PathBuf>,

        #[arg(long)]
        json: bool,

        #[arg(long, env = "SEALIM_REGISTRY_URL")]
        registry: Option<String>,
    },

    /// Register a sealed document with a status registry
    Register {
        #[arg(long, required = true)]
        key: PathBuf,

        #[arg(long)]
        passphrase_file: Option<PathBuf>,

        #[arg(long, conflicts_with_all = ["qr_file", "image"])]
        qr: Option<String>,

        #[arg(long, conflicts_with_all = ["qr", "image"])]
        qr_file: Option<PathBuf>,

        #[arg(long, conflicts_with_all = ["qr", "qr_file"])]
        image: Option<PathBuf>,

        #[arg(long, env = "SEALIM_REGISTRY_URL")]
        registry: Option<String>,
    },

    /// Decode a QR payload without verification
    Inspect {
        #[arg(long, conflicts_with_all = ["qr_file", "image"])]
        qr: Option<String>,

        #[arg(long, conflicts_with_all = ["qr", "image"])]
        qr_file: Option<PathBuf>,

        #[arg(long, conflicts_with_all = ["qr", "qr_file"])]
        image: Option<PathBuf>,

        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("-V") | Some("--version") => {
            if print_version().is_err() {
                return ExitCode::from(2);
            }
            return ExitCode::SUCCESS;
        }
        Some("-h") | Some("--help") if args.len() == 2 => {
            let _ = Cli::command().print_help();
            return ExitCode::SUCCESS;
        }
        _ => {}
    }

    let cli = Cli::parse();

    let Some(command) = cli.command else {
        let _ = Cli::command().print_help();
        return ExitCode::SUCCESS;
    };

    match run_command(command) {
        Ok(code) => code,
        Err(err) => {
            match &err {
                exit::CliError::Usage(msg) | exit::CliError::Io(msg) | exit::CliError::Key(msg) => {
                    eprintln!("error: {msg}");
                }
                exit::CliError::Verify(_) => {}
            }
            exit::exit_code_for_error(&err)
        }
    }
}

fn run_command(command: Commands) -> Result<ExitCode, exit::CliError> {
    match command {
        Commands::Keygen {
            name,
            out,
            passphrase_file,
            trust_out,
            valid_from,
            valid_until,
            force,
            json,
        } => {
            cmd_keygen::run(cmd_keygen::KeygenOptions {
                name,
                out,
                passphrase_file,
                trust_out,
                valid_from,
                valid_until,
                force,
                json,
            })?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Seal {
            key,
            passphrase_file,
            file,
            claims,
            png,
            svg,
            qr_text,
            doc_id,
            issued_at,
            registry,
        } => {
            cmd_seal::run(cmd_seal::SealOptions {
                key,
                passphrase_file,
                file,
                claims,
                png,
                svg,
                qr_text,
                doc_id,
                issued_at,
                registry,
            })?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Verify {
            qr,
            qr_file,
            image,
            file,
            trust,
            json,
            registry,
        } => {
            let code = cmd_verify::run(cmd_verify::VerifyOptions {
                qr,
                qr_file,
                image,
                file,
                trust,
                json,
                registry,
            })?;
            Ok(exit::exit_code_for_result(code))
        }
        Commands::Inspect {
            qr,
            qr_file,
            image,
            json,
        } => {
            cmd_inspect::run(cmd_inspect::InspectOptions {
                qr,
                qr_file,
                image,
                json,
            })?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Register {
            key,
            passphrase_file,
            qr,
            qr_file,
            image,
            registry,
        } => {
            let code = cmd_register::run(cmd_register::RegisterOptions {
                key,
                passphrase_file,
                qr,
                qr_file,
                image,
                registry,
            })?;
            Ok(ExitCode::from(code as u8))
        }
    }
}

fn print_version() -> std::io::Result<()> {
    use std::io::Write;
    writeln!(
        std::io::stdout(),
        "sealim {VERSION} (payload format v{PAYLOAD_VERSION})"
    )
}
