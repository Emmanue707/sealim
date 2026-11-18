use std::fs;
use std::io::{self, IsTerminal};
use std::path::Path;

use rpassword::prompt_password;
use zeroize::Zeroizing;

use crate::exit::CliError;

pub fn read_passphrase(passphrase_file: Option<&Path>) -> Result<Zeroizing<String>, CliError> {
    let pass = match passphrase_file {
        Some(path) => {
            let mut text = fs::read_to_string(path).map_err(|e| {
                CliError::usage(format!(
                    "cannot read passphrase file {}: {e}",
                    path.display()
                ))
            })?;
            if text.ends_with('\n') {
                text.pop();
                if text.ends_with('\r') {
                    text.pop();
                }
            }
            text
        }
        None => {
            if io::stdin().is_terminal() {
                let p = prompt_password("Passphrase: ")
                    .map_err(|e| CliError::usage(format!("could not read passphrase: {e}")))?;
                p
            } else {
                return Err(CliError::usage(
                    "passphrase required: use --passphrase-file or run from a terminal",
                ));
            }
        }
    };

    if pass.is_empty() {
        return Err(CliError::usage("passphrase must not be empty"));
    }

    Ok(Zeroizing::new(pass))
}
