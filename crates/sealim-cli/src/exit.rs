use std::process::ExitCode;

use sealim_core::ResultCode;

#[derive(Debug)]
pub enum CliError {
    Usage(String),
    Io(String),
    Key(String),
    Verify(ResultCode),
}

impl CliError {
    pub fn usage(msg: impl Into<String>) -> Self {
        Self::Usage(msg.into())
    }

    pub fn io(msg: impl Into<String>) -> Self {
        Self::Io(msg.into())
    }

    pub fn key(msg: impl Into<String>) -> Self {
        Self::Key(msg.into())
    }
}

pub fn exit_code_for_result(code: ResultCode) -> ExitCode {
    match code {
        ResultCode::Valid | ResultCode::ValidClaimsOnly => ExitCode::SUCCESS,
        _ => ExitCode::from(1),
    }
}

pub fn exit_code_for_error(err: &CliError) -> ExitCode {
    match err {
        CliError::Verify(code) => exit_code_for_result(*code),
        CliError::Usage(_) | CliError::Io(_) | CliError::Key(_) => ExitCode::from(2),
    }
}
