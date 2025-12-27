//! Command runner utility
//! 
//! This module provides utilities for running external commands
//! with proper timeout handling and error management.

use crate::error::{AdapterError, Result};
use std::process::{Command, Output, Stdio};
use std::time::Duration;
use tokio::process::Command as AsyncCommand;

/// Command runner for external tool execution
#[derive(Debug, Clone)]
pub struct CommandRunner {
    /// Default timeout for commands
    default_timeout: Duration,
    /// Whether to run in offline mode
    offline_mode: bool,
}

impl CommandRunner {
    /// Create new command runner with configuration
    pub fn new(default_timeout: Duration, offline_mode: bool) -> Self {
        Self {
            default_timeout,
            offline_mode,
        }
    }
    
    /// Run command with default timeout
    pub async fn run(&self, command: &str, args: &[&str]) -> Result<Output> {
        self.run_with_timeout(command, args, self.default_timeout).await
    }
    
    /// Run command with custom timeout
    pub async fn run_with_timeout(&self, command: &str, args: &[&str], timeout: Duration) -> Result<Output> {
        // Check for network operations in offline mode
        if self.offline_mode && self.is_network_command(command) {
            return Err(AdapterError::NetworkTimeout {
                operation: format!("{} {}", command, args.join(" ")),
                source: anyhow::anyhow!("Network operations disabled in offline mode"),
            });
        }
        
        let mut cmd = AsyncCommand::new(command);
        cmd.args(args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        
        // Add timeout
        let output = tokio::time::timeout(timeout, cmd.output()).await
            .map_err(|_| AdapterError::ToolTimeout {
                tool: command.to_string(),
                timeout,
                source: anyhow::anyhow!("Command timed out"),
            })?;
        
        let output = output.map_err(|e| AdapterError::ToolExecutionFailed {
            tool: command.to_string(),
            exit_code: -1,
            stderr: e.to_string(),
            source: anyhow::anyhow!("Failed to execute command"),
        })?;
        
        if !output.status.success() {
            return Err(AdapterError::ToolExecutionFailed {
                tool: command.to_string(),
                exit_code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                source: anyhow::anyhow!("Command exited with non-zero status"),
            });
        }
        
        Ok(output)
    }
    
    /// Check if command is a network operation
    fn is_network_command(&self, command: &str) -> bool {
        match command {
            "curl" | "wget" | "git" | "cargo" => true,
            _ if command.starts_with("cargo ") && 
                 (command.contains("install") || command.contains("publish") || command.contains("search")) => true,
            _ => false,
        }
    }
    
    /// Run command and return stdout as string
    pub async fn run_to_string(&self, command: &str, args: &[&str]) -> Result<String> {
        let output = self.run(command, args).await?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
    
    /// Run command and return JSON parsed result
    pub async fn run_to_json<T>(&self, command: &str, args: &[&str]) -> Result<T> 
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        let output = self.run_to_string(command, args).await?;
        serde_json::from_str(&output)
            .map_err(|e| AdapterError::ToolExecutionFailed {
                tool: command.to_string(),
                exit_code: 0,
                stderr: format!("JSON parsing error: {}", e),
                source: anyhow::anyhow!("Failed to parse JSON output"),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    
    #[tokio::test]
    async fn test_command_runner_creation() {
        let runner = CommandRunner::new(Duration::from_secs(30), false);
        
        assert_eq!(runner.default_timeout, Duration::from_secs(30));
        assert!(!runner.offline_mode);
    }
    
    #[tokio::test]
    async fn test_simple_command() {
        let runner = CommandRunner::new(Duration::from_secs(5), false);
        
        // Run echo command (should work on all platforms)
        let result = runner.run("echo", &["hello"]).await;
        assert!(result.is_ok());
        
        let output = result.unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.trim().ends_with("hello"));
    }
    
    #[tokio::test]
    async fn test_command_to_string() {
        let runner = CommandRunner::new(Duration::from_secs(5), false);
        
        let result = runner.run_to_string("echo", &["world"]).await;
        assert!(result.is_ok());
        
        let output = result.unwrap();
        assert!(output.trim().ends_with("world"));
    }
    
    #[tokio::test]
    async fn test_network_command_detection() {
        let runner = CommandRunner::new(Duration::from_secs(5), true);
        
        // Test network command detection
        assert!(runner.is_network_command("curl"));
        assert!(runner.is_network_command("git"));
        assert!(runner.is_network_command("cargo install"));
        assert!(runner.is_network_command("cargo search"));
        assert!(!runner.is_network_command("echo"));
        assert!(!runner.is_network_command("ls"));
    }
    
    #[tokio::test]
    async fn test_offline_mode() {
        let runner = CommandRunner::new(Duration::from_secs(5), true);
        
        // Network command should fail in offline mode
        let result = runner.run("curl", &["http://example.com"]).await;
        assert!(result.is_err());
        
        // Non-network command should work
        let result = runner.run("echo", &["test"]).await;
        assert!(result.is_ok());
    }
    
    #[tokio::test]
    async fn test_command_timeout() {
        let runner = CommandRunner::new(Duration::from_secs(1), false);
        
        // Command that sleeps for longer than timeout
        let result = runner.run("sleep", &["5"]).await;
        assert!(result.is_err());
        
        match result.unwrap_err() {
            AdapterError::ToolTimeout { tool, timeout, .. } => {
                assert_eq!(tool, "sleep");
                assert_eq!(timeout, Duration::from_secs(1));
            },
            _ => panic!("Expected ToolTimeout error"),
        }
    }
}
