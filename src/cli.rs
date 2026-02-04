//! Jawn Vault CLI - Client tool for interacting with the vault daemon
//!
//! Usage:
//!   vault-cli get <path>           Get a credential
//!   vault-cli set <path> <value>   Set a credential
//!   vault-cli list [prefix]        List credentials
//!   vault-cli health               Check daemon health
//!   vault-cli token create <name>  Create a new client token
//!   vault-cli token list           List client tokens

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use serde_json;

use jawn_vault::protocol::{Method, Params, Request, Response};

#[derive(Parser, Debug)]
#[command(name = "vault-cli")]
#[command(author, version, about = "Jawn Vault CLI client", long_about = None)]
struct Args {
    /// Path to vault socket
    #[arg(short, long, env = "VAULT_SOCKET")]
    socket: Option<PathBuf>,

    /// Authentication token
    #[arg(short, long, env = "VAULT_TOKEN")]
    token: Option<String>,

    /// Output as JSON
    #[arg(long)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Get a credential value
    Get {
        /// Path to the credential
        path: String,
    },

    /// Set a credential value
    Set {
        /// Path to the credential
        path: String,
        /// Value to set (reads from stdin if not provided)
        value: Option<String>,
    },

    /// Delete a credential
    Delete {
        /// Path to the credential
        path: String,
    },

    /// List credentials
    List {
        /// Prefix to filter by
        #[arg(default_value = "")]
        prefix: String,
    },

    /// Check daemon health
    Health,

    /// Invalidate a cache entry
    Invalidate {
        /// Path to invalidate
        path: String,
    },

    /// Token management
    Token {
        #[command(subcommand)]
        action: TokenCommand,
    },
}

#[derive(Subcommand, Debug)]
enum TokenCommand {
    /// Create a new client token
    Create {
        /// Client name
        name: String,

        /// Path patterns to grant access to (can be repeated)
        #[arg(short, long = "grant", action = clap::ArgAction::Append)]
        grants: Vec<String>,

        /// Permission level for grants (read, write, admin)
        #[arg(short, long, default_value = "read")]
        permission: String,
    },

    /// List all client tokens
    List,

    /// Revoke a client token
    Revoke {
        /// Client ID to revoke
        client_id: String,
    },
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let socket_path = args.socket.unwrap_or_else(|| {
        std::env::var("XDG_RUNTIME_DIR")
            .map(|d| PathBuf::from(d).join("jawn-vault.sock"))
            .unwrap_or_else(|_| PathBuf::from("/tmp/jawn-vault.sock"))
    });

    let token = args.token.unwrap_or_else(|| {
        // Try to read from ~/.vault-token
        let token_file = dirs::home_dir()
            .map(|h| h.join(".vault-token"))
            .unwrap_or_else(|| PathBuf::from("/home/jamditis/.vault-token"));

        std::fs::read_to_string(&token_file)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    });

    if token.is_empty() && !matches!(args.command, Command::Health) {
        eprintln!("error: no authentication token provided");
        eprintln!("set VAULT_TOKEN environment variable or use --token flag");
        std::process::exit(1);
    }

    // Handle token subcommands separately (they need direct DB access)
    if let Command::Token { action } = &args.command {
        return handle_token_command(action);
    }

    // Connect to daemon
    let mut stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to connect to vault at {}: {}", socket_path.display(), e);
            eprintln!("is the jawn-vault daemon running?");
            std::process::exit(1);
        }
    };

    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    let request = build_request(&args.command, &token)?;

    // Send request
    let request_json = serde_json::to_string(&request)? + "\n";
    stream.write_all(request_json.as_bytes())?;

    // Read response
    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line)?;

    let response: Response = serde_json::from_str(&response_line)?;

    // Handle response
    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        print_response(&args.command, &response)?;
    }

    // Exit with error code if request failed
    if response.error.is_some() {
        std::process::exit(1);
    }

    Ok(())
}

fn build_request(command: &Command, token: &str) -> anyhow::Result<Request> {
    let id = format!("cli-{}", std::process::id());

    let (method, params) = match command {
        Command::Get { path } => (
            Method::Get,
            Params {
                path: Some(path.clone()),
                ..Default::default()
            },
        ),
        Command::Set { path, value } => {
            let value = match value {
                Some(v) => v.clone(),
                None => {
                    // Read from stdin
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    input.trim().to_string()
                }
            };
            (
                Method::Set,
                Params {
                    path: Some(path.clone()),
                    value: Some(value),
                    ..Default::default()
                },
            )
        }
        Command::Delete { path } => (
            Method::Delete,
            Params {
                path: Some(path.clone()),
                ..Default::default()
            },
        ),
        Command::List { prefix } => (
            Method::List,
            Params {
                prefix: if prefix.is_empty() { None } else { Some(prefix.clone()) },
                ..Default::default()
            },
        ),
        Command::Health => (Method::Health, Params::default()),
        Command::Invalidate { path } => (
            Method::Invalidate,
            Params {
                path: Some(path.clone()),
                ..Default::default()
            },
        ),
        Command::Token { .. } => unreachable!(),
    };

    Ok(Request {
        id,
        auth: token.to_string(),
        method,
        params,
    })
}

fn print_response(command: &Command, response: &Response) -> anyhow::Result<()> {
    if let Some(error) = &response.error {
        eprintln!("error: {} ({})", error.message, format!("{:?}", error.code).to_lowercase());
        return Ok(());
    }

    match (&command, &response.result) {
        (Command::Get { .. }, Some(jawn_vault::protocol::ResponseResult::Credential(cred))) => {
            println!("{}", cred.value);
            if cred.cached {
                eprintln!("(cached until {})", cred.expires_at.map(|t| t.to_rfc3339()).unwrap_or_default());
            }
        }
        (Command::List { .. }, Some(jawn_vault::protocol::ResponseResult::List(list))) => {
            if list.paths.is_empty() {
                eprintln!("no credentials found");
            } else {
                for path in &list.paths {
                    println!("{}", path);
                }
            }
        }
        (Command::Health, Some(jawn_vault::protocol::ResponseResult::Health(health))) => {
            println!("status: {}", health.status);
            println!("uptime: {} seconds", health.uptime_seconds);
            println!("cache:");
            println!("  entries: {}", health.cache_entries);
            println!("  hits: {}", health.cache_hits);
            println!("  misses: {}", health.cache_misses);
            println!("  hit ratio: {:.1}%", health.cache_hit_ratio * 100.0);
        }
        (Command::Set { .. } | Command::Delete { .. } | Command::Invalidate { .. }, Some(jawn_vault::protocol::ResponseResult::Ok(_))) => {
            println!("ok");
        }
        _ => {
            eprintln!("unexpected response");
        }
    }

    Ok(())
}

fn handle_token_command(action: &TokenCommand) -> anyhow::Result<()> {
    use jawn_vault::auth::{Authenticator, Permission};

    let auth_db_path = dirs::data_local_dir()
        .map(|d| d.join("jawn-vault").join("auth.db"))
        .unwrap_or_else(|| PathBuf::from("/home/jamditis/.local/share/jawn-vault/auth.db"));

    let auth = Authenticator::new(&auth_db_path)?;

    match action {
        TokenCommand::Create { name, grants, permission } => {
            let perm = match permission.as_str() {
                "read" => Permission::Read,
                "write" => Permission::Write,
                "admin" => Permission::Admin,
                _ => {
                    eprintln!("error: invalid permission level (use: read, write, admin)");
                    std::process::exit(1);
                }
            };

            let grant_list: Vec<_> = grants.iter()
                .map(|g| (g.clone(), perm))
                .collect();

            if grant_list.is_empty() {
                eprintln!("error: at least one grant pattern is required");
                eprintln!("example: vault-cli token create myapp --grant 'claude/**' --permission read");
                std::process::exit(1);
            }

            let token = auth.create_client(name, &grant_list, None)?;
            println!("created client: {}", name);
            println!("token: {}", token);
            println!();
            println!("save this token securely - it cannot be retrieved later");
        }

        TokenCommand::List => {
            let clients = auth.list_clients()?;
            if clients.is_empty() {
                println!("no clients configured");
            } else {
                println!("{:<24} {:<20} {}", "ID", "NAME", "ENABLED");
                println!("{:-<24} {:-<20} {:-<8}", "", "", "");
                for (id, name, enabled) in clients {
                    let status = if enabled { "yes" } else { "no" };
                    println!("{:<24} {:<20} {}", id, name, status);
                }
            }
        }

        TokenCommand::Revoke { client_id } => {
            auth.revoke_client(client_id)?;
            println!("revoked client: {}", client_id);
        }
    }

    Ok(())
}
