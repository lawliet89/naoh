#[macro_use]
extern crate clap;
extern crate sodiumoxide;

use std::fs::File;
use std::io;
use std::io::prelude::*;

use clap::{Arg, App, AppSettings, SubCommand, ArgMatches};
use sodiumoxide::crypto::secretbox;

fn main() {
    let args = make_parser().get_matches();
    let result = match args.subcommand() {
        ("gen-key", Some(args)) => gen_key(args.value_of("output")),
        ("gen-nonce", Some(args)) => gen_nonce(args.value_of("output")),
        _ => Err("Unknown command".to_string()),
    };

    std::process::exit(match result {
        Ok(()) => 0,
        Err(e) => {
            println!("Error: {}", e);
            1
        }
    });
}

/// Make a command line parser for options
fn make_parser<'a, 'b>() -> App<'a, 'b>
where
    'a: 'b,
{
    let encrypt = SubCommand::with_name("encrypt").about("Encrypt a file with the provided key");
    let decrypt = SubCommand::with_name("decrypt").about("Decrypt a file with the provided key");
    let gen_key = SubCommand::with_name("gen-key").about(
        "Generate a key for use with encryption or decryption",
    );
    let gen_nonce = SubCommand::with_name("gen-nonce").about(
        "Generate a nonce for use with encryption or decryption",
    );

    App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .setting(AppSettings::SubcommandRequired)
        .setting(AppSettings::VersionlessSubcommands)
        .setting(AppSettings::PropagateGlobalValuesDown)
        .global_setting(AppSettings::DontCollapseArgsInUsage)
        .about(
            "Encrypt or decrypt a file based on `crypto_secretbox_xsalsa20poly1305`,\
            a particular combination of Salsa20 and Poly1305 specified in Cryptography in NaCl \
            (http://nacl.cr.yp.to/valid.html).",
        )
        .arg(
            Arg::with_name("output")
                .help(
                    "Specify a path to output to. Defaults to STDOUT Existing files will be \
                     truncated. \
                     Use `-` to refer to STDOUT",
                )
                .short("o")
                .long("output")
                .takes_value(true)
                .global(true),
        )
        .arg(
            Arg::with_name("input")
                .help(
                    "Input file to read from. Defaults to STDIN. \
                    Use `-` to refer to STDIN",
                )
                .short("i")
                .long("input")
                .takes_value(true)
                .global(true),
        )
        .subcommand(encrypt)
        .subcommand(decrypt)
        .subcommand(gen_key)
        .subcommand(gen_nonce)
}

fn gen_key(output: Option<&str>) -> Result<(), String> {
    let mut writer = output_writer(output.unwrap_or_else(|| "-"))?;
    let key = secretbox::gen_key();
    writer.write_all(&key.0).map_err(|e| e.to_string())?;
    Ok(())
}

fn gen_nonce(output: Option<&str>) -> Result<(), String> {
    let mut writer = output_writer(output.unwrap_or_else(|| "-"))?;
    let nonce = secretbox::gen_nonce();
    writer.write_all(&nonce.0).map_err(|e| e.to_string())?;
    Ok(())
}

/// Gets a `Read` depending on the path. If the path is `-`, read from STDIN
fn input_reader(path: &str) -> Result<Box<Read>, String> {
    match path {
        "-" => Ok(Box::new(io::stdin())),
        path => {
            let file = File::open(path).map_err(
                |e| format!("Cannot open input file: {}", e),
            )?;
            Ok(Box::new(file))
        }
    }
}

/// Gets a `Write` depending on the path. If the path is `-`, write to STDOUT
fn output_writer(path: &str) -> Result<Box<Write>, String> {
    match path {
        "-" => Ok(Box::new(io::stdout())),
        path => {
            let file = File::create(path).map_err(|e| {
                format!("Cannot open output file: {}", e)
            })?;
            Ok(Box::new(file))
        }
    }
}

/// Returns whether a string is a dash "-"
fn is_dash(s: &str) -> bool {
    s == "-"
}