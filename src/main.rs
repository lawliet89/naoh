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
    let result = run_subcommand(&args);

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
    let encrypt = SubCommand::with_name("encrypt")
        .about(
            "Encrypt a file with the provided key. \
            The output will include the encrypted payload, authentication tag, and by default \
            the nonce used.",
        )
        .arg(
            Arg::with_name("use-nonce")
                .long("use-nonce")
                .help(
                    "Instead of generating a random Nonce, provide a path to a file containing \
                     the nonce. Use - to refer to STDIN",
                )
                .takes_value(true)
                .value_name("path"),
        )
        .arg(
            Arg::with_name("write-nonce")
                .long("write-nonce")
                .help(
                    "Instead of appending the nonce to the end of the encrypted payload, write to \
                     the path provided instead. Use - to refer to STDOUT",
                )
                .takes_value(true)
                .value_name("path"),
        )
        .arg(
            Arg::with_name("key")
                .help(
                    "File to read the key from. Defaults to STDIN. \
                    Use `-` to refer to STDIN",
                )
                .short("k")
                .long("key")
                .takes_value(true)
                .required(true)
                .value_name("path"),
        );
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
        .global_setting(AppSettings::NextLineHelp)
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
                .value_name("path")
                .global(true),
        )
        .subcommand(encrypt)
        .subcommand(decrypt)
        .subcommand(gen_key)
        .subcommand(gen_nonce)
}

fn run_subcommand(args: &ArgMatches) -> Result<(), String> {
    match args.subcommand() {
        ("gen-key", Some(args)) => {
            let output = args.value_of("output").unwrap_or_else(|| "-");
            let writer = output_writer(output)?;
            gen_key(writer)
        }
        ("gen-nonce", Some(args)) => {
            let output = args.value_of("output").unwrap_or_else(|| "-");
            let writer = output_writer(output)?;
            gen_nonce(writer)
        }
        ("encrypt", Some(args)) => {
            let input = args.value_of("input").or_else(|| Some("-"));
            let key = args.value_of("key").or_else(|| Some("-"));
            let output = args.value_of("output").or_else(|| Some("-"));

            let use_nonce = args.value_of("use-nonce");
            let write_nonce = args.value_of("write-nonce");

            if dash_count([key.clone(), input.clone(), use_nonce.clone()].iter()) > 1 {
                Err("Only one input source can be from STDIN")?
            }
            if dash_count([output.clone(), write_nonce.clone()].iter()) > 1 {
                Err("Only one output source can be to STDOUT")?
            }

            let input = input_reader(input.unwrap())?; // safe to unwrap
            let output = output_writer(output.unwrap())?; // safe to unwrap
            let key = input_reader(key.unwrap())?; // safe to unwrap
            let use_nonce = match use_nonce {
                None => None,
                Some(path) => Some(input_reader(path)?),
            };
            let write_nonce = match write_nonce {
                None => None,
                Some(path) => Some(output_writer(path)?),
            };
            encrypt(key, input, output, use_nonce, write_nonce)
        }
        _ => Err("Unknown command or missing options".to_string()),
    }
}

fn gen_key<W: Write>(mut writer: W) -> Result<(), String> {
    let key = secretbox::gen_key();
    writer.write_all(&key.0).map_err(|e| e.to_string())?;
    Ok(())
}

fn gen_nonce<W: Write>(mut writer: W) -> Result<(), String> {
    let nonce = secretbox::gen_nonce();
    writer.write_all(&nonce.0).map_err(|e| e.to_string())?;
    Ok(())
}

fn encrypt<R1, R2, R3, W1, W2>(
    mut key: R1,
    mut input: R2,
    mut output: W1,
    use_nonce: Option<R3>,
    write_nonce: Option<W2>,
) -> Result<(), String>
where
    R1: Read,
    R2: Read,
    R3: Read,
    W1: Write,
    W2: Write,
{
    let nonce = match use_nonce {
        Some(mut reader) => {
            let mut buffer = Vec::new();
            let _ = reader.read_to_end(&mut buffer).map_err(|e| e.to_string())?;
            secretbox::Nonce::from_slice(&buffer).ok_or_else(
                || "Incorrect length for nonce provided",
            )?
        }
        None => secretbox::gen_nonce(),
    };

    let key = {
        let mut key_bytes = Vec::new();
        let _ = key.read_to_end(&mut key_bytes).map_err(|e| e.to_string())?;
        secretbox::Key::from_slice(&key_bytes).ok_or_else(
            || "Incorrect length for key provided",
        )?
    };

    let mut payload = Vec::new();
    let _ = input.read_to_end(&mut payload).map_err(|e| e.to_string())?;

    let encrypted_payload = secretbox::seal(&payload, &nonce, &key);
    let _ = output.write_all(&encrypted_payload).map_err(
        |e| e.to_string(),
    )?;

    let _ = match write_nonce {
        None => output.write_all(&nonce.0),
        Some(mut writer) => writer.write_all(&nonce.0),
    }.map_err(|e| e.to_string())?;

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

fn dash_count<'a, S, I>(iterator: I) -> usize
where
    S: AsRef<str> + 'a,
    I: Iterator<Item = &'a Option<S>>,
{
    iterator.fold(0, |acc, item| {
        acc +
            if item.is_some() && is_dash(item.as_ref().unwrap().as_ref()) {
                1
            } else {
                0
            }
    })
}

/// Returns whether a string is a dash "-"
fn is_dash(s: &str) -> bool {
    s == "-"
}
