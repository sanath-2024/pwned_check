use clap::{Arg, Command};
use colored::Colorize;
use rs_password_utils::pwned::{check_pwned, PwnedResponse};

use std::{
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let matches = Command::new("pwned_check")
        .arg(
            Arg::new("password file")
                .short('f')
                .long("file")
                .takes_value(true)
                .value_name("FILE")
                .required(true),
        )
        .get_matches();

    let filepath: &String = matches.try_get_one("password file")?.unwrap();
    let file = File::open(filepath)?;
    let lines: Vec<String> = BufReader::new(file)
        .lines()
        .map(|line| line.unwrap())
        .collect();
    let mut handles = Vec::new();
    for line in &lines {
        let line_clone = line.clone();
        handles.push(tokio::spawn(
            async move { check_pwned(&line_clone[..]).await },
        ));
    }
    let mut results = Vec::new();
    for handle in handles {
        let res = handle.await?;
        results.push(res.unwrap());
    }
    for result in 0..lines.len() {
        match results[result] {
            PwnedResponse::Pwned(num) => {
                eprintln!(
                    "{}",
                    format!("password \"{}\" PWNED {} times", lines[result], num).bright_red()
                );
            }
            PwnedResponse::Ok => {
                println!("password \"{}\" ok", lines[result]);
            }
        }
    }
    Ok(())
}
