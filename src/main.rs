use std::convert::Infallible;
use std::fs::OpenOptions;
use std::str::FromStr;
use std::time::{SystemTimeError,SystemTime,UNIX_EPOCH,Duration};
use std::thread;
use std::io::prelude::*;
use std::io::stdout;
use std::process;
use std::env::current_exe;
use totp_rs::{Algorithm, Secret, TOTP};
use colored::*;
use crossterm::{cursor,QueueableCommand};
use crossterm::terminal::{Clear,ClearType};
use magic_crypt::{new_magic_crypt,MagicCryptTrait,MagicCrypt256};
use inquire::{Select,Password,PasswordDisplayMode,Text,validator::Validation};

const DB_NAME: &str = "oxideauth.db";

struct TotpEntry {
    name: String,
    secret: String,
}

impl FromStr for TotpEntry {
    type Err = Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (name, secret) = s.split_once(":").unwrap();
        Ok(TotpEntry {
            name: name.parse()?,
            secret: secret.parse()?,
        })
    }
}

fn read_from_enc_file(mc: &MagicCrypt256) -> Vec<u8> {
    let mut dbpath = current_exe().unwrap();
    dbpath.set_file_name(DB_NAME);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(dbpath)
        .unwrap();
    let mut data: Vec<u8> = Vec::new();
    file.read_to_end(&mut data).unwrap();

    //se o data estiver vazio aka acabou de ser criado retorna ele vazio e não tenta decriptar
    //senão que iria acusar senha errada e fechar
    if data.is_empty() {
        return data;
    }

    match mc.decrypt_bytes_to_bytes(&data) {
        Ok(bytes) => {
            return bytes;
        }
        Err(_) => {
            println!("{}","Senha errada !".bright_red());
            process::exit(1);
        }
    }
}

fn write_to_enc_file(mc: &MagicCrypt256,data: Vec<u8>) {
    let mut dbpath = current_exe().unwrap();
    dbpath.set_file_name(DB_NAME);
    let mut file = OpenOptions::new()
        .write(true)
        .open(dbpath)
        .expect("Falha ao abrir oxideauth.db");
    
    let enc_data = mc.encrypt_bytes_to_bytes(&data);

    file.write(&enc_data).expect("Falha ao escrever oxideauth.db");
}

fn time_remaining() -> u64 {
    30-(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()%30)
}

fn generate_totp_code(key: String) -> Result<String, SystemTimeError> {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(key).to_bytes().unwrap(),
    )
    .expect("Erro ao criar TOTP struct")
    .generate_current()
}

fn add_totp_to_db() {
    let validator = |input: &str| {
        if input.contains(":") {
            return Ok(Validation::Invalid("\":\" é um caracter inválido !".into()));
        }
        return Ok(Validation::Valid);
    };
    let name = Text::new("Digite o nome para a TOTP:")
        .with_validator(validator)
        .prompt()
        .unwrap();
    let key = Text::new("Digite o secret da TOTP:")
        .with_help_message("Somente SHA1 é suportado")
        .prompt()
        .unwrap();

    let pw = Password::new("Digite a senha para a database:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_help_message("Ctrl+r para mostrar")
        .with_display_toggle_enabled()
        .without_confirmation()
        .prompt()
        .unwrap();
    
    let mc = new_magic_crypt!(pw,256);
    let mut data = read_from_enc_file(&mc);
    
    data.write(format!("{}:{}\n",name,key).as_bytes()).unwrap();
    write_to_enc_file(&mc, data);
    println!("{} TOTP Salva com sucesso !",">".bright_green());
}

fn show_db() {
    let pw = Password::new("Digite a senha para a database:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_help_message("Ctrl+r para mostrar")
        .with_display_toggle_enabled()
        .without_confirmation()
        .prompt()
        .unwrap();
    
    let mc = new_magic_crypt!(pw,256);
    let data = read_from_enc_file(&mc);
    let entryes: Vec<TotpEntry> = String::from_utf8(data).unwrap().lines().map(|f|f.parse().unwrap()).collect();
    
    if entryes.is_empty() {
        println!("{}","A database está vazia !".bright_red());
        process::exit(1)
    }

    stdout()
        .queue(cursor::MoveTo(0,0)).unwrap()
        .queue(Clear(ClearType::FromCursorDown)).unwrap();

    loop {
        stdout().queue(cursor::SavePosition).unwrap();
        for key in &entryes {
            stdout().write(format!("{} : {}\n",key.name.bright_green(),generate_totp_code(key.secret.to_owned()).expect("Falha ao gerar TOTP").bright_red()).as_bytes()).unwrap();
        }
        loop {
            let remaining = time_remaining();
            stdout().write(format!("\rTempo restante: {} segundos... ",remaining.to_string().bright_red().bold()).as_bytes()).unwrap();
            stdout().flush().unwrap();
            thread::sleep(Duration::from_secs(1));
            if remaining == 1 {
                stdout().queue(cursor::RestorePosition).unwrap();
                stdout().flush().unwrap();
                break
            } 
        }
    }
}

fn main() {
    stdout()
        .queue(cursor::MoveTo(0,0)).unwrap()
        .queue(Clear(ClearType::FromCursorDown)).unwrap();
    
    let sel = Select::new("",vec!["Ver TOTP's","Adicionar TOTP"])
        .with_help_message("↑↓ para mover")    
        .prompt();
    match sel {
        Ok("Ver TOTP's") => {show_db()},
        Ok("Adicionar TOTP") => {add_totp_to_db()},
        _ => unreachable!()
    }
}
