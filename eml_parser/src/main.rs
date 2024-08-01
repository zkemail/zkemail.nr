use base64::{engine::general_purpose, Engine as _};
use eml_parser::{
    eml::{Eml, HeaderFieldValue},
    EmlParser,
};
use noir_bignum_paramgen::{bn_limbs, redc_limbs};
use num_bigint::BigUint;
use regex::Regex;
use rsa::RsaPublicKey;
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts};
use std::error::Error;
use std::fs::write;
use trust_dns_resolver::Resolver;

const MAX_ADDRESS_LOCAL_LENGTH: usize = 64;

#[derive(Clone, Debug)]
struct DkimHeader {
    selector: Option<String>,
    domain: Option<String>,
    body_hash: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RelaxedHeaders {
    from: String,
    content_type: String,
    mime_version: String,
    subject: String,
    message_id: String,
    date: String,
    to: String,
    dkim_signature: String,
}

fn main() {
    // load email from fs
    let eml = get_demo_eml();

    // Parse out the headers of the email
    let relaxed_headers = build_relaxed_headers(&eml);
    let signed_headers = to_signed_headers(&relaxed_headers);

    // Extract the DKIM-Signature header from the email
    let dkim_header = &eml
        .headers
        .iter()
        .find(|header| header.name == "DKIM-Signature")
        .unwrap()
        .value;

    // Parse the needed fields
    let parsed_header = parse_dkim_header(dkim_header);

    // Query the DNS for the DKIM public key
    let dkim_record = query_dkim_public_key(
        parsed_header.selector.as_ref().unwrap().as_str(),
        parsed_header.domain.as_ref().unwrap().as_str(),
    );

    // Extract the public key from the DKIM record
    let pem_key = extract_and_format_dkim_public_key(&dkim_record).unwrap();
    let public_key = RsaPublicKey::from_public_key_pem(&pem_key).unwrap();

    // extract signature
    let signature = extract_dkim_signature(&dkim_header.to_string());

    // find the body hash index
    let body_hash = parsed_header
        .body_hash
        .as_ref()
        .unwrap()
        .as_bytes()
        .to_vec();
    let body_hash_index = find_body_hash_index(&signed_headers, &body_hash);

    // get the body
    let mut body = eml.body.clone().unwrap().as_bytes().to_vec();
    fix_body_newlines(&mut body);

    // get the padded recipient address local part + length
    let (padded_recipient_local, recipient_local_len) = get_padded_recipient_local(&eml);

    // build the prover.toml file
    build_prover_toml(
        &signed_headers,
        &body,
        body_hash_index,
        &signature,
        &public_key,
        &padded_recipient_local,
        recipient_local_len,
    );

    // print lengths
    println!(
        "global EMAIL_HEADER_LENGTH: u32 = {};",
        signed_headers.len()
    );
    println!("global EMAIL_BODY_LENGTH: u32 = {};", body.len());
}

fn get_demo_eml() -> Eml {
    let current_dir = std::env::current_dir().unwrap();
    let filepath = current_dir.join("src").join("demo.eml");
    EmlParser::from_file(filepath.to_str().unwrap())
        .unwrap()
        .parse()
        .unwrap()
}

fn parse_dkim_header(dkim_header: &HeaderFieldValue) -> DkimHeader {
    let value = dkim_header.to_string();
    let regex_str = r"=([^;]+);";
    let bh_regex = Regex::new(&format!("bh{}", regex_str)).unwrap();
    let s_regex = Regex::new(&format!("s{}", regex_str)).unwrap();
    let d_regex = Regex::new(&format!("d{}", regex_str)).unwrap();
    let s = s_regex
        .captures(&value)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()));
    let d = d_regex
        .captures(&value)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()));

    let bh = bh_regex
        .captures(&value)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()));
    // let b = b_regex.captures(&value).and_then(|caps| {
    //     caps.get(1)
    //         .map(|m| m.as_str().replace("\r\n", "").replace(" ", ""))
    // });

    DkimHeader {
        selector: s,
        domain: d,
        body_hash: bh,
    }
}

fn query_dkim_public_key(selector: &str, domain: &str) -> String {
    let fqdn = format!("{}._domainkey.{}", selector, domain);
    let resolver = Resolver::from_system_conf().expect("Failed to create resolver");
    let mut record: String = "".to_string();
    if let Ok(response) = resolver.txt_lookup(fqdn.as_str()) {
        for txt in response.iter() {
            for txt_part in txt.iter() {
                if let Ok(txt_str) = std::str::from_utf8(txt_part) {
                    record.push_str(txt_str);
                }
            }
        }
    };
    record
}

fn extract_and_format_dkim_public_key(dkim_record: &str) -> Result<String, Box<dyn Error>> {
    // Extract the base64-encoded public key using regex
    let re = Regex::new(r"p=([^;]+)")?;
    let caps = re
        .captures(dkim_record)
        .ok_or("No public key found in DKIM record")?;
    let pubkey_b64 = caps.get(1).ok_or("Failed to capture public key")?.as_str();

    // Format the key into lines of 64 characters each
    let formatted_key = pubkey_b64
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<&str>>()
        .join("\n");

    // Construct the PEM format key
    let pem_key = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        formatted_key
    );

    Ok(pem_key)
}

fn extract_dkim_signature(dkim_header: &str) -> Vec<u8> {
    let re = Regex::new(r"b=([^;]+)").unwrap();
    let encoded_signature = re
        .captures(dkim_header)
        .and_then(|caps| caps.get(1).map(|m| clean_dkim_signature(m.as_str())))
        .unwrap();
    general_purpose::STANDARD.decode(encoded_signature).unwrap()
}

fn clean_dkim_signature(dkim_signature: &str) -> String {
    dkim_signature.replace(&['\t', '\r', '\n', ' '][..], "")
}

pub fn build_relaxed_headers(eml: &Eml) -> RelaxedHeaders {
    let headers = &eml.headers;
    let subject = eml.subject.clone().unwrap();
    let from = headers
        .iter()
        .find(|header| header.name == "from")
        .unwrap()
        .value
        .to_string();
    let content_type = headers
        .iter()
        .find(|header| header.name == "Content-Type")
        .unwrap()
        .value
        .to_string();
    let mime_version = headers
        .iter()
        .find(|header| header.name == "Mime-Version")
        .unwrap()
        .value
        .to_string();
    let message_id = headers
        .iter()
        .find(|header| header.name == "Message-Id")
        .unwrap()
        .value
        .to_string();
    let date = headers
        .iter()
        .find(|header| header.name == "Date")
        .unwrap()
        .value
        .to_string();
    let to = headers
        .iter()
        .find(|header| header.name == "to")
        .unwrap()
        .value
        .to_string();
    let dkim_signature = headers
        .iter()
        .find(|header| header.name == "DKIM-Signature")
        .unwrap()
        .value
        .to_string();
    // remove signature from dkim field
    let patterns = ["; b=", ";\n\tb="];
    let result = patterns
        .iter()
        .enumerate() // Add the index of the pattern
        .filter_map(|(pattern_index, &pattern)| {
            dkim_signature
                .find(pattern)
                .map(|index| (pattern_index, index))
        })
        .min_by_key(|&(_, index)| index);

    let (b_index, offset) = match result {
        Some((offset, b_index)) => (b_index, offset),
        None => panic!("Failed to find the signature in the DKIM-Signature header"),
    };
    let dkim_signature = String::from(&dkim_signature[..b_index + 4 + offset]); // Include the '; b=' part
    return RelaxedHeaders {
        from,
        content_type,
        mime_version,
        subject,
        message_id,
        date,
        to,
        dkim_signature,
    };
}

pub fn to_signed_headers(relaxed_headers: &RelaxedHeaders) -> Vec<u8> {
    let headers = vec![
        format!("from:{}", relaxed_headers.from.clone()),
        format!("content-type:{}", relaxed_headers.content_type.clone()),
        format!("mime-version:{}", relaxed_headers.mime_version.clone()),
        format!("subject:{}", relaxed_headers.subject.clone()),
        format!("message-id:{}", relaxed_headers.message_id.clone()),
        format!("date:{}", relaxed_headers.date.clone()),
        format!("to:{}", relaxed_headers.to.clone()),
        format!("dkim-signature:{}", relaxed_headers.dkim_signature.clone()),
    ];
    let header_str = headers.join("\r\n");
    let header_str = header_str.replace("\n\t", " ");
    header_str.as_bytes().to_vec()
}

pub fn make_header_string(header: &Vec<u8>) -> String {
    format!("let header: [u8; {}] = {:?};", header.len(), header)
}

pub fn find_body_hash_index(signed_headers: &Vec<u8>, body_hash: &Vec<u8>) -> u32 {
    signed_headers
        .windows(body_hash.len())
        .position(|window| window == body_hash)
        .unwrap() as u32
}

fn fix_body_newlines(bytes: &mut Vec<u8>) {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x0A {
            if i == 0 || bytes[i - 1] != 0x0D {
                // Insert 0x0D before 0x0A
                bytes.insert(i, 0x0D);
                i += 1; // Move past the inserted 0x0D
            }
        }
        i += 1;
    }
    bytes.append(&mut vec![0x0D, 0x0A]);
    let mut index = bytes.len() - 2;
    let mut found = true;
    while found {
        if bytes[index] == 0x0D && bytes[index + 1] == 0x0A {
            index -= 2;
        } else {
            found = false;
        }
    }
    bytes.truncate(index + 4);
}

pub fn build_prover_toml(
    header: &Vec<u8>,
    body: &Vec<u8>,
    body_hash_index: u32,
    signature: &Vec<u8>,
    public_key: &RsaPublicKey,
    padded_recipient_local: &Vec<u8>,
    recipient_local_len: u32,
) {
    // make the body_hash_index value
    let body_hash_index = format!("body_hash_index = {}", body_hash_index);
    // make the header value
    let header = format!("header = {:?}", header);
    // make the body value
    let body = format!("body = {:?}", body);
    // make the pubkey_modulus value
    let pubkey_modulus = format!(
        "pubkey_modulus_limbs = {}",
        quote_hex(bn_limbs(public_key.n().clone(), 2048))
    );
    // make the reduction parameter for the pubkey
    let redc_params = format!(
        "redc_params_limbs = {}",
        quote_hex(redc_limbs(public_key.n().clone(), 2048))
    );
    // make the recipient local part
    let padded_recipient_local = format!("padded_recipient_local = {:?}", padded_recipient_local);
    let recipient_local_len = format!("recipient_local_length = {}", recipient_local_len);
    // make the signature value
    let sig_limbs = bn_limbs(BigUint::from_bytes_be(signature), 2048);
    let signature = format!("[signature]\nlimbs = {}", quote_hex(sig_limbs));

    // format for toml content
    let toml_content = format!(
        "{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}",
        body_hash_index,
        header,
        body,
        pubkey_modulus,
        redc_params,
        padded_recipient_local,
        recipient_local_len,
        signature
    );

    // save to fs
    let current_dir = std::env::current_dir().expect("Failed to get current directory");
    let file_path = current_dir.join("..").join("Prover.toml");
    write(file_path, toml_content).expect("Failed to write to Prover.toml");
}

pub fn quote_hex(input: String) -> String {
    let hex_values: Vec<&str> = input
        .trim_matches(|c| c == '[' || c == ']')
        .split(", ")
        .collect();
    let quoted_hex_values: Vec<String> = hex_values
        .iter()
        .map(|&value| format!("\"{}\"", value))
        .collect();
    format!("[{}]", quoted_hex_values.join(", "))
}

pub fn get_padded_recipient_local(eml: &Eml) -> (Vec<u8>, u32) {
    // find the header with the recipient email address
    let recipient = eml
        .headers
        .iter()
        .find(|header| header.name == "to")
        .unwrap()
        .value
        .to_string();
    // parse out the local part of the email address
    let re = Regex::new(r"^([^@]+)@").unwrap();
    let local = re.captures(&recipient).unwrap().get(1).unwrap().as_str();
    let mut local_bytes = local.as_bytes().to_vec();
    local_bytes.resize(MAX_ADDRESS_LOCAL_LENGTH, 0);
    // let recipient = recipient.replace("<", "").replace(">", "");
    // let recipient = recipient.split("@").collect::<Vec<&str>>()[0];
    // let recipient = recipient.as_bytes();
    // let mut padded_recipient = vec![0u8; 64];
    // let recipient_len = recipient.len() as u32;
    // padded_recipient[..recipient.len()].copy_from_slice(recipient);
    // (padded_recipient, recipient_len)
    (local_bytes, local.len() as u32)
}
