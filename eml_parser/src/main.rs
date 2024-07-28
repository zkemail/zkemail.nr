use base64::{engine::general_purpose, Engine as _};
use eml_parser::{
    eml::{Eml, HeaderFieldValue},
    EmlParser,
};
use regex::Regex;
use rsa::pkcs1v15::VerifyingKey;
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts};
use rsa::{pkcs1v15::Signature, traits::PaddingScheme};
use sha2::Sha256;
use trust_dns_resolver::{config::*, Resolver};

use noir_bignum_paramgen::{bn_limbs, bn_runtime_instance};
use num_bigint::BigUint;
use rsa::RsaPublicKey;
use std::error::Error;

#[derive(Clone, Debug)]
struct DkimHeader {
    selector: Option<String>,
    domain: Option<String>,
    body_hash: Option<String>,
    signature: Option<String>,
}

fn main() {
    // load email from fs
    let eml = get_demo_eml();

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

    // Print the noir format
    generate_2048_bit_signature_parameters(
        &general_purpose::STANDARD
            .decode(parsed_header.signature.as_ref().unwrap())
            .unwrap(),
        &public_key,
        &general_purpose::STANDARD
            .decode(parsed_header.body_hash.as_ref().unwrap())
            .unwrap(),
    );
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
    let bh_regex = Regex::new(r"bh=([^;]+);").unwrap();
    let b_regex = Regex::new(r"b=([^;]+)").unwrap();
    let s_regex = Regex::new(r"s=([^;]+);").unwrap();
    let d_regex = Regex::new(r"d=([^;]+);").unwrap();
    let s = s_regex
        .captures(&value)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()));

    let d = d_regex
        .captures(&value)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()));

    let bh = bh_regex
        .captures(&value)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()));
    let b = b_regex.captures(&value).and_then(|caps| {
        caps.get(1)
            .map(|m| m.as_str().replace("\r\n", "").replace(" ", ""))
    });

    DkimHeader {
        selector: s,
        domain: d,
        body_hash: bh,
        signature: b,
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

fn extract_public_key(dkim_record: &str) -> Option<Vec<u8>> {
    let re = Regex::new(r"p=([^;]+)").unwrap();
    if let Some(caps) = re.captures(dkim_record) {
        if let Some(pubkey_b64) = caps.get(1) {
            let pubkey_str = pubkey_b64.as_str();
            println!("pubkey_str: {:?}", pubkey_str);
            if let Ok(pubkey_bytes) = general_purpose::STANDARD.decode(pubkey_str) {
                return Some(pubkey_bytes);
            } else {
                println!(" Failed");
            }
        }
    }
    None
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

pub fn generate_2048_bit_signature_parameters(
    signature: &Vec<u8>,
    pubkey: &RsaPublicKey,
    body_hash: &Vec<u8>,
) {
    let sig_bytes = &Signature::try_from(signature.as_slice())
        .unwrap()
        .to_bytes();

    let sig_uint: BigUint = BigUint::from_bytes_be(sig_bytes);

    let mut hash = body_hash.clone();
    hash.reverse();
    let sig_str = bn_limbs(sig_uint.clone(), 2048);
    println!("let body_hash: [u8; 32] = {:?};", hash);
    println!(
        "let signature: BNInstance = BigNum::from_array({});",
        sig_str.as_str()
    );
    let r = bn_runtime_instance(pubkey.n().clone(), 2048, String::from("BNInstance"));
    println!("{}", r.as_str());
}

pub fn try_verify_signature(
    pubkey: &RsaPublicKey,
    signature: &Vec<u8>,
    body_hash: &Vec<u8>,
) -> bool {
    let verified = pubkey.verify(
        Pkcs {
            hash: Some(&Sha256::default()),
        },
        &body_hash,
        &signature,
    );
    false
}
