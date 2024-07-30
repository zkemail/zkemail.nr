use base64::{engine::general_purpose, Engine as _};
use eml_parser::{
    eml::{Eml, HeaderField, HeaderFieldValue},
    EmlParser,
};
use regex::Regex;
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts};
use rsa::{pkcs1v15::Signature, traits::PaddingScheme};
use rsa::{pkcs1v15::VerifyingKey, Pkcs1v15Encrypt, Pkcs1v15Sign};
use sha2::{Digest, Sha256};
use std::hash::Hash;
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
    let signature = parse_dkim_signature(&dkim_header.to_string());

    // print the header array
    println!("{}", make_header_string(&signed_headers));

    // print the signature and pubkey format for noir
    generate_2048_bit_signature_parameters(
        &signature,
        &public_key,
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
) {
    let sig_bytes = &Signature::try_from(signature.as_slice())
        .unwrap()
        .to_bytes();

    let sig_uint: BigUint = BigUint::from_bytes_be(sig_bytes);
    let sig_str = bn_limbs(sig_uint.clone(), 2048);
    println!(
        "let signature: BN2048 = BigNum::from_array({});",
        sig_str.as_str()
    );
    let r = bn_runtime_instance(pubkey.n().clone(), 2048, String::from("instance"));
    println!("{}", r.as_str());
}

fn parse_dkim_signature(dkim_header: &str) -> Vec<u8> {
    let b64 = extract_dkim_signature(dkim_header);
    general_purpose::STANDARD.decode(b64).unwrap()
}

fn extract_dkim_signature(dkim_header: &str) -> String {
    let re = Regex::new(r"b=([^;]+)").unwrap();
    re.captures(dkim_header)
        .and_then(|caps| caps.get(1).map(|m| clean_dkim_signature(m.as_str())))
        .unwrap()
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
    let b_index = dkim_signature.find("; b=").expect("Invalid DKIM signature format");
    let dkim_signature = String::from(&dkim_signature[..b_index + 4]); // Include the '; b=' part
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
    headers.join("\r\n").as_bytes().to_vec()
}

pub fn make_header_string(header: &Vec<u8>) -> String {
    format!("let header: [u8; {}] = {:?};", header.len(), header)
}