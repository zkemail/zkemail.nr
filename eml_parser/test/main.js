const dns = require("dns");
const forge = require("node-forge");

async function getPublicKeyForDomainAndSelector(
    domain,
    selector,
    print = true
  ) {
    // Construct the DKIM record name
    let dkimRecordName = `${selector}._domainkey.${domain}`;
    if (print) console.log(dkimRecordName);
    // Lookup the DKIM record in DNS
    let records;
    try {
      records = await dns.promises.resolveTxt(dkimRecordName);
    } catch (err) {
      if (print) console.error(err);
      return;
    }
  
    if (!records.length) {
      return;
    }
  
    // The DKIM record is a TXT record containing a string
    // We need to parse this string to get the public key
    let dkimRecord = records[0].join("");
    let match = dkimRecord.match(/p=([^;]+)/);
    if (!match) {
      console.error(`No public key found in DKIM record for ${domain}`);
      return;
    }

  
    // The public key is base64 encoded, we need to decode it
    let pubkey = match[1];
    let binaryKey = Buffer.from(pubkey, "base64").toString("base64");
    // Get match
    let matches = binaryKey.match(/.{1,64}/g);
    if (!matches) {
      console.error("No matches found");
      return;
    }
    let formattedKey = matches.join("\n");
  
    // Convert to PEM format
    let pemKey = `-----BEGIN PUBLIC KEY-----\n${formattedKey}\n-----END PUBLIC KEY-----`;
  
    console.log("PEM Key: ", pemKey);

    // Parse the RSA public key
    let publicKey = forge.pki.publicKeyFromPem(pemKey);
  
    // Get the modulus n only
    let n = publicKey.n;
    if (print) console.log("Modulus n:", n.toString(16));
  
    return BigInt(publicKey.n.toString());
  }

const main = () => {
    getPublicKeyForDomainAndSelector("gmail.com", "20230601", true);
}

main();