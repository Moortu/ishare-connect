use anyhow::Context;
use core::str;
use http::Extensions;
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use josekit::{jwe::{RSA_OAEP_256, JweHeader}, jwt::{self, JwtPayload}};
use openssl::{
    pkcs12::ParsedPkcs12_2,
    pkey::{PKey, Private},
    x509::X509,
};
use reqwest::{Request, Response};
use reqwest_middleware::{ClientBuilder, Middleware, Next};
use reqwest_retry::{
    policies::ExponentialBackoff, RetryTransientMiddleware, Retryable, RetryableStrategy,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{collections::HashMap, time::UNIX_EPOCH};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    pub roles: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceAccess {
    pub account: Account,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IshareClaims {
    iss: String,
    pub sub: String,
    pub aud: String,
    jti: String,
    pub exp: u64,
    pub iat: u64,
    #[serde(skip_deserializing)]
    nbf: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IshareClaimsWithExtra<ExtraClaims> {
    #[serde(flatten)]
    pub ishare_claims: IshareClaims,

    #[serde(flatten)]
    pub extra: ExtraClaims,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RealmAccess {
    pub roles: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserinfoClaims {
    iss: String,
    pub sub: String,
    pub aud: String,
    pub realm_access: RealmAccess,
    pub company_id: String,
}

fn parse_private_key(pkey: &PKey<Private>) -> Result<String, IshareError> {
    let private_key =
        String::from_utf8(pkey.private_key_to_pem_pkcs8().map_err(|e| IshareError {
            message: e.to_string(),
        })?)
        .map_err(|e| IshareError {
            message: e.to_string(),
        })?;

    let mut result = "".to_owned();
    let splitted: Vec<&str> = private_key.split('\n').collect();

    for (idx, part) in splitted.iter().enumerate() {
        if idx == splitted.len() - 2 {
            result += "\n";
        }
        result += part;
        if idx == 0 {
            result += "\n";
        }
    }

    return Ok(result.to_owned());
}

fn parse_certicate(pem: Vec<u8>) -> Result<String, IshareError> {
    let certificate = String::from_utf8(pem)
        .map_err(|e| IshareError {
            message: e.to_string(),
        })?
        .replace("-----BEGIN CERTIFICATE-----\n", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace("\n", "");

    Ok(certificate)
}

fn _parse_serial_number(cert: &X509) -> Result<String, IshareError> {
    let sub = cert
        .subject_name()
        .entries()
        .find(|x| x.object().to_string() == "serialNumber")
        .ok_or(IshareError {
            message: "Can't find serial number in subject".to_owned(),
        })?
        .data()
        .as_utf8()
        .map_err(|e| IshareError {
            message: e.to_string(),
        })?
        .to_string();

    Ok(sub)
}

#[derive(Deserialize)]
struct PartyResponse {
    party_token: String,
}

#[derive(Deserialize)]
struct CapabilitiesReponse {
    capabilities_token: String,
}

#[derive(Deserialize)]
struct PartiesResponse {
    parties_token: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SupportedVersion {
    pub version: String,
    pub supported_features: Vec<SupportedFeatures>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SupportedFeature {
    pub id: String,
    pub feature: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    pub description: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SupportedFeatures {
    Public(Vec<SupportedFeature>),
    Restricted(Vec<SupportedFeature>),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Role {
    pub role: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CapabilitiesInfo {
    pub party_id: String,
    pub ishare_roles: Vec<Role>,
    pub supported_versions: Vec<SupportedVersion>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Capabilities {
    pub capabilities_info: CapabilitiesInfo,
}

#[derive(Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub expires_in: i64,
}

#[derive(Debug, Clone)]
pub struct IshareError {
    pub message: String,
}

impl std::fmt::Display for IshareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for IshareError {}

pub struct ISHARE {
    client_cert: ParsedPkcs12_2,
    ishare_cert: Option<X509>,
    satellite_url: String,
    client_eori: String,
    pub sattelite_eori: String,
}

impl std::fmt::Debug for ISHARE {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", "ISHARE")
    }
}

struct RetryOnError;
impl RetryableStrategy for RetryOnError {
    fn handle(&self, res: &reqwest_middleware::Result<reqwest::Response>) -> Option<Retryable> {
        match res {
            Ok(res) if res.status().is_success() => None,
            Ok(_res) => Some(Retryable::Transient),
            Err(_error) => Some(Retryable::Transient),
        }
    }
}

struct LoggingMiddleware;

#[async_trait::async_trait]
impl Middleware for LoggingMiddleware {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        let res = next.run(req, extensions).await;

        match &res {
            Ok(res) if res.status().is_success() => {
                tracing::info!("Request finished: status [{}]", res.status())
            }
            Ok(res) => {
                tracing::error!("Request finished: status [{}]", res.status())
            }
            Err(err) => {
                tracing::error!("Request finished with error [{:?}]", err)
            }
        }

        res
    }
}

impl ISHARE {
    pub fn new(
        client_cert_path: String,
        client_cert_pass: String,
        satellite_url: String,
        ishare_cert_path: Option<String>,
        client_eori: String,
        satellite_eori: String,
    ) -> Result<Self, IshareError> {
        let _provider = openssl::provider::Provider::try_load(None, "legacy", true).unwrap();

        let client_cert_content = std::fs::read(client_cert_path).unwrap();
        let pkcs12 = openssl::pkcs12::Pkcs12::from_der(&client_cert_content).unwrap();
        let client_cert = pkcs12.parse2(&client_cert_pass).unwrap();

        let ishare_cert = match ishare_cert_path {
            Some(path) => {
                let ishare_cert_content = std::fs::read(path).map_err(|e| IshareError {
                    message: e.to_string(),
                })?;

                Some(
                    X509::from_pem(&ishare_cert_content).map_err(|e| IshareError {
                        message: e.to_string(),
                    })?,
                )
            }
            None => None,
        };

        return Ok(Self {
            client_cert,
            ishare_cert,
            satellite_url,
            client_eori,
            sattelite_eori: satellite_eori,
        });
    }

    pub fn get_client_eori(&self) -> String {
        return self.client_eori.clone();
    }

    #[tracing::instrument(skip(client_assertion))]
    pub async fn get_satelite_access_token(
        &self,
        client_assertion: &str,
    ) -> Result<LoginResponse, IshareError> {
        let form_data = vec![
            ("grant_type", "client_credentials"),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("scope", "iSHARE"),
            ("client_id", &self.client_eori),
            ("client_assertion", client_assertion),
        ];

        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(5);
        let ret_s =
            RetryTransientMiddleware::new_with_policy_and_strategy(retry_policy, RetryOnError);

        let client = ClientBuilder::new(reqwest::Client::new())
            .with(ret_s)
            .with(LoggingMiddleware)
            .build();

        let response = client
            .post(format!("{}/connect/token", self.satellite_url))
            .form(&form_data)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?;

        let bytes = response.bytes().await.unwrap();
        let body = serde_json::from_slice::<LoginResponse>(&bytes).map_err(|e| IshareError {
            message: e.to_string(),
        })?;

        return Ok(body);
    }

    pub async fn get_all_parties(
        &self,
        satellite_access_token: &str,
        role: Option<&str>,
        active_only: Option<bool>,
    ) -> anyhow::Result<PartiesInfo> {
        let mut url = url::Url::parse(&format!("{}/parties", self.satellite_url))?;

        if let Some(role) = role {
            url.query_pairs_mut().append_pair("role", role);
        }

        if let Some(active_only) = active_only {
            url.query_pairs_mut()
                .append_pair("active_only", &active_only.to_string());
        }

        let formatted_url = url.to_string();

        let response = reqwest::Client::new()
            .get(&formatted_url)
            .header(
                "Authorization",
                format!("Bearer {}", &satellite_access_token),
            )
            .send()
            .await
            .context(format!("Error fetching parties at {}", &formatted_url))?;

        let json = response
            .json::<PartiesResponse>()
            .await
            .context("Error deserializing response from parties endpoint")?;

        if !(self
            .validate_token(&json.parties_token)
            .context("Error validating parties token")?)
        {
            return Err(anyhow::anyhow!("Party token is invalid"));
        }

        let mut validation = Validation::new(Algorithm::RS256);

        let first_x5c = ISHARE::get_first_x5c(&json.parties_token)
            .context("Error retrieving x5c from party token")?;

        validation.set_audience(&[&self.client_eori]);
        let decoding_key =
            &DecodingKey::from_rsa_pem(&first_x5c.to_pem().context("Error converting x5c to pem")?)
                .context("Error creating decoding key from rsa pem")?;

        validation.set_audience(&[&self.client_eori]);

        let decoded = decode::<PartiesToken>(&json.parties_token, &decoding_key, &validation)
            .context("Error decoding party token".to_owned())?;

        return Ok(decoded.claims.parties_info);
    }

    pub async fn parties(
        &self,
        caller_client_id: &str,
        satellite_access_token: &str,
    ) -> anyhow::Result<String> {
        let url = format!("{}/parties/{}", self.satellite_url, caller_client_id);

        let response = reqwest::Client::new()
            .get(&url)
            .header(
                "Authorization",
                format!("Bearer {}", &satellite_access_token),
            )
            .send()
            .await
            .context(format!("Error fetching parties at {}", &url))?;

        let json = response
            .json::<PartyResponse>()
            .await
            .context("Error deserializing response from parties endpoint")?;

        return Ok(json.party_token);
    }

    fn create_ishare_header(&self) -> Result<Header, IshareError> {
        let cert = self.client_cert.cert.as_ref().unwrap();

        let mut certs = vec![parse_certicate(cert.to_pem().map_err(|e| {
            IshareError {
                message: e.to_string(),
            }
        })?)?];

        for ca in self
            .client_cert
            .ca
            .as_ref()
            .ok_or({
                IshareError {
                    message: "Unexpected error".to_owned(),
                }
            })?
            .iter()
        {
            certs.push(parse_certicate(ca.to_pem().map_err(|e| IshareError {
                message: e.to_string(),
            })?)?);
        }

        let header = Header {
            typ: Some("JWT".to_owned()),
            x5c: Some(certs),
            alg: Algorithm::RS256,
            ..Default::default()
        };

        return Ok(header);
    }

    fn get_encoding_key(&self) -> Result<EncodingKey, IshareError> {
        let private_key =
            parse_private_key(self.client_cert.pkey.as_ref().ok_or(IshareError {
                message: "unable to find client certificate".to_owned(),
            })?)?;

        let encoding_key = EncodingKey::from_rsa_pem(private_key.as_bytes()).unwrap();

        return Ok(encoding_key);
    }

    fn create_ishare_claims(
        &self,
        target_id: String,
        client_id: &String,
    ) -> Result<IshareClaims, IshareError> {
        let iat = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .as_secs();

        let claims = IshareClaims {
            iss: client_id.clone(),
            aud: target_id.to_owned(),
            sub: client_id.clone(),
            iat,
            nbf: iat,
            exp: iat + 30,
            jti: uuid::Uuid::new_v4().to_string(),
        };

        return Ok(claims);
    }

    pub fn create_client_assertion(&self, target_id: String) -> Result<String, IshareError> {
        let header = self.create_ishare_header()?;
        let claims = self.create_ishare_claims(target_id, &self.client_eori)?;
        let encoding_key = self.get_encoding_key()?;
        let token = encode(&header, &claims, &encoding_key).unwrap();

        return Ok(token);
    }

    pub fn create_client_assertion_with_extra_claims<T: Serialize>(
        &self,
        target_id: String,
        extra_claims: T,
    ) -> Result<String, IshareError> {
        let header = self.create_ishare_header()?;
        let ishare_claims = self.create_ishare_claims(target_id, &self.client_eori)?;
        let encoding_key = self.get_encoding_key()?;

        let claims = IshareClaimsWithExtra {
            ishare_claims,

            extra: extra_claims,
        };

        let token = encode(&header, &claims, &encoding_key).unwrap();

        return Ok(token);
    }

    pub fn create_client_assertion_with_extra_claims_encrypted<T: Serialize>(
        &self,
        target_id: String,
        extra_claims: T,
        idp_cert: &Certificate,
    ) -> Result<String, IshareError> {
        let header = self.create_ishare_header()?;
        let ishare_claims = self.create_ishare_claims(target_id, &self.client_eori)?;

        let claims = IshareClaimsWithExtra {
            ishare_claims,
            extra: extra_claims,
        };        

        let header_str = serde_json::to_string(&header).map_err(|e| IshareError {
            message: e.to_string()
        })?;
        let claims_str = serde_json::to_string(&claims).map_err(|e| IshareError {
            message: e.to_string()
        })?;

        let header_map: HashMap<&str, Value> = serde_json::from_str(&header_str).map_err(|e| IshareError {
            message: e.to_string()
        })?;
        let claims_map: HashMap<&str, Value> = serde_json::from_str(&claims_str).map_err(|e| IshareError {
            message: e.to_string()
        })?;

        
        let mut jwe_header = JweHeader::new();
        for claim in header_map {
            let _ = jwe_header.set_claim(claim.0, Some(claim.1.clone()));
        }
        //https://crates.io/crates/josekit
        
        jwe_header.set_content_encryption("A128CBC-HS256");
        
        let mut jwe_payload = JwtPayload::new();
        for claim in claims_map {
            let _ = jwe_payload.set_claim(claim.0, Some(claim.1.clone()));
        }

        let cert = openssl::x509::X509::from_pem(
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                idp_cert.x5c
            )
            .as_bytes(),
        ).map_err(|e| IshareError {
            message: e.to_string()
        })?;

        let public_key = cert.public_key().map_err(|e| IshareError {
            message: e.to_string()
        })?;
        let pkey_bytes = public_key.public_key_to_pem().map_err(|e| IshareError {
            message: e.to_string()
        })?;

        let encrypter = RSA_OAEP_256.encrypter_from_pem(&pkey_bytes).map_err(|e| IshareError {
            message: e.to_string()
        })?;
        let jwk: String = jwt::encode_with_encrypter(&jwe_payload, &jwe_header, &encrypter).map_err(|e| IshareError {
            message: e.to_string()
        })?;
        
        return Ok(jwk);

        /* 
        
        let mut jws_header = JwsHeader::new();
        for claim in header_map {
            let _ = jws_header.set_claim(claim.0, Some(claim.1.clone()));
        }
        let private_key =
            parse_private_key(self.client_cert.pkey.as_ref().ok_or(IshareError {
                message: "unable to find client certificate".to_owned(),
            })?)?;

        let signer = RS256.signer_from_pem(&private_key.as_bytes()).unwrap();
        let jwt = jwt::encode_with_signer(&jwe_payload, &jwe_header, &signer).unwrap();
        */
    }

    fn get_first_x5c(token: &str) -> Result<X509, GetFirstX5CError> {
        let header = jsonwebtoken::decode_header(&token).context("Error decoding header")?;

        let x5c = match header.x5c {
            Some(x5c) => x5c,
            None => return Err(GetFirstX5CError::MissingX5CHeader),
        };

        let cert = openssl::x509::X509::from_pem(
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                x5c[0]
            )
            .as_bytes(),
        )
        .context("Error creating certificate from pem")?;

        return Ok(cert);
    }

    pub fn validate_token(&self, token: &String) -> Result<bool, ValidateTokenError> {
        let ishare_cert = self
            .ishare_cert
            .as_ref()
            .context("Error dereferencing ishare_cert")?;

        let cert = ISHARE::get_first_x5c(token)?;

        let public_key = ishare_cert
            .public_key()
            .context("Error getting public key")?;

        if !cert
            .verify(&public_key)
            .context("Error verifying certificate with public key")?
        {
            return Ok(false);
        }

        return Ok(true);
    }

    pub async fn get_public_capabilities(&self, url: &str) -> anyhow::Result<CapabilitiesInfo> {
        let response = reqwest::get(url)
            .await
            .context(format!("Error retrieving capabilities at: {}", url))?;

        let json = response
            .json::<CapabilitiesReponse>()
            .await
            .context("Error deserializing response from parties endpoint")?;

        if !(self
            .validate_token(&json.capabilities_token)
            .context("Error validating capabilities token")?)
        {
            return Err(anyhow::anyhow!("Capabilities token is not valid"));
        }

        let mut validation = Validation::new(Algorithm::RS256);

        let first_x5c = ISHARE::get_first_x5c(&json.capabilities_token)
            .context("Error retrieving x5c from capabilities token")?;

        validation.set_audience(&[&self.client_eori]);
        let decoding_key =
            &DecodingKey::from_rsa_pem(&first_x5c.to_pem().context("Error converting x5c to pem")?)
                .context("Error creating decoding key from rsa pem")?;

        validation.set_audience(&[&self.client_eori]);

        let decoded =
            decode::<Capabilities>(&json.capabilities_token, &decoding_key, &validation).unwrap();

        return Ok(decoded.claims.capabilities_info);
    }

    pub fn decode_token(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        token: &str,
        client_id: &str,
        audience: Option<&str>,
    ) -> Result<TokenData<IshareClaims>, DecodeTokenError> {
        let mut validation = Validation::new(Algorithm::RS256);

        let audience = match audience {
            None => &self.client_eori,
            Some(aud) => aud,
        };

        validation.set_audience(&[audience]);
        let first_x5c = ISHARE::get_first_x5c(token)?;
        let decoding_key =
            &DecodingKey::from_rsa_pem(&first_x5c.to_pem().context("Error converting x5c to pem")?)
                .context("Error creating decoding key from rsa pem")?;

        let decoded = decode::<IshareClaims>(&token, decoding_key, &validation)?;

        match decoded.header.typ {
            None => return Err(DecodeTokenError::MissingTypHeader),
            Some(t) if t != "JWT" => return Err(DecodeTokenError::InvalidTypeHeader),
            Some(_) => {}
        }

        if decoded.claims.exp != (decoded.claims.iat + 30) {
            return Err(DecodeTokenError::ExpNotIatPlus30);
        }

        if decoded.claims.iat
            > now
                .timestamp()
                .try_into()
                .context("error converting timestamp to i64")?
        {
            return Err(DecodeTokenError::IatAfterNow);
        }

        if decoded.claims.iss != client_id {
            return Err(DecodeTokenError::IssDoesntMatchClientId);
        }

        if decoded.claims.sub != decoded.claims.iss {
            return Err(DecodeTokenError::SubDoesNotMatchIss);
        }

        Ok(decoded)
    }

    pub fn decode_token_custom_claims<CustomClaims: DeserializeOwned>(
        &self,
        token: &str,
        audience: Option<&str>,
    ) -> Result<TokenData<IshareClaimsWithExtra<CustomClaims>>, DecodeTokenError> {
        let mut validation = Validation::new(Algorithm::RS256);

        match audience {
            Some(aud) => validation.set_audience(&[aud]),
            None => validation.set_audience(&[&self.client_eori]),
        }

        let first_x5c = ISHARE::get_first_x5c(token)?;
        let decoding_key =
            &DecodingKey::from_rsa_pem(&first_x5c.to_pem().context("Error converting x5c to pem")?)
                .context("Error creating decoding key from rsa pem")?;

        let decoded =
            decode::<IshareClaimsWithExtra<CustomClaims>>(&token, decoding_key, &validation)?;

        Ok(decoded)
    }

    pub fn validate_party_certificate(
        &self,
        client_assertion_token: &TokenData<IshareClaims>,
        party_info: &PartyInfo,
    ) -> anyhow::Result<bool> {
        let client_cert = match client_assertion_token.header.x5c.clone() {
            Some(x) => x[0].clone(),
            None => return Err(anyhow::anyhow!("missing x5c header")),
        };

        let certificates = match &party_info.certificates_or_spor {
            CertificatesOrSpor::Spor(_) => return Err(anyhow::anyhow!("cannot validate party certificate for SPOR")),
            CertificatesOrSpor::Certificates(cert) => cert,
        };

        if !certificates
            .iter()
            .any(|c| &c.x5c == &client_cert)
        {
            return Ok(false);
        }

        return Ok(true);
    }

    pub async fn validate_party(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        client_id: &str,
        satellite_access_token: &str,
    ) -> Result<PartyInfo, ValidatePartyError> {
        let encoded_party_token = self
            .parties(client_id, satellite_access_token)
            .await
            .context("Error fetching ishare parties information")?;

        if !(self
            .validate_token(&encoded_party_token)
            .context("Error validating parties token")?)
        {
            return Err(ValidatePartyError::Unexpected(anyhow::anyhow!(
                "Party token is invalid"
            )));
        }

        let mut validation = Validation::new(Algorithm::RS256);

        let first_x5c = ISHARE::get_first_x5c(&encoded_party_token)
            .context("Error retrieving x5c from party token")?;

        validation.set_audience(&[&self.client_eori]);
        let decoding_key =
            &DecodingKey::from_rsa_pem(&first_x5c.to_pem().context("Error converting x5c to pem")?)
                .context("Error creating decoding key from rsa pem")?;

        validation.set_audience(&[&self.client_eori]);

        let decoded = decode::<PartyToken>(&encoded_party_token, &decoding_key, &validation)
            .context("Error decoding party token".to_owned())?;

        match decoded.claims.party_info {
            PartyInfoOption::Empty {} => Err(ValidatePartyError::NotFound(client_id.to_owned())),
            PartyInfoOption::PartyInfo(party_info) if party_info.adherence.status != "Active" => {
                Err(ValidatePartyError::Inactive(client_id.to_owned()))
            }
            PartyInfoOption::PartyInfo(party_info) => {
                let end_date = chrono::DateTime::parse_from_rfc3339(&party_info.adherence.end_date)
                    .context(format!(
                        "Error parsing adherence end date {}",
                        &party_info.adherence.end_date
                    ))?;

                if now > end_date {
                    tracing::warn!("end_date of adherence is expired");
                }

                Ok(party_info)
            }
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum GetFirstX5CError {
    #[error("x5c is missing from header")]
    MissingX5CHeader,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum ValidatePartyError {
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
    #[error("The ishare party {0} is currently not active")]
    Inactive(String),
    #[error("The ishare party {0} does not seem to exist")]
    NotFound(String),
    #[error("adherence is not active anymore")]
    AdherenceExpired,
}

#[derive(thiserror::Error, Debug)]
pub enum ValidateTokenError {
    #[error(transparent)]
    GetFirstX5CError(#[from] GetFirstX5CError),
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum DecodeTokenError {
    #[error(transparent)]
    GetFirstX5CError(#[from] GetFirstX5CError),
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
    #[error(transparent)]
    DecodingError(#[from] jsonwebtoken::errors::Error),
    #[error("typ is missing from header")]
    MissingTypHeader,
    #[error("typ should be 'JWT'")]
    InvalidTypeHeader,
    #[error("exp field is not iat + 30 seconds")]
    ExpNotIatPlus30,
    #[error("iss does not match client_id")]
    IssDoesntMatchClientId,
    #[error("sub does not match iss")]
    SubDoesNotMatchIss,
    #[error("serial number not found in x5c certificate")]
    SerialNotFound,
    #[error("serial does not match client id")]
    SerialDoesntMatchClientId,
    #[error("issued at is in the future")]
    IatAfterNow,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Adherence {
    pub status: String,
    pub end_date: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Certificate {
    x5c: String,
}

#[derive(Debug, Serialize, Deserialize)]

pub struct Spor {
    signed_request: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificatesOrSpor {
    Certificates(Vec<Certificate>),
    Spor(Spor),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PartyInfo {
    pub adherence: Adherence,
    pub party_id: String,
    pub party_name: String,
    #[serde(flatten)]
    pub certificates_or_spor: CertificatesOrSpor,
    pub capability_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum PartyInfoOption {
    PartyInfo(PartyInfo),
    Empty {},
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PartyToken {
    iss: String,
    sub: String,
    aud: String,
    jti: String,
    exp: u64,
    iat: u64,
    nbf: u64,
    party_info: PartyInfoOption,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PartiesInfo {
    pub data: Vec<PartyInfo>,
    pub count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PartiesToken {
    iss: String,
    sub: String,
    aud: String,
    jti: String,
    exp: u64,
    iat: u64,
    nbf: u64,
    parties_info: PartiesInfo,
}

pub fn validate_request_arguments(
    grant_type: &str,
    client_assertion_type: &str,
    scope: &str,
) -> Result<(), String> {
    if grant_type != "client_credentials" {
        return Err("grant type should be 'client_credentials'".to_owned());
    }

    if client_assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
        return Err("client assertion type should be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'".to_owned());
    }

    if scope != "iSHARE" {
        return Err("scope should be iSHARE".to_owned());
    }

    return Ok(());
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_validate_request_arguments() {
        assert!(matches!(
            validate_request_arguments(
                "",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "iSHARE"
            ),
            Err(m) if m == "grant type should be 'client_credentials'"
        ));

        assert!(matches!(
            validate_request_arguments(
                "client_credentials",
                "",
                "iSHARE"
            ),
            Err(m) if m == "client assertion type should be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'"
        ));

        assert!(matches!(
            validate_request_arguments(
                "client_credentials",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ""
            ),
            Err(m) if m == "scope should be iSHARE"
        ));
    }
}
