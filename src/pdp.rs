use crate::delegation_evidence::{
    build_filter_delegation_request, verify_delegation_evidence, DelegationEvidence,
    DelegationTarget, Environment, Policy, Resource, ResourceRules, ResourceTarget,
};
use crate::ishare;

use super::delegation_request::{build_simple_delegation_request, DelegationRequestContainer};
use super::ishare::{IshareClaimsWithExtra, IshareError, ISHARE};
use base64::prelude::*;

use chrono::Utc;
use jsonwebtoken::TokenData;
use reqwest::header::AUTHORIZATION;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const YEAR_SECONDS: i64 = 31556926;

#[derive(Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub expires_in: i64,
}

#[derive(Deserialize)]
pub struct DelegationTokenResponse {
    delegation_token: String,
}

pub struct PDP<'a> {
    ishare: &'a ISHARE,
    eori: String,
    url: String,
}

#[derive(Deserialize)]
struct DelegationTokenClaims {
    #[serde(rename = "delegationEvidence")]
    pub delegation_evidence: DelegationEvidence,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicySetInsert {
    policy_issuer: String,
    licences: Vec<String>,
    max_delegation_depth: i32,
    target: DelegationTarget,
    policies: Vec<Policy>,
}

#[derive(Deserialize)]
pub struct PolicySetInsertResponse {
    pub uuid: Uuid,
}

impl<'a> PDP<'a> {
    pub fn new(ishare: &'a ISHARE, eori: String, url: String) -> PDP<'a> {
        return Self { ishare, eori, url };
    }

    pub async fn authorize(
        &self,
        access_token: &str,
        action: &str,
        access_subject: &str,
        policy_issuer: &str,
        resource_type: &str,
        identifiers: Option<Vec<String>>,
        attributes: Option<Vec<String>>,
    ) -> Result<bool, IshareError> {
        let delegation_request = self.create_delegation_request(
            action,
            access_subject,
            policy_issuer,
            resource_type,
            identifiers,
            attributes,
        );

        let delegation_token = self.call_pdp(access_token, &delegation_request).await?;

        return self
            .check_delegation_token(&delegation_token, resource_type)
            .map_err(|e| IshareError {
                message: format!("{:?}", e),
            });
    }

    fn check_delegation_token(
        &self,
        delegation_token: &str,
        resource_type: &str,
    ) -> Result<bool, ishare::DecodeTokenError> {
        let decoded: TokenData<IshareClaimsWithExtra<DelegationTokenClaims>> =
            self.ishare
                .decode_token_custom_claims::<DelegationTokenClaims>(delegation_token, None)?;

        let de = decoded.claims.extra.delegation_evidence;

        let authorized = verify_delegation_evidence(&de, resource_type.to_string());

        return Ok(authorized);
    }

    async fn call_pdp(
        &self,
        access_token: &str,
        delegation_request: &DelegationRequestContainer,
    ) -> Result<String, IshareError> {
        let target_url = format!("{}/delegation", self.url);

        let response = reqwest::Client::new()
            .post(target_url)
            .header("Authorization", format!("Bearer {access_token}"))
            .json(delegation_request)
            .send()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .error_for_status()
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .json::<DelegationTokenResponse>()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?;

        Ok(response.delegation_token)
    }

    pub async fn put_policy_set(
        &self,
        access_token: &str,
        policy_issuer: &str,
        access_subject: &str,
        service_provider: &str,
        resource_type: String,
        actions: Vec<String>,
        identifiers: Option<Vec<String>>,
    ) -> Result<PolicySetInsertResponse, IshareError> {
        let target_url = format!("{}/policy-set", self.url);

        let actual_identifiers = match identifiers {
            None => vec!["*".to_owned()],
            Some(id) => id,
        };

        let actual_attributes = vec!["*".to_owned()];

        let service_providers = vec![service_provider.to_owned()];

        let new_policy = Policy {
            rules: vec![ResourceRules {
                effect: "Permit".to_owned(),
            }],
            target: ResourceTarget {
                actions,
                resource: Resource {
                    resource_type,
                    identifiers: actual_identifiers,
                    attributes: actual_attributes,
                },
                environment: Some(Environment { service_providers }),
            },
        };

        let policy_set = PolicySetInsert {
            policy_issuer: policy_issuer.to_owned(),
            licences: vec!["ISHARE.0001".to_owned()],
            max_delegation_depth: 1,
            policies: vec![new_policy],
            target: DelegationTarget {
                access_subject: access_subject.to_owned(),
            },
        };

        let response = reqwest::Client::new()
            .post(target_url)
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&policy_set)
            .send()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .error_for_status()
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .json::<PolicySetInsertResponse>()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?;

        Ok(response)
    }

    pub async fn remove_policy_set(
        &self,
        access_token: &str,
        policy_set_id: &str,
    ) -> Result<(), IshareError> {
        let target_url = format!("{}/policy-set/{}", self.url, policy_set_id);

        reqwest::Client::new()
            .delete(target_url)
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .error_for_status()
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?;

        Ok(())
    }

    pub async fn put_policy_filter(
        &self,
        access_token: &str,
        policy_issuer: &str,
        access_subject: &str,
        service_provider: &str,
        resource_type: String,
        actions: Vec<String>,
        identifiers: Vec<String>,
    ) -> Result<DelegationEvidence, IshareError> {
        let target_url = format!("{}/ar/policy", self.url);
        let policies_delegation_response = self
            .get_policies(&access_token, policy_issuer, access_subject)
            .await?;

        let policies = match policies_delegation_response {
            Some(de) => de.policy_sets.get(0).map_or(vec![], |p| p.policies.clone()),
            None => vec![],
        };

        let now = Utc::now().timestamp();
        let delegation_request = build_filter_delegation_request(
            now,
            now + YEAR_SECONDS,
            policy_issuer.to_owned(),
            access_subject.to_owned(),
            resource_type,
            service_provider.to_owned(),
            actions,
            identifiers,
            vec!["*".to_owned()],
            policies,
        );

        let response = reqwest::Client::new()
            .post(target_url)
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&delegation_request)
            .send()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .error_for_status()
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .json::<DelegationEvidence>()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?;

        Ok(response)
    }

    async fn get_policies(
        &self,
        access_token: &str,
        issuer: &str,
        access_subject: &str,
    ) -> Result<Option<DelegationEvidence>, IshareError> {
        let target_url = format!(
            "{}/ar/policy?issuer={issuer}&access_subject={access_subject}",
            self.url
        );
        let response = reqwest::Client::new()
            .get(target_url)
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let result = response
            .error_for_status()
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .json::<DelegationEvidence>()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?;

        return Ok(Some(result));
    }

    fn create_delegation_request(
        &self,
        action: &str,
        access_subject: &str,
        policy_issuer: &str,
        resource_type: &str,
        identifiers: Option<Vec<String>>,
        attributes: Option<Vec<String>>,
    ) -> DelegationRequestContainer {
        let service_provider = self.ishare.get_client_eori();
        let actions = vec![action.to_string()];

        let delegation_request = build_simple_delegation_request(
            policy_issuer.to_string(),
            access_subject.to_string(),
            resource_type.to_string(),
            service_provider,
            actions,
            identifiers,
            attributes,
        );

        delegation_request
    }

    pub async fn connect_admin(
        &self,
        admin_username: &str,
        admin_password: &str,
        pdp_app_id: &str,
        pdp_app_secret: &str,
    ) -> Result<LoginResponse, IshareError> {
        let form_data = vec![
            ("grant_type", "password"),
            ("username", admin_username),
            ("password", admin_password),
        ];

        let target_url = format!("{}/oauth2/token", self.url);
        let basic_auth = base64::engine::general_purpose::STANDARD
            .encode(format!("{pdp_app_id}:{pdp_app_secret}"));

        let response = reqwest::Client::new()
            .post(target_url)
            .form(&form_data)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, format!("Basic {basic_auth}"))
            .send()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .error_for_status()
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .json::<LoginResponse>()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?;

        return Ok(response);
    }

    pub async fn connect(&self) -> Result<LoginResponse, IshareError> {
        let client_assertion = self.ishare.create_client_assertion(self.eori.clone())?;

        let client_id = self.ishare.get_client_eori();

        let form_data = vec![
            ("grant_type", "client_credentials"),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("scope", "iSHARE"),
            ("client_id", &client_id),
            ("client_assertion", &client_assertion),
        ];

        let target_url = format!("{}/connect/machine/token", self.url);

        let response = reqwest::Client::new()
            .post(target_url)
            .form(&form_data)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .error_for_status()
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .json::<LoginResponse>()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?;

        return Ok(response);
    }
}
