use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DelegationRequestContainer {
    #[serde(rename = "delegationRequest")]
    pub delegation_request: DelegationRequest,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DelegationRequest {
    pub policy_issuer: String,
    pub target: DelegationTarget,
    pub policy_sets: Vec<PolicySet>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DelegationTarget {
    pub access_subject: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicySet {
    pub policies: Vec<Policy>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub target: ResourceTarget,
    pub rules: Vec<ResourceRules>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResourceTarget {
    pub resource: Resource,
    pub actions: Vec<String>,
    pub environment: Environment,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub identifiers: Vec<String>,
    pub attributes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResourceRules {
    pub effect: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Environment {
    pub service_providers: Vec<String>,
}

pub fn build_simple_delegation_request(
    policy_issuer: String,
    access_subject: String,
    resource_type: String,
    service_provider: String,
    actions: Vec<String>,
    identifiers: Option<Vec<String>>,
    attributes: Option<Vec<String>>,
) -> DelegationRequestContainer {
    let actual_identifiers = match identifiers {
        None => vec!["*".to_owned()],
        Some(id) => id,
    };

    let actual_attributes = match attributes {
        None => vec!["*".to_owned()],
        Some(attr) => attr,
    };

    let service_providers = vec![service_provider];

    let delegation_request = DelegationRequest {
        policy_issuer,
        target: DelegationTarget { access_subject },
        policy_sets: vec![PolicySet {
            policies: vec![Policy {
                rules: vec![ResourceRules {
                    effect: "Permit".to_owned(),
                }],
                target: ResourceTarget {
                    actions: actions,
                    resource: Resource {
                        resource_type: resource_type,
                        identifiers: actual_identifiers,
                        attributes: actual_attributes,
                    },
                    environment: Environment { service_providers },
                },
            }],
        }],
    };

    return DelegationRequestContainer { delegation_request };
}
