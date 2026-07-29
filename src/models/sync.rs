use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Profile {
    #[serde(rename = "Name", alias = "name")]
    pub name: Option<String>,
    #[serde(rename = "Culture", alias = "culture")]
    pub culture: String,
    #[serde(rename = "Email", alias = "email")]
    pub email: String,
    #[serde(rename = "Id", alias = "id")]
    pub id: String,
    #[serde(rename = "MasterPasswordHint", alias = "masterPasswordHint")]
    pub master_password_hint: Option<String>,
    #[serde(rename = "SecurityStamp", alias = "securityStamp")]
    pub security_stamp: String,
    #[serde(rename = "Object", alias = "object")]
    pub object: String,
    #[serde(rename = "PremiumFromOrganization", alias = "premiumFromOrganization")]
    pub premium_from_organization: bool,
    #[serde(rename = "ForcePasswordReset", alias = "forcePasswordReset")]
    pub force_password_reset: bool,
    #[serde(rename = "EmailVerified", alias = "emailVerified")]
    pub email_verified: bool,
    #[serde(rename = "TwoFactorEnabled", alias = "twoFactorEnabled")]
    pub two_factor_enabled: bool,
    #[serde(rename = "Premium", alias = "premium")]
    pub premium: bool,
    #[serde(rename = "UsesKeyConnector", alias = "usesKeyConnector")]
    pub uses_key_connector: bool,
    #[serde(rename = "CreationDate", alias = "creationDate")]
    pub creation_date: String,
    #[serde(rename = "PrivateKey", alias = "privateKey")]
    pub private_key: String,
    #[serde(rename = "Key", alias = "key")]
    pub key: String,
    #[serde(rename = "AvatarColor", alias = "avatarColor")]
    pub avatar_color: Option<String>,
}
