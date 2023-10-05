export interface SynapseOIDCProvider {
  idp_id: string;
  idp_name: string;
  issuer: string;
  client_id: string;
  scopes: string[];
  client_auth_method?: "client_secret_basic" | "client_secret_post" | "none";
  client_secret?: string;
  client_secret_jwt_key?: string;
}

export interface SynapseConfig {
  database?: {
    name: "sqlite3";
    args?: {
      database: string;
    };
  } | {
    name: "psycopg2";
    args?: {
      user?: string;
      password?: string;
      database?: string;
      host?: string;
      port?: number;
    };
  } | any;

  oidc_providers?: SynapseOIDCProvider[];
  oidc_config?: SynapseOIDCProvider;
  allow_guest_access?: boolean;
  cas_config?: {
    enabled?: boolean;
  };
  saml2_config?: {
    sp_config?: {};
  };
  sso?: {
    client_whitelist?: string[];
    update_profile_information?: boolean;
  };
  jwt_config?: {
    enabled?: boolean;
  };
  password_config?: {
    enabled?: boolean;
    localdb_enabled?: boolean;
  };
  enable_registration_captcha?: boolean;
  enable_registration?: boolean;
  user_consent?: {};
  enable_3pid_changes?: boolean;
  login_via_existing_session?: {
    enabled?: boolean;
  };
}
