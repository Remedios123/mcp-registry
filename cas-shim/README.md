# Company CAS and UC adapter

The shim exposes OIDC to the Keycloak CAS broker and keeps UC credentials on
the server. A verified UC account becomes the employee's Keycloak username.
The CAS profile supports employees whose directory record has no email.
Administrators retain the realm's email login setting.

## Configure

1. Supply the values in [.env.example](.env.example) through the service
   environment. Use the organization's CA bundle for private certificates.
   Register the exact shim callback service with CAS and UC.
2. Start the shim from the repository root.

       uv run --project cas-shim uvicorn app:app --app-dir cas-shim --no-access-log

   Set SHIM_ALLOWED_REDIRECT_URIS to the public Keycloak broker callback URI,
   including its port on a non-default port.
3. Run the [CAS provisioning script](../keycloak/setup/configure-cas.py)
   with operator credentials in the environment.

       uv run python keycloak/setup/configure-cas.py configure --signup-mode whitelist
       uv run python keycloak/setup/configure-cas.py bind EMP001 "Example Employee"

   Select **open** instead of **whitelist** to allow automatic account
   creation on first successful CAS login.
4. Enable EGRESS_AUTH_ENABLED on the gateway, configure the upstream secret
   store, and supply ENTERPRISE_CREDENTIAL_PROFILES,
   ENTERPRISE_CREDENTIAL_SHIM_URL, ENTERPRISE_CREDENTIAL_SHIM_PUBLIC_URL,
   and the same SHIM_INTERNAL_TOKEN to Registry. List the exact registered
   destination URLs permitted to receive UC credentials.
5. Edit the HR service and select **Egress Auth → Per-user OAuth → UC**.
   Enterprise options come from deployment configuration. Reconnect existing
   WorkBuddy connections to receive the protected employee claim.

UC replaces the previous token when refreshing it. The adapter retains
scheduled refresh, read-time refresh, and the inactivity cutoff. Expired or
missing credentials produce a short-lived browser link bound to the account
and profile. A CAS callback from a different employee fails.

Keep the internal credential endpoint and MongoDB reachable only by trusted
services. Real UC requires authenticated MongoDB and verified HTTPS for exchange
and refresh. The shim encrypts new token values and binds them to the employee,
profile, and expiry. Preserve SHIM_SIGNING_SECRET across restarts. Changing
it requires employees to authorize again. Set SHIM_ALLOW_LEGACY_VAULT=true
temporarily only to read trusted plaintext rows from the previous deployment.
A successful login or refresh replaces those rows with encrypted values.
Keep runtime environments, signing keys, and database files outside Git.
