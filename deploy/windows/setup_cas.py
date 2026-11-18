"""Configure company CAS on a native Windows instance."""

import argparse
from getpass import getpass
import json
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile
from urllib.parse import urlsplit

from dotenv import dotenv_values

from gateway import _lock
from local_mongo_auth import ADMIN_PASSWORD, APP_PASSWORD


_ENDPOINTS = {
    'CAS_BASE': 'Company CAS base URL',
    'UC_AUTH_URL': 'UC ticket exchange URL',
    'UC_REFRESH_URL': 'UC refresh URL (optional)',
}
_SHIM_SECRETS = ('SHIM_CLIENT_SECRET', 'SHIM_SIGNING_SECRET', 'SHIM_INTERNAL_TOKEN')
_GATEWAY_SECRETS = ('SECRET_KEY', 'AUTH_SERVER_NGINX_MARKER_SECRET')
_KEYCLOAK_SECRETS = ('KEYCLOAK_ADMIN_PASSWORD', 'KEYCLOAK_CLIENT_SECRET')
_TEMPLATE = Path(__file__).with_name('gateway.env.example')


def _ask(label: str) -> str:
    return input(f'{label}: ').strip().strip('"')


def _load_legacy() -> dict[str, str | None]:
    filename = _ask('Old cas-shim .env path (optional, Enter to set up manually)')
    if not filename:
        return {}
    path = Path(filename)
    if not path.is_file():
        raise ValueError(f'Old CAS settings file does not exist: {path}')
    return dotenv_values(path, interpolate=False, encoding='utf-8-sig')


def _cas_values(current: dict[str, str | None], legacy: dict[str, str | None]) -> dict[str, str]:
    updates = {'WINDOWS_MANAGE_CAS_SHIM': 'true', 'CAS_SHIM_MOCK': 'false', 'CAS_TLS_VERIFY': 'true'}
    for name, label in _ENDPOINTS.items():
        value = current.get(name) or legacy.get(name)
        if not value:
            value = '' if name == 'UC_REFRESH_URL' and name in current else _ask(label)
        endpoint = urlsplit(value)
        if (value or name != 'UC_REFRESH_URL') and (
            endpoint.scheme != 'https' or not endpoint.hostname or endpoint.username or endpoint.fragment
        ):
            raise ValueError(f'{label} must use an HTTPS URL.')
        updates[name] = value
    ca = current.get('CAS_CA_BUNDLE') or legacy.get('CAS_CA_BUNDLE')
    if ca and (current.get('CAS_CA_BUNDLE') or Path(ca).is_file()):
        updates['CAS_CA_BUNDLE'] = ca
    signup = current.get('WINDOWS_CAS_SIGNUP_MODE') or 'whitelist'
    if signup not in {'open', 'whitelist'}:
        raise ValueError('Employee signup policy must be whitelist or open.')
    updates['WINDOWS_CAS_SIGNUP_MODE'] = signup
    local_keycloak = (current.get('WINDOWS_MANAGE_KEYCLOAK') or 'false').lower() == 'true'
    if local_keycloak and signup == 'whitelist':
        employee = current.get('WINDOWS_CAS_INITIAL_EMPLOYEE')
        if employee is None:
            employee = _ask('First employee ID for the CAS whitelist (Enter to skip)')
        if employee and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', employee):
            raise ValueError('The employee ID is invalid.')
        updates['WINDOWS_CAS_INITIAL_EMPLOYEE'] = employee
    updates['UC_REFRESH_METHOD'] = current.get('UC_REFRESH_METHOD') or legacy.get('UC_REFRESH_METHOD') or 'get'
    return updates


def _instance_values(current: dict[str, str | None]) -> dict[str, str]:
    updates = {}
    local_keycloak = (current.get('WINDOWS_MANAGE_KEYCLOAK') or 'false').lower() == 'true'
    secret_names = (*_GATEWAY_SECRETS, *_SHIM_SECRETS, *(_KEYCLOAK_SECRETS if local_keycloak else ()))
    for name in secret_names:
        value = current.get(name) or secrets.token_urlsafe(48)
        if len(value) < 32:
            raise ValueError(f'{name} must be at least 32 characters.')
        updates[name] = value

    if (current.get('WINDOWS_MANAGE_MONGO') or 'false').lower() == 'true':
        for name in (ADMIN_PASSWORD, APP_PASSWORD):
            updates[name] = current.get(name) or secrets.token_urlsafe(48)
    else:
        for name in ('MONGODB_CONNECTION_STRING', 'SHIM_MONGO_URI'):
            uri = current.get(name) or getpass(f'Authenticated {name}: ')
            credentials = urlsplit(uri)
            if credentials.scheme not in {'mongodb', 'mongodb+srv'} or not credentials.netloc:
                raise ValueError(f'{name} must contain an authenticated MongoDB URI.')
            updates[name] = uri
    return updates


def _save(config: Path, lines: list[str], updates: dict[str, str]) -> None:
    pattern = re.compile(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=')
    header = '# Company CAS settings'
    kept = [line for line in lines if line != header and not ((match := pattern.match(line)) and match[1] in updates)]
    session = [f'{name}={json.dumps(value, ensure_ascii=False)}' for name, value in updates.items()]
    with tempfile.NamedTemporaryFile(
        mode='w', encoding='utf-8', newline='\n', dir=config.parent, delete=False,
    ) as output:
        output.write('\n'.join(['\n'.join(kept).rstrip(), '', header, *session, '']))
        temporary = Path(output.name)
    try:
        os.replace(temporary, config)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--instance', required=True, type=Path)
    args = parser.parse_args()
    config = args.instance.resolve() / 'gateway.env'
    try:
        with _lock(config.parent):
            source = config if config.is_file() else _TEMPLATE
            values = dotenv_values(source, interpolate=False, encoding='utf-8-sig')
            legacy = {} if values.get('CAS_BASE') and values.get('UC_AUTH_URL') else _load_legacy()
            _save(config, source.read_text(encoding='utf-8-sig').splitlines(), {
                **_cas_values(values, legacy), **_instance_values(values),
            })
    except (OSError, RuntimeError, ValueError, EOFError, KeyboardInterrupt) as exc:
        print(f'CAS setup did not finish. {exc}', file=sys.stderr)
        return 1
    print(f'CAS settings saved in {config}.')
    print('If the gateway is running, stop it. Then double-click start-gateway.bat.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
