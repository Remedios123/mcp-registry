"""Provision and stop the Windows launcher's authenticated loopback MongoDB."""

from urllib.parse import quote

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure, PyMongoError


ADMIN_PASSWORD = 'WINDOWS_MONGO_ADMIN_PASSWORD'
APP_PASSWORD = 'WINDOWS_MONGO_APP_PASSWORD'
_ADMIN = 'windows-registry-mongo-admin'
_APP = 'windows-registry-mongo-app'
_HOST = '127.0.0.1'


def configure_managed_mongo_auth(env: dict[str, str], port: int) -> None:
    """Set the authenticated registry and shim connections for this instance."""
    if min(len(env.get(ADMIN_PASSWORD, '')), len(env.get(APP_PASSWORD, ''))) < 32:
        raise ValueError('Run setup-cas.bat to configure the managed MongoDB passwords.')
    password = quote(env[APP_PASSWORD], safe='')
    target = f'mongodb://{_APP}:{password}@{_HOST}:{port}'
    query = '?authSource=admin&directConnection=true'
    registry_db = quote(env['DOCUMENTDB_DATABASE'], safe='')
    shim_db = quote(env.get('SHIM_MONGO_DB') or 'cas_shim', safe='')
    env['MONGODB_CONNECTION_STRING'] = f'{target}/{registry_db}{query}'
    env['SHIM_MONGO_URI'] = f'{target}/{shim_db}{query}'


def _admin_client(port: int, password: str) -> MongoClient:
    return MongoClient(_HOST, port, username=_ADMIN, password=password, authSource='admin',
                       directConnection=True, timeoutMS=5000)


def bootstrap_managed_mongo(env: dict[str, str]) -> None:
    """Create the two managed users when absent and verify application access."""
    port = int(env['DOCUMENTDB_PORT'])
    password = env[ADMIN_PASSWORD]
    try:
        with _admin_client(port, password) as admin:
            try:
                admin.admin.command('ping')
            except OperationFailure as exc:
                if exc.code != 18:
                    raise
                # MongoDB's localhost exception permits the first user only.
                with MongoClient(_HOST, port, directConnection=True, timeoutMS=5000) as local:
                    local.admin.command('createUser', _ADMIN, pwd=password,
                                        roles=['userAdminAnyDatabase', 'hostManager'])

        with _admin_client(port, password) as admin:
            if not admin.admin.command('usersInfo', _APP)['users']:
                databases = {env['DOCUMENTDB_DATABASE'], env.get('SHIM_MONGO_DB') or 'cas_shim'}
                admin.admin.command('createUser', _APP, pwd=env[APP_PASSWORD], roles=[
                    {'role': 'readWrite', 'db': name} for name in sorted(databases)
                ])
        with MongoClient(env['MONGODB_CONNECTION_STRING'], timeoutMS=5000) as application:
            application.admin.command('ping')
    except PyMongoError as exc:
        raise RuntimeError(
            'Managed MongoDB authentication failed. Restore the instance MongoDB passwords '
            'or configure an authenticated database with WINDOWS_MANAGE_MONGO=false.'
        ) from exc


def shutdown_managed_mongo(port: int, secured: bool, env: dict[str, str]) -> None:
    """Request a clean MongoDB shutdown with the instance's authentication mode."""
    if secured:
        password = env.get(ADMIN_PASSWORD)
        if not password:
            raise RuntimeError('The managed MongoDB password is missing from gateway.env.')
        client = _admin_client(port, password)
    else:
        client = MongoClient(_HOST, port, directConnection=True, timeoutMS=3000)
    try:
        with client:
            client.admin.command('shutdown')
    except ConnectionFailure:
        # A successful shutdown normally disconnects before returning a reply.
        # The launcher checks process exit before clearing the process record.
        pass
    except PyMongoError as exc:
        raise RuntimeError('MongoDB refused the shutdown request.') from exc
