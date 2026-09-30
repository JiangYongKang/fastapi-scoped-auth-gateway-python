"""Credential issuance: API keys, refresh/access token pairs, rotation."""

from __future__ import annotations

from auth_gateway.audit import Auditor, AuditRecord
from auth_gateway.clock import Clock
from auth_gateway.config import Settings
from auth_gateway.crypto import (
    generate_credential,
    hash_secret,
    parse_credential,
    verify_secret,
)
from auth_gateway.errors import AuthError, DenyReason
from auth_gateway.models import (
    AccessTokenRecord,
    ApiKeyRecord,
    FamilyRecord,
    RefreshTokenRecord,
)
from auth_gateway.storage import CredentialStore


class Issuer:
    def __init__(
        self,
        store: CredentialStore,
        settings: Settings,
        clock: Clock,
        auditor: Auditor,
    ) -> None:
        self.store = store
        self.settings = settings
        self.clock = clock
        self.auditor = auditor

    # ---- API keys -----------------------------------------------------
    def issue_api_key(
        self, scopes: frozenset[str], ttl: int | None = None, subject: str = "api"
    ) -> tuple[ApiKeyRecord, str]:
        """Create an API key; return (record, raw_secret_to_show_once)."""
        now = self.clock.now()
        lifetime = ttl if ttl is not None else self.settings.default_api_key_ttl
        raw = generate_credential("ak")
        key_id, secret = parse_credential(raw)
        record = ApiKeyRecord(
            key_id=key_id,
            secret_hash=hash_secret(secret),
            scopes=frozenset(scopes),
            issued_at=now,
            expires_at=now + lifetime,
        )
        self.store.put_api_key(record)
        self.auditor.record(
            AuditRecord(
                event="issue_api_key",
                credential_kind="api_key",
                credential_id=key_id,
                decision="allow",
                granted_scopes=sorted(scopes),
                detail=f"subject={subject} ttl={lifetime}",
            )
        )
        return record, raw

    def revoke_api_key(self, key_id: str) -> None:
        self.store.revoke_api_key(key_id)
        self.auditor.record(
            AuditRecord(
                event="revoke_api_key",
                credential_kind="api_key",
                credential_id=key_id,
                decision="allow",
                detail="revoked",
            )
        )

    # ---- Token families ----------------------------------------------
    def _new_access_token(
        self, family_id: str, scopes: frozenset[str]
    ) -> tuple[AccessTokenRecord, str]:
        now = self.clock.now()
        raw = generate_credential("at")
        token_id, secret = parse_credential(raw)
        record = AccessTokenRecord(
            token_id=token_id,
            family_id=family_id,
            secret_hash=hash_secret(secret),
            scopes=frozenset(scopes),
            issued_at=now,
            expires_at=now + self.settings.access_token_ttl,
        )
        self.store.put_access_token(record)
        return record, raw

    def _new_refresh_token(
        self, family_id: str
    ) -> tuple[RefreshTokenRecord, str]:
        now = self.clock.now()
        raw = generate_credential("rt")
        token_id, secret = parse_credential(raw)
        record = RefreshTokenRecord(
            token_id=token_id,
            family_id=family_id,
            secret_hash=hash_secret(secret),
            issued_at=now,
            expires_at=now + self.settings.refresh_token_ttl,
        )
        return record, raw

    def issue_token_family(
        self, scopes: frozenset[str], subject: str = "user"
    ) -> dict[str, str]:
        """Create a refresh+access pair; return raw credentials once."""
        family_id = f"fam_{generate_credential('id').split('.')[0].removeprefix('id_')}"
        family = FamilyRecord(
            family_id=family_id, scopes=frozenset(scopes), lineage=[]
        )
        self.store.put_family(family)

        refresh_record, raw_refresh = self._new_refresh_token(family_id)
        self.store.put_refresh_token(refresh_record)
        family.lineage.append(refresh_record.token_id)
        self.store.put_family(family)

        _, raw_access = self._new_access_token(family_id, scopes)

        self.auditor.record(
            AuditRecord(
                event="issue_token_family",
                credential_kind="refresh_token",
                credential_id=refresh_record.token_id,
                decision="allow",
                granted_scopes=sorted(scopes),
                detail=f"subject={subject} family={family_id}",
                extra={"family_id": family_id},
            )
        )
        return {
            "family_id": family_id,
            "access_token": raw_access,
            "refresh_token": raw_refresh,
            "token_type": "Bearer",
            "access_token_expires_in": self.settings.access_token_ttl,
            "refresh_token_expires_in": self.settings.refresh_token_ttl,
        }

    def rotate_refresh(self, raw_refresh_token: str) -> dict[str, str]:
        """Exchange a refresh token for a new refresh+access pair.

        Rotation is atomic: the presented refresh token can succeed exactly
        once. Re-presentation (concurrent or repeated) rejects the request
        and invalidates the whole credential family.
        """
        try:
            token_id, secret = parse_credential(raw_refresh_token)
        except ValueError:
            self._deny_refresh(None, DenyReason.INVALID_CREDENTIAL, "malformed")
            raise  # _deny_refresh always raises; keeps type checkers happy

        existing = self.store.get_refresh_token(token_id)
        if existing is None:
            self._deny_refresh(
                token_id, DenyReason.INVALID_CREDENTIAL, "unknown token"
            )
        assert existing is not None

        # Verify the secret *before* attempting rotation so a guessed id with
        # the wrong secret is invalid, never a family-killing reuse.
        if not verify_secret(secret, existing.secret_hash):
            self._deny_refresh(
                token_id, DenyReason.INVALID_CREDENTIAL, "bad secret"
            )

        # Scopes are bound to the credential family and preserved across
        # rotations; a revoked family cannot reach this point.
        family = self.store.get_family(existing.family_id)
        scopes = family.scopes if family is not None else frozenset()

        new_refresh_record, new_raw_refresh = self._new_refresh_token(
            existing.family_id
        )
        # Atomic check-and-consume under the store lock.
        self.store.rotate_refresh_token(
            token_id, new_refresh_record, self.clock.now()
        )
        _, new_raw_access = self._new_access_token(existing.family_id, scopes)

        self.auditor.record(
            AuditRecord(
                event="refresh_rotate",
                credential_kind="refresh_token",
                credential_id=new_refresh_record.token_id,
                decision="allow",
                granted_scopes=sorted(scopes),
                detail=f"family={existing.family_id} rotated_from={token_id}",
                extra={"family_id": existing.family_id},
            )
        )
        return {
            "family_id": existing.family_id,
            "access_token": new_raw_access,
            "refresh_token": new_raw_refresh,
            "token_type": "Bearer",
            "access_token_expires_in": self.settings.access_token_ttl,
            "refresh_token_expires_in": self.settings.refresh_token_ttl,
        }

    def revoke_family(self, family_id: str, reason: str) -> None:
        self.store.revoke_family(family_id, reason)
        self.auditor.record(
            AuditRecord(
                event="revoke_family",
                credential_kind="refresh_token",
                decision="allow",
                reason=reason,
                detail=f"family={family_id}",
                extra={"family_id": family_id},
            )
        )

    def _deny_refresh(
        self, token_id: str | None, reason: DenyReason, detail: str
    ) -> None:
        self.auditor.record(
            AuditRecord(
                event="refresh_rotate",
                credential_kind="refresh_token",
                credential_id=token_id,
                decision="deny",
                reason=reason.value,
                detail=detail,
            )
        )
        raise AuthError(reason, detail, http_status=401)
