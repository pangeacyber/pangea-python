# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Dict, List, Literal, Optional, Union, cast, overload

from pydantic import TypeAdapter

import pangea.services.redact as m
from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse, PangeaResponseResult


class RedactAsync(ServiceBaseAsync):
    """Redact service client.

    Provides the methods to interact with the Pangea Redact Service:
        [https://pangea.cloud/docs/api/redact](https://pangea.cloud/docs/api/redact)

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import Redact

        PANGEA_TOKEN = os.getenv("PANGEA_REDACT_TOKEN")

        redact_config = PangeaConfig(domain="aws.us.pangea.cloud")

        # Setup Pangea Redact service client
        redact = Redact(token=PANGEA_TOKEN, config=redact_config)
    """

    service_name = "redact"

    def __init__(
        self, token: str, config: PangeaConfig | None = None, logger_name: str = "pangea", config_id: str | None = None
    ) -> None:
        """
        Redact client

        Initializes a new Redact client.

        Args:
            token: Pangea API token.
            config: Configuration.
            logger_name: Logger name.

        Examples:
             config = PangeaConfig(domain="pangea_domain")
             redact = RedactAsync(token="pangea_token", config=config)
        """

        super().__init__(token, config, logger_name, config_id=config_id)

    async def redact(
        self,
        text: str,
        debug: Optional[bool] = None,
        rules: Optional[List[str]] = None,
        rulesets: Optional[List[str]] = None,
        return_result: Optional[bool] = None,
        redaction_method_overrides: Mapping[str, m.RedactionMethodOverrides] | None = None,
        llm_request: Optional[bool] = None,
        vault_parameters: Optional[m.VaultParameters] = None,
    ) -> PangeaResponse[m.RedactResult]:
        """
        Redact

        Redact sensitive information from provided text.

        OperationId: redact_post_v1_redact

        Args:
            text (str): The text data to redact
            debug (bool, optional): Setting this value to true will provide a detailed analysis of
                the redacted data and the rules that caused redaction
            rules (list[str], optional): An array of redact rule short names
            rulesets (list[str], optional): An array of redact rulesets short names
            return_result(bool, optional): Setting this value to false will omit the redacted result only returning count
            redaction_method_overrides: A set of redaction method overrides for any enabled rule. These methods override the config declared methods
            llm_request: Boolean flag to enable FPE redaction for LLM requests
            vault_parameters: A set of vault parameters to use for redaction

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            Pangea Response with redacted text in the response.result property,
                available response fields can be found in our
                [API Documentation](https://pangea.cloud/docs/api/redact#redact).

        Examples:
            response = redact.redact(text="Jenny Jenny... 555-867-5309")
        """

        input = m.RedactRequest(
            text=text,
            debug=debug,
            rules=rules,
            rulesets=rulesets,
            return_result=return_result,
            redaction_method_overrides=redaction_method_overrides,
            llm_request=llm_request,
            vault_parameters=vault_parameters,
        )
        return await self.request.post("v1/redact", m.RedactResult, data=input.model_dump(exclude_none=True))

    async def redact_structured(
        self,
        data: Union[Dict, str],
        jsonp: Optional[List[str]] = None,
        format: Optional[m.RedactFormat] = None,
        debug: Optional[bool] = None,
        rules: Optional[List[str]] = None,
        rulesets: Optional[List[str]] = None,
        return_result: Optional[bool] = None,
        redaction_method_overrides: Mapping[str, m.RedactionMethodOverrides] | None = None,
        llm_request: bool | None = None,
        vault_parameters: m.VaultParameters | None = None,
    ) -> PangeaResponse[m.StructuredResult]:
        """
        Redact structured

        Redact sensitive information from structured data (e.g., JSON).

        OperationId: redact_post_v1_redact_structured

        Args:
            data (dict, str): Structured data to redact
            jsonp (list[str]): JSON path(s) used to identify the specific JSON fields to redact in
                the structured data. Note: If jsonp parameter is used, the data parameter must be
                in JSON format.
            format (RedactFormat, optional): The format of the passed data. Default: "json"
            debug (bool, optional): Setting this value to true will provide a detailed analysis of
                the redacted data and the rules that caused redaction
            rules (list[str], optional): An array of redact rule short names
            rulesets (list[str], optional): An array of redact rulesets short names
            return_result(bool, optional): Setting this value to false will omit the redacted result only returning count
            redaction_method_overrides: A set of redaction method overrides for any enabled rule. These methods override the config declared methods
            llm_request: Boolean flag to enable FPE redaction for LLM requests
            vault_parameters: A set of vault parameters to use for redaction

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            Pangea Response with redacted data in the response.result field,
                available response fields can be found in our
                [API Documentation](https://pangea.cloud/docs/api/redact#redact-structured)

        Examples:
            data = {
                "number": "555-867-5309",
                "ip": "1.1.1.1",
            }

            response = redact.redact_structured(data=data, redact_format="json")
        """

        input = m.StructuredRequest(
            data=data,
            jsonp=jsonp,
            format=format,
            debug=debug,
            rules=rules,
            rulesets=rulesets,
            return_result=return_result,
            redaction_method_overrides=redaction_method_overrides,
            llm_request=llm_request,
            vault_parameters=vault_parameters,
        )
        return await self.request.post(
            "v1/redact_structured", m.StructuredResult, data=input.model_dump(exclude_none=True)
        )

    async def unredact(self, redacted_data: m.RedactedData, fpe_context: str) -> PangeaResponse[m.UnredactResult]:
        """
        Unredact

        Decrypt or unredact fpe redactions

        OperationId: redact_post_v1_unredact

        Args:
            redacted_data: Data to unredact
            fpe_context (base64): FPE context used to decrypt and unredact data

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            Pangea Response with redacted data in the response.result field,
                available response fields can be found in our
                [API Documentation](https://pangea.cloud/docs/api/redact#unredact)
        """
        input = m.UnredactRequest(redacted_data=redacted_data, fpe_context=fpe_context)
        return await self.request.post("v1/unredact", m.UnredactResult, data=input.model_dump(exclude_none=True))

    async def get_service_config(self, config_id: str) -> PangeaResponse[m.ServiceConfigResult]:
        """
        Get a service config.


        OperationId: redact_post_v1beta_config
        """
        response = await self.request.post("v1beta/config", PangeaResponseResult, data={"id": config_id})
        response.result = TypeAdapter(m.ServiceConfigResult).validate_python(response.json["result"])
        return cast(PangeaResponse[m.ServiceConfigResult], response)

    @overload
    async def create_service_config(
        self,
        name: str,
        *,
        version: Literal["1.0.0"],
        enabled_rules: Sequence[str] | None = None,
        redactions: Mapping[str, m.Redaction] | None = None,
        vault_service_config_id: str | None = None,
        salt_vault_secret_id: str | None = None,
        rules: Mapping[str, m.RuleV1] | None = None,
        rulesets: Mapping[str, m.RulesetV1] | None = None,
        supported_languages: Sequence[Literal["en"]] | None = None,
    ) -> PangeaResponse[m.ServiceConfigResult]:
        """
        Create a v1.0.0 service config.

        OperationId: redact_post_v1beta_config_create

        Args:
            vault_service_config_id: Service config used to create the secret
            salt_vault_secret_id: Pangea only allows hashing to be done using a salt value to prevent brute-force attacks.
        """

    @overload
    async def create_service_config(
        self,
        name: str,
        *,
        version: Literal["2.0.0"] | None = None,
        enabled_rules: Sequence[str] | None = None,
        enforce_enabled_rules: bool | None = None,
        redactions: Mapping[str, m.Redaction] | None = None,
        vault_service_config_id: str | None = None,
        salt_vault_secret_id: str | None = None,
        fpe_vault_secret_id: str | None = None,
        rules: Mapping[str, m.RuleV2] | None = None,
        rulesets: Mapping[str, m.RulesetV2] | None = None,
        supported_languages: Sequence[Literal["en"]] | None = None,
    ) -> PangeaResponse[m.ServiceConfigResult]:
        """
        Create a v2.0.0 service config.

        OperationId: redact_post_v1beta_config_create

        Args:
            enforce_enabled_rules: Always run service config enabled rules across all redact calls regardless of flags?
            vault_service_config_id: Service config used to create the secret
            salt_vault_secret_id: Pangea only allows hashing to be done using a salt value to prevent brute-force attacks.
            fpe_vault_secret_id: The ID of the key used by FF3 Encryption algorithms for FPE.
        """

    async def create_service_config(
        self,
        name: str,
        *,
        version: Literal["1.0.0", "2.0.0"] | None = None,
        enabled_rules: Sequence[str] | None = None,
        enforce_enabled_rules: bool | None = None,
        fpe_vault_secret_id: str | None = None,
        redactions: Mapping[str, m.Redaction] | None = None,
        rules: Mapping[str, m.RuleV1 | m.RuleV2] | None = None,
        rulesets: Mapping[str, m.RulesetV1 | m.RulesetV2] | None = None,
        salt_vault_secret_id: str | None = None,
        supported_languages: Sequence[Literal["en"]] | None = None,
        vault_service_config_id: str | None = None,
    ) -> PangeaResponse[m.ServiceConfigResult]:
        """
        Create a service config.

        OperationId: redact_post_v1beta_config_create

        Args:
            enforce_enabled_rules: Always run service config enabled rules across all redact calls regardless of flags?
            fpe_vault_secret_id: The ID of the key used by FF3 Encryption algorithms for FPE.
            salt_vault_secret_id: Pangea only allows hashing to be done using a salt value to prevent brute-force attacks.
            vault_service_config_id: Service config used to create the secret
        """

        response = await self.request.post(
            "v1beta/config/create",
            PangeaResponseResult,
            data={
                "name": name,
                "version": version,
                "enabled_rules": enabled_rules,
                "enforce_enabled_rules": enforce_enabled_rules,
                "fpe_vault_secret_id": fpe_vault_secret_id,
                "redactions": redactions,
                "rules": rules,
                "rulesets": rulesets,
                "salt_vault_secret_id": salt_vault_secret_id,
                "supported_languages": supported_languages,
                "vault_service_config_id": vault_service_config_id,
            },
        )
        response.result = TypeAdapter(m.ServiceConfigResult).validate_python(response.json["result"])
        return cast(PangeaResponse[m.ServiceConfigResult], response)

    @overload
    async def update_service_config(
        self,
        config_id: str,
        *,
        version: Literal["1.0.0"],
        name: str,
        updated_at: str,
        enabled_rules: Sequence[str] | None = None,
        redactions: Mapping[str, m.Redaction] | None = None,
        vault_service_config_id: str | None = None,
        salt_vault_secret_id: str | None = None,
        rules: Mapping[str, m.RuleV1] | None = None,
        rulesets: Mapping[str, m.RulesetV1] | None = None,
        supported_languages: Sequence[Literal["en"]] | None = None,
    ) -> PangeaResponse[m.ServiceConfigResult]:
        """
        Update a v1.0.0 service config.

        OperationId: redact_post_v1beta_config_update

        Args:
            vault_service_config_id: Service config used to create the secret
            salt_vault_secret_id: Pangea only allows hashing to be done using a salt value to prevent brute-force attacks.
        """

    @overload
    async def update_service_config(
        self,
        config_id: str,
        *,
        version: Literal["2.0.0"] | None = None,
        name: str,
        updated_at: str,
        enabled_rules: Sequence[str] | None = None,
        enforce_enabled_rules: bool | None = None,
        redactions: Mapping[str, m.Redaction] | None = None,
        vault_service_config_id: str | None = None,
        salt_vault_secret_id: str | None = None,
        fpe_vault_secret_id: str | None = None,
        rules: Mapping[str, m.RuleV2] | None = None,
        rulesets: Mapping[str, m.RulesetV2] | None = None,
        supported_languages: Sequence[Literal["en"]] | None = None,
    ) -> PangeaResponse[m.ServiceConfigResult]:
        """
        Update a v2.0.0 service config.

        OperationId: redact_post_v1beta_config_update

        Args:
            enforce_enabled_rules: Always run service config enabled rules across all redact calls regardless of flags?
            vault_service_config_id: Service config used to create the secret
            salt_vault_secret_id: Pangea only allows hashing to be done using a salt value to prevent brute-force attacks.
            fpe_vault_secret_id: The ID of the key used by FF3 Encryption algorithms for FPE.
        """

    async def update_service_config(
        self,
        config_id: str,
        *,
        version: Literal["1.0.0", "2.0.0"] | None = None,
        name: str,
        updated_at: str,
        enabled_rules: Sequence[str] | None = None,
        enforce_enabled_rules: bool | None = None,
        fpe_vault_secret_id: str | None = None,
        redactions: Mapping[str, m.Redaction] | None = None,
        rules: Mapping[str, m.RuleV1 | m.RuleV2] | None = None,
        rulesets: Mapping[str, m.RulesetV1 | m.RulesetV2] | None = None,
        salt_vault_secret_id: str | None = None,
        supported_languages: Sequence[Literal["en"]] | None = None,
        vault_service_config_id: str | None = None,
    ) -> PangeaResponse[m.ServiceConfigResult]:
        """
        Update a service config.

        OperationId: redact_post_v1beta_config_update

        Args:
            enforce_enabled_rules: Always run service config enabled rules across all redact calls regardless of flags?
            fpe_vault_secret_id: The ID of the key used by FF3 Encryption algorithms for FPE.
            salt_vault_secret_id: Pangea only allows hashing to be done using a salt value to prevent brute-force attacks.
            vault_service_config_id: Service config used to create the secret
        """

        response = await self.request.post(
            "v1beta/config/update",
            PangeaResponseResult,
            data={
                "id": config_id,
                "updated_at": updated_at,
                "name": name,
                "version": version,
                "enabled_rules": enabled_rules,
                "enforce_enabled_rules": enforce_enabled_rules,
                "fpe_vault_secret_id": fpe_vault_secret_id,
                "redactions": redactions,
                "rules": rules,
                "rulesets": rulesets,
                "salt_vault_secret_id": salt_vault_secret_id,
                "supported_languages": supported_languages,
                "vault_service_config_id": vault_service_config_id,
            },
        )
        response.result = TypeAdapter(m.ServiceConfigResult).validate_python(response.json["result"])
        return cast(PangeaResponse[m.ServiceConfigResult], response)

    async def delete_service_config(self, config_id: str) -> PangeaResponse[m.ServiceConfigResult]:
        """
        Delete a service config.

        OperationId: redact_post_v1beta_config_delete

        Args:
            config_id: An ID for a service config
        """

        response = await self.request.post("v1beta/config/delete", PangeaResponseResult, data={"id": config_id})
        response.result = TypeAdapter(m.ServiceConfigResult).validate_python(response.json["result"])
        return cast(PangeaResponse[m.ServiceConfigResult], response)

    async def list_service_configs(
        self,
        *,
        filter: m.ServiceConfigFilter | None = None,
        last: str | None = None,
        order: Literal["asc", "desc"] | None = None,
        order_by: Literal["id", "created_at", "updated_at"] | None = None,
        size: int | None = None,
    ) -> PangeaResponse[m.ServiceConfigListResult]:
        """
        List service configs.

        OperationId: redact_post_v1beta_config_list

        Args:
            last: Reflected value from a previous response to obtain the next page of results.
            order: Order results asc(ending) or desc(ending).
            order_by: Which field to order results by.
            size: Maximum results to include in the response.
        """

        return await self.request.post(
            "v1beta/config/list",
            m.ServiceConfigListResult,
            data={"filter": filter, "last": last, "order": order, "order_by": order_by, "size": size},
        )
