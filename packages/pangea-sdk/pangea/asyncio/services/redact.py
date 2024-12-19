# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from __future__ import annotations

from typing import Dict, List, Optional, Union

import pangea.services.redact as m
from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse


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
        redaction_method_overrides: Optional[m.RedactionMethodOverrides] = None,
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
        redaction_method_overrides: Optional[m.RedactionMethodOverrides] = None,
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
