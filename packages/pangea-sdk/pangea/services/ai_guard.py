from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Annotated, Any, Generic, Literal, Optional, overload

from pydantic import BaseModel, ConfigDict, Field, RootModel

from pangea._typing import T
from pangea.config import PangeaConfig
from pangea.response import APIRequestModel, APIResponseModel, PangeaResponse, PangeaResponseResult
from pangea.services.base import ServiceBase

# This is named "prompt injection" in the API spec even though it is also used
# for many other detectors.
PromptInjectionAction = Literal["report", "block"]

MaliciousEntityAction = Literal["report", "defang", "disabled", "block"]

# This is named "PII entity" in the API spec even though it is also used for the
# secrets detector.
PiiEntityAction = Literal["disabled", "report", "block", "mask", "partial_masking", "replacement", "hash", "fpe"]


class Message(APIRequestModel):
    role: Optional[str] = None
    content: str


class McpToolsMessage(APIRequestModel):
    role: Literal["tools"]
    content: list[dict[str, Any]]


class CodeDetectionOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[Literal["report", "block"]] = None
    threshold: Optional[float] = None


class LanguageDetectionOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[Literal["", "report", "allow", "block"]] = ""
    languages: Optional[list[str]] = None
    threshold: Optional[float] = None


class TopicDetectionOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[Literal["", "report", "block"]] = ""
    topics: Optional[list[str]] = None
    threshold: Optional[float] = None


class PromptInjectionOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[PromptInjectionAction] = None


class SelfHarmOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[PromptInjectionAction] = None
    threshold: Optional[float] = None


class GibberishOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[PromptInjectionAction] = None


class RoleplayOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[PromptInjectionAction] = None


class SentimentOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[PromptInjectionAction] = None
    threshold: Optional[float] = None


class MaliciousEntityOverride(APIRequestModel):
    disabled: Optional[bool] = None
    ip_address: Optional[MaliciousEntityAction] = None
    url: Optional[MaliciousEntityAction] = None
    domain: Optional[MaliciousEntityAction] = None


class CompetitorsOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[PromptInjectionAction] = None


class PiiEntityOverride(APIRequestModel):
    disabled: Optional[bool] = None
    email_address: Optional[PiiEntityAction] = None
    nrp: Optional[PiiEntityAction] = None
    location: Optional[PiiEntityAction] = None
    person: Optional[PiiEntityAction] = None
    phone_number: Optional[PiiEntityAction] = None
    date_time: Optional[PiiEntityAction] = None
    ip_address: Optional[PiiEntityAction] = None
    url: Optional[PiiEntityAction] = None
    money: Optional[PiiEntityAction] = None
    credit_card: Optional[PiiEntityAction] = None
    crypto: Optional[PiiEntityAction] = None
    iban_code: Optional[PiiEntityAction] = None
    us_bank_number: Optional[PiiEntityAction] = None
    nif: Optional[PiiEntityAction] = None
    au_abn: Optional[PiiEntityAction] = None
    au_acn: Optional[PiiEntityAction] = None
    au_tfn: Optional[PiiEntityAction] = None
    medical_license: Optional[PiiEntityAction] = None
    uk_nhs: Optional[PiiEntityAction] = None
    au_medicare: Optional[PiiEntityAction] = None
    us_drivers_license: Optional[PiiEntityAction] = None
    us_itin: Optional[PiiEntityAction] = None
    us_passport: Optional[PiiEntityAction] = None
    us_ssn: Optional[PiiEntityAction] = None


class SecretsDetectionOverride(APIRequestModel):
    disabled: Optional[bool] = None
    slack_token: Optional[PiiEntityAction] = None
    rsa_private_key: Optional[PiiEntityAction] = None
    ssh_dsa_private_key: Optional[PiiEntityAction] = None
    ssh_ec_private_key: Optional[PiiEntityAction] = None
    pgp_private_key_block: Optional[PiiEntityAction] = None
    amazon_aws_access_key_id: Optional[PiiEntityAction] = None
    amazon_aws_secret_access_key: Optional[PiiEntityAction] = None
    amazon_mws_auth_token: Optional[PiiEntityAction] = None
    facebook_access_token: Optional[PiiEntityAction] = None
    github_access_token: Optional[PiiEntityAction] = None
    jwt_token: Optional[PiiEntityAction] = None
    google_api_key: Optional[PiiEntityAction] = None
    google_cloud_platform_api_key: Optional[PiiEntityAction] = None
    google_drive_api_key: Optional[PiiEntityAction] = None
    google_cloud_platform_service_account: Optional[PiiEntityAction] = None
    google_gmail_api_key: Optional[PiiEntityAction] = None
    youtube_api_key: Optional[PiiEntityAction] = None
    mailchimp_api_key: Optional[PiiEntityAction] = None
    mailgun_api_key: Optional[PiiEntityAction] = None
    basic_auth: Optional[PiiEntityAction] = None
    picatic_api_key: Optional[PiiEntityAction] = None
    slack_webhook: Optional[PiiEntityAction] = None
    stripe_api_key: Optional[PiiEntityAction] = None
    stripe_restricted_api_key: Optional[PiiEntityAction] = None
    square_access_token: Optional[PiiEntityAction] = None
    square_oauth_secret: Optional[PiiEntityAction] = None
    twilio_api_key: Optional[PiiEntityAction] = None
    pangea_token: Optional[PiiEntityAction] = None


class ImageDetectionItems(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[Literal["", "report", "block"]] = ""
    topics: Optional[list[str]] = None
    threshold: Annotated[Optional[float], Field(ge=0.0, le=1.0, multiple_of=0.01)] = None


class Overrides(APIRequestModel):
    """Overrides flags."""

    ignore_recipe: Optional[bool] = None
    """Bypass existing Recipe content and create an on-the-fly Recipe."""

    code_detection: Optional[CodeDetectionOverride] = None
    competitors: Optional[CompetitorsOverride] = None
    gibberish: Optional[GibberishOverride] = None
    image: Optional[ImageDetectionItems] = None
    language_detection: Optional[LanguageDetectionOverride] = None
    malicious_entity: Optional[MaliciousEntityOverride] = None
    pii_entity: Optional[PiiEntityOverride] = None
    prompt_injection: Optional[PromptInjectionOverride] = None
    roleplay: Optional[RoleplayOverride] = None
    secrets_detection: Optional[SecretsDetectionOverride] = None
    selfharm: Optional[SelfHarmOverride] = None
    sentiment: Optional[SentimentOverride] = None
    topic: Optional[TopicDetectionOverride] = None


class MaliciousPromptOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[Literal["report", "block"]] = None


class Overrides2(APIRequestModel):
    ignore_recipe: Optional[bool] = False
    """Bypass existing Recipe content and create an on-the-fly Recipe."""
    code: Optional[CodeDetectionOverride] = None
    language: Optional[LanguageDetectionOverride] = None
    topic: Optional[TopicDetectionOverride] = None
    malicious_prompt: Optional[MaliciousPromptOverride] = None
    malicious_entity: Optional[MaliciousEntityOverride] = None
    competitors: Optional[CompetitorsOverride] = None
    confidential_and_pii_entity: Optional[PiiEntityOverride] = None
    secret_and_key_entity: Optional[SecretsDetectionOverride] = None
    image: Optional[ImageDetectionItems] = None


class LogFields(APIRequestModel):
    """Additional fields to include in activity log"""

    citations: Optional[str] = None
    """Origin or source application of the event"""

    extra_info: Optional[str] = None
    """Stores supplementary details related to the event"""

    model: Optional[str] = None
    """Model used to perform the event"""

    source: Optional[str] = None
    """IP address of user or app or agent"""

    tools: Optional[str] = None
    """Tools used to perform the event"""


class AnalyzerResponse(APIResponseModel):
    analyzer: str
    confidence: float


class PromptInjectionResult(APIResponseModel):
    action: str
    """The action taken by this Detector"""

    analyzer_responses: list[AnalyzerResponse]
    """Triggered prompt injection analyzers."""


class PiiEntity(APIResponseModel):
    type: str
    value: str
    action: str
    """The action taken on this Entity"""
    start_pos: Optional[int] = None


class PiiEntityResult(APIResponseModel):
    entities: list[PiiEntity]
    """Detected redaction rules."""


class MaliciousEntity(APIResponseModel):
    type: str
    value: str
    action: Optional[str] = None
    start_pos: Optional[int] = None
    raw: Optional[dict[str, object]] = None


class MaliciousEntityResult(APIResponseModel):
    entities: list[MaliciousEntity]
    """Detected harmful items."""


class CustomEntity(APIResponseModel):
    type: str
    value: str
    action: str
    """The action taken on this Entity"""
    start_pos: Optional[int] = None
    raw: Optional[dict[str, object]] = None


class CustomEntityResult(APIResponseModel):
    entities: list[CustomEntity]
    """Detected redaction rules."""


class SecretsEntity(APIResponseModel):
    type: str
    value: str
    action: str
    """The action taken on this Entity"""
    start_pos: Optional[int] = None
    redacted_value: Optional[str] = None


class SecretsEntityResult(APIResponseModel):
    entities: list[SecretsEntity]
    """Detected redaction rules."""


class RedactEntityResultItem(APIResponseModel):
    action: str
    """The action taken on this Entity"""

    redacted: bool

    type: str

    value: str

    start_pos: Optional[int] = None


class RedactEntityResult(APIResponseModel):
    entities: Optional[list[RedactEntityResultItem]] = None
    """Detected redaction rules."""


class LanguageDetectionResult(APIResponseModel):
    action: Optional[str] = None
    """The action taken by this Detector"""

    language: Optional[str] = None


class Topic(APIResponseModel):
    topic: str
    confidence: float


class TopicDetectionResult(APIResponseModel):
    action: Optional[str] = None
    """The action taken by this Detector"""

    topics: Optional[list[Topic]] = None
    """List of topics detected"""


class CodeDetectionResult(APIResponseModel):
    language: str
    action: str
    """The action taken by this Detector"""


class GuardDetector(APIResponseModel, Generic[T]):
    detected: Optional[bool] = None
    data: Optional[T] = None


class TextGuardDetectors(APIResponseModel):
    code_detection: Optional[GuardDetector[CodeDetectionResult]] = None
    competitors: Optional[GuardDetector[object]] = None
    custom_entity: Optional[GuardDetector[object]] = None
    gibberish: Optional[GuardDetector[object]] = None
    hardening: Optional[GuardDetector[object]] = None
    language_detection: Optional[GuardDetector[LanguageDetectionResult]] = None
    malicious_entity: Optional[GuardDetector[MaliciousEntityResult]] = None
    pii_entity: Optional[GuardDetector[PiiEntityResult]] = None
    profanity_and_toxicity: Optional[GuardDetector[object]] = None
    prompt_injection: Optional[GuardDetector[PromptInjectionResult]] = None
    secrets_detection: Optional[GuardDetector[SecretsEntityResult]] = None
    selfharm: Optional[GuardDetector[object]] = None
    sentiment: Optional[GuardDetector[object]] = None
    topic: Optional[GuardDetector[TopicDetectionResult]] = None


class PromptMessage(APIResponseModel):
    role: str
    content: str


class TextGuardResult(PangeaResponseResult):
    detectors: TextGuardDetectors
    """Result of the recipe analyzing and input prompt."""

    access_rules: Optional[object] = None
    """Result of the recipe evaluating configured rules"""

    blocked: Optional[bool] = None
    """Whether or not the prompt triggered a block detection."""

    fpe_context: Optional[str] = None
    """
    If an FPE redaction method returned results, this will be the context passed to
    unredact.
    """

    prompt_messages: Optional[list[PromptMessage]] = None
    """Updated structured prompt, if applicable."""

    prompt_text: Optional[str] = None
    """Updated prompt text, if applicable."""

    recipe: Optional[str] = None
    """The Recipe that was used."""

    transformed: Optional[bool] = None
    """Whether or not the original input was transformed."""


class Tool(RootModel[str]):
    root: Annotated[str, Field(min_length=1)]
    """Tool name"""


class McpTool(APIRequestModel):
    server_name: Annotated[str, Field(min_length=1)]
    """MCP server name"""

    tools: Annotated[list[Tool], Field(min_length=1)]


class ExtraInfo(BaseModel):
    """(AIDR) Logging schema."""

    # Additional properties are allowed here.
    model_config = ConfigDict(extra="allow")

    app_name: Optional[str] = None
    """Name of source application/agent."""

    app_group: Optional[str] = None
    """The group of source application/agent."""

    app_version: Optional[str] = None
    """Version of the source application/agent."""

    actor_name: Optional[str] = None
    """Name of subject actor/service account."""

    actor_group: Optional[str] = None
    """The group of subject actor."""

    source_region: Optional[str] = None
    """Geographic region or data center."""

    sub_tenant: Optional[str] = None
    """Sub tenant of the user or organization"""
    mcp_tools: Optional[Sequence[McpTool]] = None

    """Each item groups tools for a given MCP server."""


class AccessRuleResult(APIResponseModel):
    """
    Details about the evaluation of a single rule, including whether it matched,
    the action to take, the rule name, and optional debugging information.
    """

    matched: bool
    """Whether this rule's logic evaluated to true for the input."""

    action: str
    """
    The action resulting from the rule evaluation. One of 'allowed', 'blocked',
    or 'reported'.
    """

    name: str
    """A human-readable name for the rule."""

    logic: Optional[dict[str, Any]] = None
    """The JSON logic expression evaluated for this rule."""

    attributes: Optional[dict[str, Any]] = None
    """The input attribute values that were available during rule evaluation."""


class GuardDetectors(APIResponseModel):
    """Result of the recipe analyzing and input prompt."""

    code: Optional[GuardDetector[CodeDetectionResult]] = None
    competitors: Optional[GuardDetector[object]] = None
    confidential_and_pii_entity: Optional[GuardDetector[RedactEntityResult]] = None
    custom_entity: Optional[GuardDetector[RedactEntityResult]] = None
    language: Optional[GuardDetector[LanguageDetectionResult]] = None
    malicious_entity: Optional[GuardDetector[MaliciousEntityResult]] = None
    malicious_prompt: Optional[GuardDetector[PromptInjectionResult]] = None
    prompt_hardening: Optional[GuardDetector[object]] = None
    secret_and_key_entity: Optional[GuardDetector[RedactEntityResult]] = None
    topic: Optional[GuardDetector[TopicDetectionResult]] = None


class GuardResult(PangeaResponseResult):
    output: Optional[dict[str, Any]] = None
    """Updated structured prompt."""

    blocked: Optional[bool] = None
    """Whether or not the prompt triggered a block detection."""

    transformed: Optional[bool] = None
    """Whether or not the original input was transformed."""

    recipe: Optional[str] = None
    """The Recipe that was used."""

    detectors: GuardDetectors
    """Result of the recipe analyzing and input prompt."""

    access_rules: Optional[dict[str, AccessRuleResult]] = None
    """Result of the recipe evaluating configured rules"""

    fpe_context: Optional[str] = None
    """
    If an FPE redaction method returned results, this will be the context passed
    to unredact.
    """

    input_token_count: Optional[float] = None
    """Number of tokens counted in the input"""

    output_token_count: Optional[float] = None
    """Number of tokens counted in the output"""


class AIGuard(ServiceBase):
    """AI Guard service client.

    Provides methods to interact with Pangea's AI Guard service.

    Examples:
        from pangea.services import AIGuard

        ai_guard = AIGuard(token="pangea_token")
    """

    service_name = "ai-guard"

    def __init__(
        self, token: str, config: PangeaConfig | None = None, logger_name: str = "pangea", config_id: str | None = None
    ) -> None:
        """
        AI Guard service client.

        Initializes a new AI Guard client.

        Args:
            token: Pangea API token.
            config: Pangea service configuration.
            logger_name: Logger name.
            config_id: Configuration ID.

        Examples:
            from pangea.services import AIGuard

            ai_guard = AIGuard(token="pangea_token")
        """

        super().__init__(token, config, logger_name, config_id)

    @overload
    def guard_text(
        self,
        text: str,
        *,
        debug: bool | None = None,
        log_fields: LogFields | None = None,
        overrides: Overrides | None = None,
        recipe: str | None = None,
    ) -> PangeaResponse[TextGuardResult]:
        """
        Guard LLM input and output text

        Detect, remove, or block malicious content and intent in LLM inputs and
        outputs to prevent model manipulation and data leakage.

        OperationId: ai_guard_post_v1_text_guard

        Args:
            text: Text to be scanned by AI Guard for PII, sensitive data,
                malicious content, and other data types defined by the
                configuration. Supports processing up to 20 KiB of text.
            debug: Setting this value to true will provide a detailed analysis
                of the text data
            log_field: Additional fields to include in activity log
            overrides: Overrides flags. Note: This parameter has no effect when
                the request is made by AIDR
            recipe: Recipe key of a configuration of data types and settings
                defined in the Pangea User Console. It specifies the rules that
                are to be applied to the text, such as defang malicious URLs.

        Examples:
            response = ai_guard.guard_text("text")
        """

    @overload
    def guard_text(
        self,
        *,
        messages: Sequence[Message | McpToolsMessage],
        recipe: str | None = None,
        debug: bool | None = None,
        overrides: Overrides | None = None,
        log_fields: LogFields | None = None,
        only_relevant_content: bool = False,
    ) -> PangeaResponse[TextGuardResult]:
        """
        Guard LLM input and output text

        Detect, remove, or block malicious content and intent in LLM inputs and
        outputs to prevent model manipulation and data leakage.

        OperationId: ai_guard_post_v1_text_guard

        Args:
            messages: Structured messages data to be scanned by AI Guard for
                PII, sensitive data, malicious content, and other data types
                defined by the configuration. Supports processing up to 20 KiB
                of JSON text using Pangea message format.
            debug: Setting this value to true will provide a detailed analysis
                of the text data
            log_field: Additional fields to include in activity log
            overrides: Overrides flags. Note: This parameter has no effect when
                the request is made by AIDR
            recipe: Recipe key of a configuration of data types and settings
                defined in the Pangea User Console. It specifies the rules that
                are to be applied to the text, such as defang malicious URLs.
            only_relevant_content: Whether or not to only send relevant content
                to AI Guard.

        Examples:
            response = ai_guard.guard_text(messages=[Message(role="user", content="hello world")])
        """

    def guard_text(
        self,
        text: str | None = None,
        *,
        messages: Sequence[Message | McpToolsMessage] | None = None,
        debug: bool | None = None,
        log_fields: LogFields | None = None,
        overrides: Overrides | None = None,
        recipe: str | None = None,
        only_relevant_content: bool = False,
    ) -> PangeaResponse[TextGuardResult]:
        """
        Guard LLM input and output text

        Detect, remove, or block malicious content and intent in LLM inputs and
        outputs to prevent model manipulation and data leakage.

        OperationId: ai_guard_post_v1_text_guard

        Args:
            text: Text to be scanned by AI Guard for PII, sensitive data,
                malicious content, and other data types defined by the
                configuration. Supports processing up to 10KB of text.
            messages: Structured messages data to be scanned by AI Guard for
                PII, sensitive data, malicious content, and other data types
                defined by the configuration. Supports processing up to 10KB of
                JSON text
            debug: Setting this value to true will provide a detailed analysis
                of the text data
            log_field: Additional fields to include in activity log
            overrides: Overrides flags. Note: This parameter has no effect when
                the request is made by AIDR
            recipe: Recipe key of a configuration of data types and settings
                defined in the Pangea User Console. It specifies the rules that
                are to be applied to the text, such as defang malicious URLs.
            only_relevant_content: Whether or not to only send relevant content
                to AI Guard.

        Examples:
            response = ai_guard.guard_text("text")
        """

        if text is not None and messages is not None:
            raise ValueError("Exactly one of `text` or `messages` must be given")

        if only_relevant_content and messages is not None:
            original_messages = messages
            messages, original_indices = get_relevant_content(messages)

        response = self.request.post(
            "v1/text/guard",
            TextGuardResult,
            data={
                "text": text,
                "messages": messages,
                "recipe": recipe,
                "debug": debug,
                "overrides": overrides,
                "log_fields": log_fields,
            },
        )

        if only_relevant_content and response.result and response.result.prompt_messages:
            response.result.prompt_messages = patch_messages(
                original_messages, original_indices, response.result.prompt_messages
            )  # type: ignore[assignment]

        return response

    def guard(
        self,
        input: Mapping[str, Any],
        *,
        recipe: str | None = None,
        debug: bool | None = None,
        overrides: Overrides2 | None = None,
        app_id: str | None = None,
        actor_id: str | None = None,
        llm_provider: str | None = None,
        model: str | None = None,
        model_version: str | None = None,
        request_token_count: int | None = None,
        response_token_count: int | None = None,
        source_ip: str | None = None,
        source_location: str | None = None,
        tenant_id: str | None = None,
        event_type: Literal["input", "output", "tool_input", "tool_output", "tool_listing"] | None = None,
        collector_instance_id: str | None = None,
        extra_info: ExtraInfo | None = None,
        count_tokens: bool | None = None,
    ) -> PangeaResponse[GuardResult]:
        """
        Guard LLM input and output

        Analyze and redact content to avoid manipulation of the model, addition
        of malicious content, and other undesirable data transfers.

        OperationId: ai_guard_post_v1_guard

        Args:
            input: 'messages' (required) contains Prompt content and role array
                in JSON format. The `content` is the multimodal text or image
                input that will be analyzed. Additional properties such as
                'tools' may be provided for analysis.
            recipe: Recipe key of a configuration of data types and settings defined in the Pangea User Console. It specifies the rules that are to be applied to the text, such as defang malicious URLs.
            debug: Setting this value to true will provide a detailed analysis of the text data
            app_name: Name of source application.
            llm_provider: Underlying LLM.  Example: 'OpenAI'.
            model: Model used to perform the event. Example: 'gpt'.
            model_version: Model version used to perform the event. Example: '3.5'.
            request_token_count: Number of tokens in the request.
            response_token_count: Number of tokens in the response.
            source_ip: IP address of user or app or agent.
            source_location: Location of user or app or agent.
            tenant_id: For gateway-like integrations with multi-tenant support.
            event_type: (AIDR) Event Type.
            collector_instance_id: (AIDR) collector instance id.
            extra_info: (AIDR) Logging schema.
            count_tokens: Provide input and output token count.
        """
        return self.request.post(
            "v1/guard",
            GuardResult,
            data={
                "input": input,
                "recipe": recipe,
                "debug": debug,
                "overrides": overrides,
                "app_id": app_id,
                "actor_id": actor_id,
                "llm_provider": llm_provider,
                "model": model,
                "model_version": model_version,
                "request_token_count": request_token_count,
                "response_token_count": response_token_count,
                "source_ip": source_ip,
                "source_location": source_location,
                "tenant_id": tenant_id,
                "event_type": event_type,
                "collector_instance_id": collector_instance_id,
                "extra_info": extra_info,
                "count_tokens": count_tokens,
            },
        )


def get_relevant_content(
    messages: Sequence[Message | McpToolsMessage],
) -> tuple[list[Message | McpToolsMessage], list[int]]:
    """
    Returns relevant messages and their indices in the original list.

    1, If last message is "assistant", then the relevant messages are all system
      messages that come before it, plus that last assistant message.
    2. Else, find the last "assistant" message. Then the relevant messages are
      all system messages that come before it, and all messages that come after
      it.
    """

    if len(messages) == 0:
        return [], []

    system_messages = [msg for msg in messages if msg.role == "system"]
    system_indices = [i for i, msg in enumerate(messages) if msg.role == "system"]

    # If the last message is assistant, then return all system messages and that
    # assistant message.
    if messages[-1].role == "assistant":
        return system_messages + [messages[-1]], system_indices + [len(messages) - 1]

    # Otherwise, work backwards until we find the last assistant message, then
    # return all messages after that.
    last_assistant_index = -1
    for i in range(len(messages) - 1, -1, -1):
        if messages[i].role == "assistant":
            last_assistant_index = i
            break

    relevant_messages = []
    indices = []
    for i, msg in enumerate(messages):
        if msg.role == "system" or i > last_assistant_index:
            relevant_messages.append(msg)
            indices.append(i)

    return relevant_messages, indices


def patch_messages(
    original: Sequence[Message | McpToolsMessage],
    original_indices: list[int],
    transformed: Sequence[PromptMessage],
) -> list[Message | McpToolsMessage | PromptMessage]:
    if len(original) == len(transformed):
        return list(transformed)

    return [
        transformed[original_indices.index(i)] if i in original_indices else orig for i, orig in enumerate(original)
    ]
