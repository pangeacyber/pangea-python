from __future__ import annotations

from typing import List, Optional

from typing_extensions import Literal

from pangea.response import PangeaResponse, PangeaResponseResult
from pangea.services.base import ServiceBase
from pangea.services.intel import UserBreachedData


class TextGuardSecurityIssues(PangeaResponseResult):
    compromised_email_addresses: int
    malicious_domain_count: int
    malicious_ip_count: int
    malicious_url_count: int
    redacted_item_count: int


class TextGuardFindings(PangeaResponseResult):
    artifact_count: int
    malicious_count: int
    security_issues: TextGuardSecurityIssues


class RedactRecognizerResult(PangeaResponseResult):
    field_type: str
    """The entity name."""

    score: float
    """The certainty score that the entity matches this specific snippet."""

    text: str
    """The text snippet that matched."""

    start: int
    """The starting index of a snippet."""

    end: int
    """The ending index of a snippet."""

    redacted: bool
    """Indicates if this rule was used to anonymize a text snippet."""


class RedactReport(PangeaResponseResult):
    count: int
    recognizer_results: List[RedactRecognizerResult]


class IntelResults(PangeaResponseResult):
    category: List[str]
    """
    The categories that apply to this indicator as determined by the provider.
    """

    score: int
    """The score, given by the Pangea service, for the indicator."""

    verdict: Literal["malicious", "suspicious", "unknown", "benign"]


class TextGuardReport(PangeaResponseResult):
    domain_intel: Optional[IntelResults] = None
    ip_intel: Optional[IntelResults] = None
    redact: RedactReport
    url_intel: Optional[IntelResults] = None
    user_intel: Optional[UserBreachedData] = None


class TextGuardArtifact(PangeaResponseResult):
    defanged: bool
    end: int
    start: int
    type: str
    value: str
    verdict: Optional[str] = None
    """The verdict, given by the Pangea service, for the indicator."""


class TextGuardResult(PangeaResponseResult):
    artifacts: Optional[List[TextGuardArtifact]] = None
    findings: TextGuardFindings
    redacted_prompt: str

    # `debug=True` only.
    report: Optional[TextGuardReport] = None


class DataGuard(ServiceBase):
    """Data Guard service client.

    Provides methods to interact with Pangea's Data Guard service.
    """

    service_name = "data-guard"

    def guard_text(
        self,
        text: str,
        *,
        recipe: str = "pangea_prompt_guard",
        debug: bool = False,
    ) -> PangeaResponse[TextGuardResult]:
        """
        Text guard (Beta)

        Guard text.

        How to install a [Beta release](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: data_guard_post_v1_text_guard

        Args:
            text: Text.
            recipe: Recipe.
            debug: Debug.

        Examples:
            response = data_guard.guard_text("text")
        """

        return self.request.post(
            "v1/text/guard", TextGuardResult, data={"text": text, "recipe": recipe, "debug": debug}
        )

    def guard_file(
        self,
        file_url: str,
    ) -> PangeaResponse[PangeaResponseResult]:
        """
        File guard (Beta)

        Guard a file URL.

        How to install a [Beta release](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: data_guard_post_v1_file_guard

        Args:
            file_url: File URL.

        Examples:
            response = data_guard.guard_file("https://example.org/file.txt")
        """

        return self.request.post("v1/file/guard", PangeaResponseResult, data={"file_url": file_url})
