from __future__ import annotations

import os

from pytest_httpserver import HTTPServer
from pytest_httpserver.httpserver import HandlerType

from pangea import PangeaConfig
from pangea.asyncio.services import EmbargoAsync
from pangea.services import Embargo

base_url = os.environ.get("TEST_API_BASE_URL", "http://127.0.0.1:4010")


def _mock_failures(httpserver: HTTPServer) -> None:
    # First failure.
    httpserver.expect_request("/v1/ip/check", method="POST", handler_type=HandlerType.ONESHOT).respond_with_json(
        {
            "request_id": "prq_11111111111111111111111111111111",
            "request_time": "2025-07-31T14:27:58.899758Z",
            "response_time": "2025-07-31T14:27:59.659923Z",
            "status": "InternalError",
            "summary": "Internal Error. Contact support@pangea.cloud if the error persists.",
            "result": None,
        },
        status=500,
        headers={"x-request-id": "prq_11111111111111111111111111111111"},
    )

    # Second failure.
    httpserver.expect_request(
        "/v1/ip/check",
        method="POST",
        headers={"X-Pangea-Retried-Request-Ids": "prq_11111111111111111111111111111111"},
        handler_type=HandlerType.ONESHOT,
    ).respond_with_json(
        {
            "request_id": "prq_22222222222222222222222222222222",
            "request_time": "2025-07-31T14:27:58.899758Z",
            "response_time": "2025-07-31T14:27:59.659923Z",
            "status": "InternalError",
            "summary": "Internal Error. Contact support@pangea.cloud if the error persists.",
            "result": None,
        },
        status=500,
        headers={"x-request-id": "prq_22222222222222222222222222222222"},
    )

    # Third attempt succeeds.
    httpserver.expect_request(
        "/v1/ip/check",
        method="POST",
        header_value_matcher=lambda key, actual, expected: key == "X-Pangea-Retried-Request-Ids"
        and actual is not None
        and (
            actual == expected or actual == "prq_22222222222222222222222222222222,prq_11111111111111111111111111111111"
        ),
        headers={
            # Note that the ordering is not deterministic. The important part is
            # that both request IDs are present.
            "X-Pangea-Retried-Request-Ids": "prq_11111111111111111111111111111111,prq_22222222222222222222222222222222"
        },
        handler_type=HandlerType.ONESHOT,
    ).respond_with_json(
        {
            "request_id": "prq_33333333333333333333333333333333",
            "request_time": "2025-07-31T14:27:58.899758Z",
            "response_time": "2025-07-31T14:27:59.659923Z",
            "status": "Success",
            "summary": "Failed to find info for IP: 127.0.0.1",
            "result": None,
        },
        status=200,
        headers={"x-request-id": "prq_33333333333333333333333333333333"},
    )


def test_retries(httpserver: HTTPServer):
    _mock_failures(httpserver)

    client = Embargo(token="my_api_token", config=PangeaConfig(base_url_template=httpserver.url_for("/")))
    response = client.ip_check("127.0.0.1")
    assert response.request_id == "prq_33333333333333333333333333333333"
    assert response.http_status == 200


async def test_retries_async(httpserver: HTTPServer):
    _mock_failures(httpserver)

    async with EmbargoAsync(
        token="my_api_token", config=PangeaConfig(base_url_template=httpserver.url_for("/"))
    ) as client:
        response = await client.ip_check("127.0.0.1")
        assert response.request_id == "prq_33333333333333333333333333333333"
        assert response.http_status == 200
