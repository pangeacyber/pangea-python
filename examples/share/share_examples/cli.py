from __future__ import annotations

import logging
from pathlib import Path

import click
from pangea.config import PangeaConfig
from pangea.services.share.share import (
    Authenticator,
    AuthenticatorType,
    LinkType,
    Share,
    ShareLinkCreateItem,
)


@click.command()
@click.option(
    "--input",
    "-i",
    "input_",
    type=click.Path(exists=True, resolve_path=True, path_type=Path),
    required=True,
    help="Local path to upload.",
)
@click.option(
    "--dest",
    type=str,
    default="/",
    help="Destination path in Share.",
)
@click.option("--email", type=str, help="Email address to protect the share link with.")
@click.option("--phone", type=str, help="Phone number to protect the share link with.")
@click.option("--password", type=str, help="Password to protect the share link with.")
@click.option(
    "--link-type",
    type=click.Choice([x.value for x in LinkType], case_sensitive=False),
    default=LinkType.DOWNLOAD,
    help="Type of link.",
)
@click.option(
    "--share-token",
    envvar="PANGEA_SHARE_TOKEN",
    required=True,
    help="Pangea Secure Share API token. May also be set via the `PANGEA_SHARE_TOKEN` environment variable.",
)
@click.option(
    "--pangea-domain",
    envvar="PANGEA_DOMAIN",
    required=True,
    help="Pangea API domain. May also be set via the `PANGEA_DOMAIN` environment variable.",
)
def share(
    *,
    input_: Path,
    dest: str = "/",
    email: str | None = None,
    phone: str | None = None,
    password: str | None = None,
    link_type: LinkType = LinkType.DOWNLOAD,
    share_token: str,
    pangea_domain: str,
) -> None:
    """
    An example command line utility that creates an email+code, SMS+code, or
    password-secured download/upload/editor share-link for a given file or
    for each file in a given directory.
    """

    if not any([email, phone, password]):
        raise click.UsageError("At least one of --email, --phone, or --password must be provided.")

    authenticators: list[Authenticator] = []
    if password:
        authenticators.append(Authenticator(auth_type=AuthenticatorType.PASSWORD, auth_context=password))
    if email:
        authenticators.append(Authenticator(auth_type=AuthenticatorType.EMAIL_OTP, auth_context=email))
    if phone:
        authenticators.append(Authenticator(auth_type=AuthenticatorType.SMS_OTP, auth_context=phone))

    share = Share(share_token, config=PangeaConfig(domain=pangea_domain))
    share.logger.setLevel(logging.FATAL)

    # Upload files.
    files = input_.iterdir() if input_.is_dir() else [input_]
    object_ids: list[str] = []
    for file in files:
        with file.open("rb") as f:
            upload_response = share.put(f, folder=f"{dest}/{file.name}")
            assert upload_response.result
            object_ids.append(upload_response.result.object.id)

    # Create share link.
    link_response = share.share_link_create(
        [ShareLinkCreateItem(targets=object_ids, link_type=link_type, authenticators=authenticators)]
    )
    assert link_response.result
    click.echo(link_response.result.share_link_objects[0].link)


if __name__ == "__main__":
    share()
