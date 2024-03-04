import asyncio
import datetime
import logging
import unittest
from http.client import HTTPConnection

import pangea.exceptions as pe
from pangea import PangeaConfig
from pangea.asyncio.services import ShareAsync
from pangea.asyncio.services.share import FileUploaderAsync
from pangea.response import PangeaResponse, TransferMethod
from pangea.services.share.share import (
    ArchiveFormat,
    Authenticator,
    AuthenticatorType,
    LinkType,
    PutResult,
    ShareLinkCreateItem,
    ShareLinkSendItem,
)
from pangea.tools import TestEnvironment, get_test_domain, get_test_token, logger_set_pangea_config
from pangea.utils import get_file_upload_params

TEST_ENVIRONMENT = TestEnvironment.DEVELOP
PDF_FILEPATH = "./tests/testdata/testfile.pdf"
TIME = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
FOLDER_DELETE = f"/sdk_tests/delete/{TIME}"
FOLDER_FILES = f"/sdk_tests/files/{TIME}"
METADATA = {"field1": "value1", "field2": "value2"}
ADD_METADATA = {"field3": "value3"}
TAGS = ["tag1", "tag2"]
ADD_TAGS = ["tag3"]


def get_test_file():
    return open(PDF_FILEPATH, "rb")


def debug_requests_on():
    """Switches on logging of the requests module."""
    HTTPConnection.debuglevel = 1

    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


class TestShare(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # debug_requests_on()
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(
            domain=domain, custom_user_agent="sdk-test", queued_retry_enabled=True, poll_result_timeout=240
        )
        self.client = ShareAsync(token, config=config)
        logger_set_pangea_config(logger_name=self.client.logger.name)

    async def asyncTearDown(self):
        await self.client.close()

    async def test_folder(self):
        try:
            resp_create = await self.client.folder_create(path=FOLDER_DELETE)
            self.assertEqual(resp_create.status, "Success")
            self.assertNotEqual(resp_create.result.object.id, "")
            self.assertEqual(resp_create.result.object.type, "folder")
            self.assertNotEqual(resp_create.result.object.name, "")
            self.assertNotEqual(resp_create.result.object.created_at, "")
            self.assertNotEqual(resp_create.result.object.updated_at, "")
            id = resp_create.result.object.id

            resp_delete = await self.client.delete(id=id)
            self.assertEqual(resp_delete.status, "Success")
            self.assertEqual(resp_delete.result.count, 1)
        except pe.PangeaAPIException as e:
            print(e)
            print(type(e))
            self.assertTrue(False)

    async def test_put_transfer_method_post_url(self):
        try:
            with get_test_file() as f:
                name = f"{TIME}_file_post_url"
                response = await self.client.put(file=f, name=name, transfer_method=TransferMethod.POST_URL)
                self.assertEqual(response.status, "Success")
        except pe.PangeaAPIException as e:
            print(e)
            print(type(e))
            self.assertTrue(False)

    async def test_put_transfer_method_multipart(self):
        try:
            with get_test_file() as f:
                name = f"{TIME}_file_multipart"
                response = await self.client.put(file=f, name=name, transfer_method=TransferMethod.MULTIPART)
                self.assertEqual(response.status, "Success")
                self.assertEqual(response.result.object.name, name)
        except pe.PangeaAPIException as e:
            print(e)
            print(type(e))
            self.assertTrue(False)

    async def test_split_upload_file_post(self):
        with get_test_file() as f:
            name = f"{TIME}_file_split_post_url"
            params = get_file_upload_params(f)
            response = await self.client.request_upload_url(
                name=name,
                transfer_method=TransferMethod.POST_URL,
                crc32c=params.crc_hex,
                sha256=params.sha256_hex,
                size=params.size,
            )
            url = response.accepted_result.post_url
            file_details = response.accepted_result.post_form_data

            uploader = FileUploaderAsync()
            await uploader.upload_file(
                url=url, name=name, file=f, transfer_method=TransferMethod.POST_URL, file_details=file_details
            )

        max_retry = 24
        for retry in range(max_retry):
            try:
                # wait some time to get result ready and poll it
                await asyncio.sleep(10)

                response: PangeaResponse[PutResult] = await self.client.poll_result(response=response)
                self.assertEqual(response.status, "Success")
                break
            except pe.PangeaAPIException:
                self.assertLess(retry, max_retry - 1)

    async def test_split_upload_file_put(self):
        with get_test_file() as f:
            name = f"{TIME}_file_split_put_url"
            response = await self.client.request_upload_url(name=name, transfer_method=TransferMethod.PUT_URL)
            url = response.accepted_result.put_url

            uploader = FileUploaderAsync()
            await uploader.upload_file(url=url, name=name, file=f, transfer_method=TransferMethod.PUT_URL)

        max_retry = 24
        for retry in range(max_retry):
            try:
                # wait some time to get result ready and poll it
                await asyncio.sleep(10)

                response: PangeaResponse[PutResult] = await self.client.poll_result(response=response)
                self.assertEqual(response.status, "Success")
                break
            except pe.PangeaAPIException:
                self.assertLess(retry, max_retry - 1)

    async def test_life_cycle(self):
        # Create a folder
        resp_create = await self.client.folder_create(path=FOLDER_FILES)
        folder_id = resp_create.result.object.id
        self.assertEqual(resp_create.status, "Success")

        # Upload a file with path as unique param
        with get_test_file() as f:
            path = FOLDER_FILES + f"/{TIME}_file_multipart_1"
            resp_put_path = await self.client.put(file=f, path=path, transfer_method=TransferMethod.MULTIPART)

        self.assertEqual(resp_put_path.status, "Success")
        self.assertEqual(folder_id, resp_put_path.result.object.parent_id)
        self.assertIsNone(resp_put_path.result.object.metadata)
        self.assertIsNone(resp_put_path.result.object.tags)
        self.assertIsNone(resp_put_path.result.object.md5)
        self.assertIsNotNone(resp_put_path.result.object.sha256)
        self.assertIsNone(resp_put_path.result.object.sha512)

        # Upload a file with parent id and name
        with get_test_file() as f:
            name = f"{TIME}_file_multipart_2"
            resp_put_id = await self.client.put(
                file=f,
                parent_id=folder_id,
                name=name,
                transfer_method=TransferMethod.MULTIPART,
                metadata=METADATA,
                tags=TAGS,
            )
        self.assertEqual(resp_put_id.status, "Success")
        self.assertEqual(folder_id, resp_put_id.result.object.parent_id)
        self.assertEqual(METADATA, resp_put_id.result.object.metadata)
        self.assertEqual(TAGS, resp_put_id.result.object.tags)
        self.assertIsNone(resp_put_id.result.object.md5)
        self.assertIsNotNone(resp_put_id.result.object.sha256)
        self.assertIsNone(resp_put_id.result.object.sha512)

        # Update file. full metadata and tags
        resp_update = await self.client.update(id=resp_put_path.result.object.id, metadata=METADATA, tags=TAGS)
        self.assertTrue(resp_update.success)
        self.assertEqual(METADATA, resp_update.result.object.metadata)
        self.assertEqual(TAGS, resp_update.result.object.tags)

        # Update file. add metadata and tags
        resp_update_add = await self.client.update(
            id=resp_put_path.result.object.id, add_metadata=ADD_METADATA, add_tags=ADD_TAGS
        )
        self.assertTrue(resp_update_add.success)
        metadata_final = {}
        metadata_final.update(METADATA)
        metadata_final.update(ADD_METADATA)
        self.assertEqual(metadata_final, resp_update_add.result.object.metadata)
        tags_final = []
        tags_final.extend(TAGS)
        tags_final.extend(ADD_TAGS)
        self.assertEqual(tags_final, resp_update_add.result.object.tags)

        # Get archive
        resp_get_archive = await self.client.get_archive(
            ids=[folder_id], format=ArchiveFormat.ZIP, transfer_method=TransferMethod.MULTIPART
        )
        self.assertTrue(resp_get_archive.success)
        self.assertEqual(len(resp_get_archive.attached_files), 1)
        for af in resp_get_archive.attached_files:
            af.save("./")

        resp_get_archive = await self.client.get_archive(
            ids=[folder_id], format=ArchiveFormat.TAR, transfer_method=TransferMethod.DEST_URL
        )
        self.assertTrue(resp_get_archive.success)
        self.assertEqual(len(resp_get_archive.attached_files), 0)
        self.assertIsNotNone(resp_get_archive.result.dest_url)

        # Download file
        await self.client.download_file(url=resp_get_archive.result.dest_url)
        await self.client.download_file(url=resp_get_archive.result.dest_url, filename="download.tar")
        await self.client.download_file(url=resp_get_archive.result.dest_url, dest_folder="./download/")
        await self.client.download_file(
            url=resp_get_archive.result.dest_url, filename="download.tar", dest_folder="./download/"
        )

        # Create share link
        authenticators = [Authenticator(auth_type=AuthenticatorType.PASSWORD, auth_context="somepassword")]
        link_list = [
            ShareLinkCreateItem(
                targets=[folder_id],
                link_type=LinkType.EDITOR,
                max_access_count=3,
                authenticators=authenticators,
                message="hello",
                title="share link",
            )
        ]
        resp_create_link = await self.client.share_link_create(links=link_list)

        links = resp_create_link.result.share_link_objects
        self.assertEqual(len(links), 1)

        link = links[0]
        self.assertEqual(link.access_count, 0)
        self.assertEqual(link.max_access_count, 3)
        self.assertEqual(len(link.authenticators), 1)
        self.assertEqual(link.authenticators[0].auth_type, AuthenticatorType.PASSWORD.value)

        self.assertIsNotNone(link.link)
        self.assertNotEqual(link.link, "")
        self.assertIsNotNone(link.id)
        self.assertNotEqual(link.id, "")

        self.assertEqual(len(link.targets), 1)

        # Send link
        resp_send_link = await self.client.share_link_send(
            links=[ShareLinkSendItem(id=link.id, email="email@pangea.cloud")],
            sender_email="share@pangea.cloud",
            sender_name="Pangea",
        )
        self.assertTrue(len(resp_send_link.result.share_link_objects) > 0)

        # Get share link
        resp_get_link = await self.client.share_link_get(id=link.id)
        self.assertTrue(resp_get_link.success)
        self.assertEqual(resp_get_link.result.share_link_object.link, link.link)
        self.assertEqual(resp_get_link.result.share_link_object.access_count, 0)
        self.assertEqual(resp_get_link.result.share_link_object.max_access_count, link.max_access_count)
        # self.assertEqual(resp_get_link.result.share_link_object.created_at, link.created_at)
        # self.assertEqual(resp_get_link.result.share_link_object.expires_at, link.expires_at)

        # List share link
        resp_list_link = await self.client.share_link_list()
        self.assertTrue(resp_list_link.success)
        self.assertTrue(resp_list_link.result.count > 0)
        self.assertTrue(len(resp_list_link.result.share_link_objects) > 0)

        # Delete share link
        resp_delete_link = await self.client.share_link_delete(ids=[link.id])
        self.assertTrue(resp_delete_link.success)
        self.assertEqual(len(resp_delete_link.result.share_link_objects), 1)

        # List files in folder
        list_filter = {
            "folder": FOLDER_FILES,
        }
        resp_list = await self.client.list(filter=list_filter)
        self.assertTrue(resp_list.success)
        self.assertEqual(resp_list.result.count, 2)
        self.assertEqual(len(resp_list.result.objects), 2)
