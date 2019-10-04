# -*- coding: utf-8 -*-

import pytest
from mock import MagicMock, patch, sentinel

from botocore.exceptions import ClientError

from sceptre.connection_manager import ConnectionManager
from sceptre.stack import Stack

from resolver.kms import KmsResolver, KmsBase
from resolver.exceptions import ParameterNotFoundError


class TestKmsResolver(object):

    @patch(
        "resolver.kms.KmsResolver._get_decoded_value"
    )
    def test_resolve(self, mock_get_decoded_value):
        stack = MagicMock(spec=Stack)
        stack.profile = "test_profile"
        stack.region = "test_region"
        stack.dependencies = []
        stack._connection_manager = MagicMock(spec=ConnectionManager)
        stack_kms_resolver = KmsResolver(
            "/dev/DbPassword", stack
        )
        mock_get_decoded_value.return_value = "parameter_value"
        stack_kms_resolver.resolve()
        mock_get_decoded_value.assert_called_once_with(
            "/dev/DbPassword", "test_profile", "test_region"
        )
        assert stack.dependencies == []


class MockKmsBase(KmsBase):
    """
    MockBaseResolver inherits from the abstract base class
    KmsBase, and implements the abstract methods. It is used
    to allow testing on KmsBase, which is not otherwise
    instantiable.
    """

    def __init__(self, *args, **kwargs):
        super(MockKmsBase, self).__init__(*args, **kwargs)

    def resolve(self):
        pass


class TestKmsBase(object):

    def setup_method(self, test_method):
        self.stack = MagicMock(spec=Stack)
        self.stack.name = "test_name"
        self.stack._connection_manager = MagicMock(
            spec=ConnectionManager
        )
        self.base_kms = MockKmsBase(
            None, self.stack
        )

    @patch(
        "resolver.kms.KmsBase._request_kms_value"
    )
    def test_get_decoded_value_with_valid_key(self, mock_request_kms_value):
        mock_request_kms_value.return_value = {
          "KeyId": "arn:aws:kms:us-east-1:111111111111:key/17c85202-6da4-4ee1-afc9-b8cef983e0d9",
          "Plaintext": b"Secret"
        }

        response = self.base_kms._get_decoded_value("AQICAHjd17DKHzNyNq9XvuZzboDpt6OhdLG7eDPA==")
        assert response == "Secret"

    @patch(
        "resolver.kms.KmsBase._request_kms_value"
    )
    def test_get_decoded_value_with_invalid_response(self, mock_request_kms_value):
        mock_request_kms_value.return_value = {
          "KeyId": "arn:aws:kms:us-east-1:111111111111:key/17c85202-6da4-4ee1-afc9-b8cef983e0d9",
        }

        with pytest.raises(KeyError):
            self.base_kms._get_decoded_value(None)

    def test_request_kms_value_with_invalid_input(self):
        self.stack.connection_manager.call.side_effect = TypeError(
            {
                "Error": {
                    "Code": "500",
                    "Message": "Boom!"
                }
            },
            sentinel.operation
        )

        with pytest.raises(TypeError):
            self.base_kms._request_kms_value(None)

    def test_request_kms_value_with_parameter_not_found(self):
        self.stack.connection_manager.call.side_effect = ClientError(
            {
                "Error": {
                    "Code": "ParameterNotFound",
                    "Message": "Boom!"
                }
            },
            sentinel.operation
        )

        with pytest.raises(ParameterNotFoundError):
            self.base_kms._request_kms_value("AQICAHjd17DKHzNyNq9XvuZzboDpt6OhdLG7eDPA==")
