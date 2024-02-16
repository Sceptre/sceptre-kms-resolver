# -*- coding: utf-8 -*-

import abc
import base64
import six
import logging

from botocore.exceptions import ClientError

from sceptre.resolvers import Resolver
from resolver.exceptions import ParameterNotFoundError

TEMPLATE_EXTENSION = ".yaml"


@six.add_metaclass(abc.ABCMeta)
class KmsBase(Resolver):
    """
    A abstract base class which provides methods for getting KMS parameters.
    """

    def __init__(self, *args, **kwargs):
        self.logger = logging.getLogger(__name__)
        super(KmsBase, self).__init__(*args, **kwargs)

    def _get_decoded_value(self, param, profile=None, region=None):
        """
        Attempts to get the KMS parameter named by ``param``

        :param param: The name of the KMS parameter in which to return.
        :type param: str
        :returns: KMS parameter value.
        :rtype: str
        :raises: KeyError
        """
        response = self._request_kms_value(param, profile, region)

        try:
            binary_value = response["Plaintext"]
            decoded_value = binary_value.decode()
            return decoded_value
        except KeyError:
            self.logger.error(
                "%s - Invalid response looking for: %s", self.stack.name, param
            )
            raise

    def _request_kms_value(self, param, profile=None, region=None):
        """
        Communicates with AWS CloudFormation to fetch KMS parameters.

        :returns: The decoded value of the parameter
        :rtype: dict
        :raises: resolver.exceptions.ParameterNotFoundError
        """
        connection_manager = self.stack.connection_manager
        ciphertext = param
        ciphertext_blob = base64.b64decode(ciphertext)

        try:
            response = connection_manager.call(
                service="kms",
                command="decrypt",
                kwargs={"CiphertextBlob": ciphertext_blob},
                profile=profile,
                region=region,
            )
        except TypeError as e:
            raise e
        except ClientError as e:
            if "ParameterNotFound" in e.response["Error"]["Code"]:
                self.logger.error("%s - ParameterNotFound: %s", self.stack.name, param)
                raise ParameterNotFoundError(e.response["Error"]["Message"])
            else:
                raise e
        else:
            return response


class KmsResolver(KmsBase):
    """
    Resolver for retrieving the value of an KMS parameter.

    :param argument: The parameter name to get.
    :type argument: str
    """

    def __init__(self, *args, **kwargs):
        super(KmsResolver, self).__init__(*args, **kwargs)

    def resolve(self):
        """
        Retrieves the value of KMS parameter

        :returns: The decoded value of the KMS parameter
        :rtype: str
        """
        self.logger.debug("Resolving KMS parameter: {0}".format(self.argument))

        value = None
        profile = self.stack.profile
        region = self.stack.region
        if self.argument:
            param = self.argument
            value = self._get_decoded_value(param, profile, region)

        return value
