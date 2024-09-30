from typing import List, Any, Type
from collections.abc import Callable
from dataclasses import dataclass

from ..fuzzable import Fuzzable
from ..utils import Node


@dataclass
class Message(Node):
    """This class encapsulates the logic for creating and managing messages.

    A `Message` is a node of the protocol graph representing a message that can be sent to the 
    target, possibly after being fuzzed. It also decides, based on which fields have been modified, 
    the responses that can be received.

    Attributes:
        name: Name of the message.
        content: The content of the message.
        possible_responses: List of possible response types.
        excluded: List of fields to be excluded from fuzzing.
    """

    def __init__(self, content: Fuzzable, name: str = "", excluded: List[str] | None = None, possible_responses: List[Type] | None = None):
        """Initialize a Message object.

        Args:
            content: The content of the message.
            name (optional): The name of the message. Defaults to the class name.
            excluded (optional): List of fields to be excluded from fuzzing. Defaults to `None`.
            possible_responses (optional): List of possible response types. Defaults to `None`.
        """

        super().__init__(0)  # ids will be managed by the Protocol

        # assign the class name as the default name for the node
        self.name: str = name if name else self.__class__.__name__
        self.content: Fuzzable = content
        self.possible_responses: List[Type] = possible_responses
        self.excluded: List[Type] = excluded

    @property
    def response_required(self) -> bool:
        """Check if responses are required for this message.

        Returns:
            bool: `True` if possible responses are defined, `False` otherwise.
        """

        return self.possible_responses is not None and len(self.possible_responses) > 0


Relation = Callable[..., bool]


@dataclass
class Response:
    """The `Response` class represents a response that can be received from the target.

    It is a part of the protocol graph and is associated with a specific request message. The 
    `Response` class encapsulates the logic for validating the response based on certain 
    conditions, called `relations`, with the associated request message.

    Attributes:
        name: Name of the response.
        content: Content of the response.
        request: Associated request message.
        relations: A list of relations that the response must satisfy with respect to the request 
            message. These relations are defined as functions or callable objects that take the 
            request content as first argument and the response content as second argument, and 
            return a boolean value indicating whether the relation holds. If the relations list is 
            `None` or empty, it means that no specific relations are required for the response to 
            be valid.
    """

    def __init__(self, request: Message, name: str = "", content: Any = None, relations: List[Relation] | None = None):
        """Initialize a `Response` object.

        Args:
            request: The associated request message.
            name (optional): The name of the response. Defaults to the class name.
            content (optional): The content of the response. Defaults to `None`.
            relations (optional): A list of relations that the response must satisfy. Defaults to 
                `None`.
        """

        self.name: str = name if name else self.__class__.__name__
        self.content: Any = content
        self.request: Message = request
        self.relations: List[Relation] | None = relations

    def check(self) -> bool:
        """Check if all the relations with the request message are satisfied.

        Returns:
            bool: `True` if all relations pass, `False` otherwise.
        """

        for rel in self.relations:
            if not rel(self.request.content, self.content):
                return False
        return True
