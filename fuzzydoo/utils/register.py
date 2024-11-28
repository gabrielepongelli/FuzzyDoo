from typing import Generic, TypeVar, Type, Any
from collections.abc import Callable


RegistrableT = TypeVar('RegistrableT')

RegisterT = dict[str | Any, Type[RegistrableT] | "RegisterT"]


class ClassRegister(Generic[RegistrableT]):
    """A generic class registry for managing and retrieving registered classes.

    This class provides a mechanism to register and retrieve classes based on a hierarchical naming 
    scheme. It allows for flexible classification and easy access to registered classes.

    Example:
        >>> @register("BaseClass")
        >>> class MyClass:
        >>>     pass
        >>> 
        >>> # Retrieve the class
        >>> cls = ClassRegister[MyClass].get("BaseClass", "MyClass")
    """

    _registered_classes: RegisterT[RegistrableT] = {}

    @classmethod
    def get(cls, name: str, *args) -> Type[RegistrableT]:
        """Retrieve a registered class based on its name and optional classification arguments.

        This method searches the class registry for a class matching the given base name and 
        additional classification arguments. It traverses the hierarchical structure of the 
        registry to find the most specific class matching the provided criteria.

        Args:
            name: The base name of the class to retrieve. This is the primary identifier
                for the class category in the registry.
            *args: Variable length argument list of strings. Each argument represents an additional 
                level of classification or specialization for the desired class. These are used to 
                navigate the nested structure of the registry.

        Returns:
            Type[RegistrableT]: The registered class that matches the given name and classification 
                arguments.

        Raises:
            ValueError: If no class matching the given name and classification exists in the 
                registry. This could occur if the class hasn't been registered or if the
                provided classification path is invalid.
        """

        try:
            cls_reg = cls._registered_classes[name]
            for arg in args:
                cls_reg = cls_reg[arg]
            return cls_reg
        except KeyError as e:
            raise ValueError("Unknown class specified") from e

    @classmethod
    def _register_rec(cls, reg: RegisterT, update: RegisterT) -> RegisterT:
        """Recursively update the register with new values.

        This method is a helper for the `register` method. It recursively traverses the `update` 
        dictionary and updates the corresponding entries in the `reg` dictionary. If a key in 
        `update` corresponds to a nested dictionary, it recursively updates that nested structure.

        Args:
            reg: The existing register dictionary to be updated.
            update: The dictionary containing new values to be added or updated in the register.

        Returns:
            RegisterT: The updated register dictionary after incorporating all changes from the 
                update.

        Note:
            This method modifies the `reg` dictionary in-place and also returns it for convenience.
        """

        for k, v in update.items():
            if isinstance(v, dict):
                reg[k] = cls._register_rec(reg.get(k, {}), v)
            else:
                reg[k] = v

        return reg

    @classmethod
    def register(cls, registrable: Type[RegistrableT], name: str, *args):
        """Register a new class in the class registry.

        This method adds a new class to the registry, allowing it to be retrieved later using the
        `get` method. The class can be registered with a hierarchical classification structure.

        Args:
            registrable: The class to be registered.
            name: The base name or primary category under which the class will be registered. This 
                serves as the top-level key in the registry.
            *args: Variable length argument list of strings. Each argument represents an additional
                level of classification or specialization for the class being registered. These are
                used to create a nested structure in the registry.

        Note:
            If no additional args are provided, the class is registered directly under the base 
            name. If args are provided, they create a nested structure in the registry, with the 
            class being placed at the deepest level of this structure.
        """

        if len(args) == 0:
            update: RegisterT = {name: registrable}
        else:
            update: RegisterT = {args[-1]: registrable}
            args = args[:-1]
            for arg in args[::-1]:
                update = {arg: update}
            update = {name: update}

        cls._registered_classes = cls._register_rec(
            cls._registered_classes, update)


def register(name: str | type, *args, append_name: bool = True) -> Callable[[RegistrableT], RegistrableT]:
    """Decorator that registers a class in the specified category.

    This decorator works together with the `ClassRegister` class to register a class under a 
    specified category and optional subcategories.

    Args:
        name: The base name or category under which the class will be registered. If a type is 
            provided, its class name will be used as the base name.
        *args: Additional classification arguments that further specify the subcategories for the 
            class registration. The name of the decorated class is automatically appended as the 
            last argument.
        append_name (optional): Whether to automatically append the name of the decorated class as 
            the last argument of `args`. Defaults to `True`.

    Returns:
        Callable[[RegistrableT], RegistrableT]: A decorator function that registers the class and 
            returns it unchanged.
    """

    def decorator(cls: RegistrableT) -> RegistrableT:
        nonlocal args, name

        if isinstance(name, type):
            name = name.__name__

        if append_name:
            args = args + (cls.__name__,)

        ClassRegister.register(cls, name, *args)
        return cls

    return decorator
