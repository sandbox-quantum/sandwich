import pysandwich.proto.errors_pb2 as SandwichErrorProto


class SandwichException(Exception):
    """Base class for Sandwich exceptions.

    This class wraps all errors defined in the `errors.proto` file, as well
    as the ones defined in `tunnel.proto` and `io.proto`.

    A Sandwich error lies on an error code.

    Attributes:
        _code: The error code.
    """

    def __init__(
        self,
        code: int,
        kind: SandwichErrorProto.ErrorKind = None,
        msg=None,
        *kargs,
        **kwargs,
    ):
        """Constructs a Sandwich exception from an error code.

        Arguments:
            code:
                Error code.
        """
        if not msg:
            super().__init__(self._resolve_error_string(code), *kwargs, **kwargs)
        else:
            super().__init__(msg.decode("ascii"), *kwargs, **kwargs)
        self._kind = kind
        self._code = code

    @property
    def kind(self) -> SandwichErrorProto.ErrorKind:
        """Returns the error kind.

        Returns:
            The error kind.
        """
        return self._kind

    @property
    def code(self) -> int:
        """Returns the error code.

        Returns:
            The error code.
        """
        return self._code

    def _resolve_error_string(self, code):
        errors_map = None
        try:
            errors_map = self._ERRORS_MAP
        except AttributeError:
            pass
        if (errors_map is not None) and (code in errors_map):
            return errors_map[code]["msg"]
        return f"Unknown error code {code}"

    @classmethod
    def new(
        cls,
        code: int,
        kind: SandwichErrorProto.ErrorKind = None,
        msg: str = None,
    ) -> "SandwichException":
        """Constructs an exception from an error code.

        Returns:
            The most appropriate exception object.
        """
        from pysandwich.generated_error_codes import _ERROR_KIND_MAP

        if target_cls := _ERROR_KIND_MAP.get(kind):
            return target_cls(code, kind, msg)
        errors_map = cls._ERRORS_MAP
        if (
            (errors_map is not None)
            and (code in errors_map)
            and ((target_cls := errors_map[code].get("cls")) is not None)
        ):
            return target_cls()(kind=kind)
        return SandwichException(code=code, kind=kind, msg=msg)
