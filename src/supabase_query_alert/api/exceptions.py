class ManagementAPIError(Exception):
    pass


class RateLimitError(ManagementAPIError):
    def __init__(
        self, message: str = "Rate limit exceeded", retry_after: float | None = None
    ) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class AuthenticationError(ManagementAPIError):
    pass


class NotFoundError(ManagementAPIError):
    pass
