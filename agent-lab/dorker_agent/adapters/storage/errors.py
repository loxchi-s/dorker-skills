"""Storage adapter exceptions for content-addressed artifact persistence."""


class ArtifactStoreError(RuntimeError):
    """Base error for artifact storage failures."""


class ArtifactNotFoundError(ArtifactStoreError):
    """The requested content digest is not present."""


class ArtifactIntegrityError(ArtifactStoreError):
    """Stored bytes do not match their content address."""
