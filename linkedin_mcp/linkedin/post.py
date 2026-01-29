"""LinkedIn post-related models and exceptions.

Note: Post creation logic is now handled directly in server.py
using the FastMCP OAuth proxy for authentication.
This module contains only models and exceptions for API interactions.
"""
from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, FilePath


class PostCreationError(Exception):
    """Raised when post creation fails."""
    pass


class MediaUploadError(Exception):
    """Raised when media upload fails."""
    pass


class MediaCategory(str, Enum):
    """Valid media categories."""
    NONE = "NONE"
    IMAGE = "IMAGE"
    VIDEO = "VIDEO"
    ARTICLE = "ARTICLE"


class PostVisibility(str, Enum):
    """Valid post visibility values."""
    PUBLIC = "PUBLIC"
    CONNECTIONS = "CONNECTIONS"


class MediaRequest(BaseModel):
    """Media attachment request."""
    file_path: FilePath
    title: Optional[str] = None
    description: Optional[str] = None


class PostRequest(BaseModel):
    """LinkedIn post request model."""
    text: str
    visibility: PostVisibility = PostVisibility.PUBLIC
    media: Optional[List[MediaRequest]] = None
