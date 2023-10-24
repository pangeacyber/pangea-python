from functools import wraps

from deprecated import deprecated


def pangea_deprecated(*args, **kwargs):
    """
    Use this decorator to mark something as deprecated.

    This is what gets it to show up in our generated SDK docs.

    Example:
      @pangea_deprecated(version="1.2.0", reason="Should use FileIntel.hashReputation()")
      def lookup()
    """

    def decorator(f):
        @wraps(f)
        def wrapper(*iargs, **ikwargs):
            return deprecated(*args, **kwargs)(f)(*iargs, **ikwargs)

        setattr(wrapper, "_deprecated", kwargs)
        return wrapper

    return decorator
