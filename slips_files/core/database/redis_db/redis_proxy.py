class RedisProxy:
    """
    the goal of this class is to provide a proxy for Redis client operations.
    so we can use a context manager AND access self.r like this
    self.r instead of self._ctx.get(None) in all the db functions.
    """

    def __init__(self, context_var, factory):
        self._ctx = context_var
        # the function that creates a new Redis client
        self._factory = factory

    def __getattr__(self, name):
        client = self._ctx.get(None)
        if client is None:
            client = self._factory()
            self._ctx.set(client)
        return getattr(client, name)
