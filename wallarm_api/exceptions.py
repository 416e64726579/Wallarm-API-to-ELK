class NonSuccessResponse(Exception):
    pass


class ClosedSocket(Exception):
    pass


class EnvVariableNotSet(Exception):
    pass


class NoSchemeDefined(Exception):
    print('Specify one of the following schemes: http://, https://, tcp://, udp://')

