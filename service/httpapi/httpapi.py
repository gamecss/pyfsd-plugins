"""PyFSD PyFSDPlugin plugin :: httpapi.py
Version: -2
"""

from json import JSONDecodeError, JSONEncoder, dumps, loads
from re import compile
from typing import TYPE_CHECKING, Any, Dict, List, Tuple, Type, Union

from twisted.application.internet import TCPServer
from twisted.internet.defer import Deferred
from twisted.logger import Logger
from twisted.plugin import IPlugin
from twisted.python.compat import nativeString
from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET, Site
from zope.interface import implementer

from ..define.utils import MayExist, verifyConfigStruct
from ..plugin import BasePyFSDPlugin
from ..service import config as all_config

try:
    from pyfsd.plugins.whazzup import whazzupGenerator
except ImportError:
    raise ImportError("httpapi plugin requires whazzup plugin.")

if TYPE_CHECKING:
    from twisted.python.failure import Failure
    from twisted.web.server import Request

    from ..service import PyFSDService

config: dict
encoder: Type[JSONEncoder]
is_sha256_regex = compile("^[a-fA-F0-9]{64}$")


def makeEncoder(encoding):
    class Encoder(JSONEncoder):
        def default(self, o: Any) -> Any:
            assert config is not None
            if isinstance(o, bytes):
                return o.decode(encoding=encoding, errors="replace")
            else:
                return super().default(o)

    return Encoder


@implementer(IPlugin)
class PluginTCPServer(TCPServer):
    ...


@implementer(IPlugin)
class HTTPAPIPlugin(BasePyFSDPlugin, Resource):
    plugin_name = "httpapi"
    pyfsd: "PyFSDService"
    isLeaf = True
    logger = Logger()

    def beforeStart(self, pyfsd: "PyFSDService", _) -> None:
        self.pyfsd = pyfsd

    def render(self, request: "Request") -> Union[bytes, int]:
        request.setHeader("Content-Type", "application/json")
        method = getattr(self, "renderJson_" + nativeString(request.method), None)
        if method is None or not hasattr(method, "__call__"):
            request.setResponseCode(501)
            return (
                b'{"message": "Not Implemented", "method": "%s"}'
                % request.method.replace(b'"', b'\\"')
            )
        try:
            result = method(request, request.uri.removeprefix(b"/").split(b"/"))
        except BaseException:
            request.setResponseCode(500)
            self.logger.failure("Error info:")
            return b'{"message": "Internal Server Error"}'
        if isinstance(result, dict):
            return dumps(result, ensure_ascii=False, cls=encoder).encode()
        elif isinstance(result, Deferred):

            def errback(failure: "Failure"):
                self.logger.failure(
                    f"Error happend in {'renderJson_' + nativeString(request.method)}",
                    failure=failure,
                )
                if not request.finished:
                    request.write(b'{"message": "Internal Server Error"}')
                    request.finish()

            result.addErrback(errback)
            return NOT_DONE_YET
        elif isinstance(result, int):
            return result
        elif isinstance(result, bytes):
            return result
        else:
            request.setResponseCode(500)
            self.logger.error("renderer returned invaild data: {data}", data=result)
            return b'{"message": "Internal Server Error"}'

    def renderJson_GET(
        self, request: "Request", path: List[bytes]
    ) -> Union[dict, Deferred]:
        request.setHeader("Content-Type", "application/json")
        if path == [b"whazzup.json"]:
            return whazzupGenerator.generateWhazzup(
                heading_instead_pbh=config["use_heading"]
            )
        elif path[0] == b"query":
            if len(path) > 2:
                request.setResponseCode(404)
                return {"message": "Not Found"}
            if self.pyfsd.db_pool is None:
                request.setResponseCode(503)
                return {"message": "Service Unavailable"}
            if len(path) == 2:
                # Query single

                def handler(result: List[Tuple[str, int]]):
                    if len(result) == 0:
                        request.write(b'{"exist": false}')
                    else:
                        request.write(b'{"exist": true, "rating": %d}' % result[0][1])
                    request.finish()

                return self.pyfsd.db_pool.runQuery(
                    "SELECT callsign, rating FROM users WHERE callsign = ?;",
                    (path[1].decode(errors="replace"),),
                ).addCallback(handler)
            else:
                # Query all

                def handler(result: List[Tuple[str, int]]):
                    info: Dict[int, List[str]] = {}
                    for user in result:
                        callsign, rating = user
                        if rating not in info:
                            info[rating] = []
                        info[rating].append(callsign)
                    request.write(
                        dumps(
                            {"rating": info}, ensure_ascii=False, cls=encoder
                        ).encode()
                    )
                    request.finish()

                return self.pyfsd.db_pool.runQuery(
                    "SELECT callsign, rating FROM users;",
                ).addCallback(handler)
        else:
            request.setResponseCode(404)
            return {"message": "Not Found"}

    def renderJson_POST(
        self, request: "Request", path: List[bytes]
    ) -> Union[dict, Deferred]:
        def checkBody(fmt: dict, check_token: bool = True) -> Tuple[bool, dict]:
            """
            Args:
                fmt: Format. Like verifyConfigStruct's structure.
                check_token: Check token in body.
            Returns:
                return[1] is body if return[0] == True else return[1] is response
            """
            try:
                body = loads(
                    request.content.read().decode(  # type: ignore[attr-defined]
                        errors="replace"
                    )
                )
            except JSONDecodeError:
                request.setResponseCode(400)
                return False, {"message": "Invaild body"}
            if check_token and body.get("token") != config["token"]:
                request.setResponseCode(403)
                return False, {"message": "Forbidden"}
            try:
                verifyConfigStruct(body, fmt)
            except (TypeError, KeyError):
                return False, {"message": "Invaild body struct"}
            return True, body

        if path == [b"create"]:
            is_body, arg2 = checkBody(
                {"callsign": str, "password": str}, check_token=True
            )
            if not is_body:
                return arg2
            else:
                if self.pyfsd.db_pool is None:
                    request.setResponseCode(503)
                    return {"message": "Service Unavailable"}
                body = arg2
                if is_sha256_regex.match(body["password"]) is None:
                    request.setResponseCode(400)
                    return {"message": "Password must hashed by sha256"}

                def sayDone(_):
                    request.write(b'{"message": "OK"}')
                    request.finish()

                def checkIfExist(result: List[Tuple[str]]):
                    if len(result) > 0:
                        request.setResponseCode(409)
                        request.write(b'{"message": "Conflict"}')
                        request.finish()
                    else:
                        self.pyfsd.db_pool.runQuery(  # type: ignore[union-attr]
                            "INSERT INTO users VALUES (?, ?, ?);",
                            (body["callsign"], body["password"], 1),
                        ).addCallback(sayDone)

                return self.pyfsd.db_pool.runQuery(
                    "SELECT callsign FROM users WHERE callsign = ?;",
                    (body["callsign"],),
                ).addCallback(checkIfExist)
        elif path == [b"modify"]:
            is_body, arg2 = checkBody(
                {"callsign": str, "password": MayExist[str], "rating": MayExist[int]},
                check_token=True,
            )
            if not is_body:
                return arg2
            else:
                if self.pyfsd.db_pool is None:
                    request.setResponseCode(503)
                    return {"message": "Service Unavailable"}
                body = arg2
                if is_sha256_regex.match(body["password"]) is None:
                    request.setResponseCode(400)
                    return {"message": "Password must hashed by sha256"}
                password = body.get("password", None)
                rating = body.get("rating", None)
                if password is None and rating is None:
                    request.setResponseCode(400)
                    return {"message": "Must modify password or rating"}
                args = []
                if password is not None:
                    args.append(password)
                if rating is not None:
                    args.append(rating)
                args.append(body["callsign"])

                def sayDone(_):
                    request.write(b'{"message": "OK"}')
                    request.finish()

                def checkIfExist(result: List[Tuple[str]]):
                    if not len(result) > 0:
                        request.setResponseCode(404)
                        request.write(b'{"message": "User not found"}')
                        request.finish()
                    else:
                        self.pyfsd.db_pool.runQuery(  # type: ignore[union-attr]
                            "UPDATE users SET "
                            f"{'password = ?' if password is not None else ''}"
                            f"""{', ' if (
                                password is not None
                                and rating is not None
                            ) else ''}"""
                            f"{'rating = ?' if rating is not None else ''}"
                            " WHERE callsign = ?",
                            args,
                        ).addCallback(sayDone)

                return self.pyfsd.db_pool.runQuery(
                    "SELECT callsign FROM users WHERE callsign = ?;",
                    (body["callsign"],),
                ).addCallback(checkIfExist)
        elif path == [b"login"]:
            is_body, arg2 = checkBody(
                {"callsign": str, "password": str},
                check_token=True,
            )
            if not is_body:
                return arg2
            else:
                if self.pyfsd.db_pool is None:
                    request.setResponseCode(503)
                    return {"message": "Service Unavailable"}
                body = arg2

                if is_sha256_regex.match(body["password"]) is None:
                    request.setResponseCode(400)
                    return {"message": "Password must hashed by sha256"}

                def handler(result: List[Tuple[str, str, int]]):
                    if len(result) == 0:
                        request.write(b'{"exist": false}')
                    else:
                        _, hashed_password, rating = result[0]
                        success = (
                            b"true" if hashed_password == body["password"] else b"false"
                        )
                        request.write(
                            b'{"exist": true, "success": %s, "rating": %d}'
                            % (success, rating)
                        )
                    request.finish()

                return self.pyfsd.db_pool.runQuery(
                    "SELECT callsign, password, rating FROM users "
                    "WHERE callsign = ?;",
                    (body["callsign"],),
                ).addCallback(handler)
        else:
            request.setResponseCode(404)
            return {"message": "Not Found"}

    def renderJson_DELETE(
        self, request: "Request", path: List[bytes]
    ) -> Union[dict, Deferred]:
        # yee, I'm going to use json body in DELETE method
        def checkBody(fmt: dict, check_token: bool = True) -> Tuple[bool, dict]:
            """
            Args:
                fmt: Format. Like verifyConfigStruct's structure.

                check_token: Check token in body.
            Returns:
                return[1] is body if return[0] == True else return[1] is response
            """
            try:
                body = loads(
                    request.content.read().decode(  # type: ignore[attr-defined]
                        errors="replace"
                    )
                )
            except JSONDecodeError:
                request.setResponseCode(400)
                return False, {"message": "Invaild body"}
            if check_token and body.get("token") != config["token"]:
                request.setResponseCode(403)
                return False, {"message": "Forbidden"}
            try:
                verifyConfigStruct(body, fmt)
            except (TypeError, KeyError):
                return False, {"message": "Invaild body struct"}
            return True, body

        if path == [b"delete"]:
            is_body, arg2 = checkBody(
                {"callsign": str}, check_token=True
            )
            if not is_body:
                return arg2
            else:
                if self.pyfsd.db_pool is None:
                    request.setResponseCode(503)
                    return {"message": "Service Unavailable"}
                body = arg2

                def sayDone(_):
                    request.write(b'{"message": "OK"}')
                    request.finish()

                def checkIfExist(result: List[Tuple[str]]):
                    if not len(result) > 0:
                        request.setResponseCode(404)
                        request.write(b'{"message": "User not found"}')
                        request.finish()
                    else:
                        self.pyfsd.db_pool.runQuery(  # type: ignore[union-attr]
                            "DELETE FROM users WHERE callsign = ?;",
                            (body["callsign"],),
                        ).addCallback(sayDone)

                return self.pyfsd.db_pool.runQuery(
                    "SELECT callsign FROM users WHERE callsign = ?;",
                    (body["callsign"],),
                ).addCallback(checkIfExist)
        else:
            request.setResponseCode(404)
            return {"message": "Not Found"}


assert all_config is not None
verifyConfigStruct(
    all_config,
    {"plugin": {"httpapi": {"port": int, "client_coding": str, "use_heading": bool}}},
)
config = all_config["plugin"]["httpapi"]
plugin = HTTPAPIPlugin()

if config["token"] == "DEFAULT":
    from secrets import token_urlsafe

    config["token"] = token_urlsafe()
    plugin.logger.warn(
        f"httpai plugin: Please change default token. Now token is {config['token']}"
    )
encoder = makeEncoder(config["client_coding"])
service = PluginTCPServer(config["port"], Site(plugin))
