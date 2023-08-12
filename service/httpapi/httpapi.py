# mypy: disable-error-code="no-any-return"
"""PyFSD PyFSDPlugin plugin :: httpapi.py
Version: -1
"""

from json import JSONDecodeError, JSONEncoder, dumps, loads
from re import compile
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
    Type,
    Union,
)

from sqlalchemy.sql import exists, select
from twisted.application.internet import TCPServer
from twisted.internet.defer import Deferred
from twisted.logger import Logger
from twisted.plugin import IPlugin
from twisted.python.compat import nativeString
from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET, Site
from zope.interface import implementer

from pyfsd.db_tables import users as users_table
from pyfsd.define.utils import MayExist, verifyConfigStruct
from pyfsd.plugin import BasePyFSDPlugin
from pyfsd.service import config as all_config

try:
    from pyfsd.plugins.whazzup import whazzupGenerator
except ImportError:
    raise ImportError("httpapi plugin requires whazzup plugin.")

if TYPE_CHECKING:
    from alchimia.engine import TwistedResultProxy
    from twisted.python.failure import Failure
    from twisted.web.server import Request

    from ..service import PyFSDService

config: dict
encoder: Type[JSONEncoder]
is_sha256_regex = compile("^[a-fA-F0-9]{64}$")


def selectAllProxy(
    handler: Callable,
) -> Callable[["TwistedResultProxy"], None]:
    def proxy(proxy: "TwistedResultProxy") -> None:
        proxy.fetchall().addCallback(handler)

    return proxy


def makeEncoder(encoding: str) -> Type[JSONEncoder]:
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
    pass


@implementer(IPlugin)
class HTTPAPIPlugin(BasePyFSDPlugin, Resource):
    plugin_name = "httpapi"
    pyfsd: "PyFSDService"
    isLeaf = True
    logger = Logger()

    def beforeStart(self, pyfsd: "PyFSDService", _: Optional[dict]) -> None:
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

            def errback(failure: "Failure") -> None:
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
                heading_instead_pbh=bool(config["use_heading"])
            )
        elif path[0] == b"query":
            if len(path) > 2:
                request.setResponseCode(404)
                return {"message": "Not Found"}
            if self.pyfsd.db_engine is None:
                request.setResponseCode(503)
                return {"message": "Service Unavailable"}
            if len(path) == 2:
                # Query single

                def handler(result: List[Tuple[int]]) -> None:
                    if len(result) == 0:
                        request.write(b'{"exist": false}')
                    else:
                        request.write(b'{"exist": true, "rating": %d}' % result[0][0])
                    request.finish()

                return self.pyfsd.db_engine.execute(
                    select([users_table.c.rating]).where(
                        users_table.c.callsign == path[1].decode(errors="replace")
                    )
                ).addCallback(selectAllProxy(handler))
            else:
                # Query all

                def handler(result: List[Tuple[str, int]]) -> None:
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

                return self.pyfsd.db_engine.execute(
                    select([users_table.c.callsign, users_table.c.rating])
                ).addCallback(selectAllProxy(handler))
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
                    request.content.read().decode(  # type: ignore[union-attr]
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
                if self.pyfsd.db_engine is None:
                    request.setResponseCode(503)
                    return {"message": "Service Unavailable"}
                body = arg2
                if is_sha256_regex.match(body["password"]) is None:
                    request.setResponseCode(400)
                    return {"message": "Password must hashed by sha256"}

                def sayDone(_: "TwistedResultProxy") -> None:
                    request.write(b'{"message": "OK"}')
                    request.finish()

                def checkIfExist(result: List[Tuple[bool]]) -> None:
                    if result[0][0]:
                        request.setResponseCode(409)
                        request.write(b'{"message": "Conflict"}')
                        request.finish()
                    else:
                        self.pyfsd.db_engine.execute(  # type: ignore[union-attr]
                            users_table.insert().values(
                                callsign=body["callsign"],
                                password=body["password"],
                                rating=1,
                            )
                        ).addCallback(sayDone)

                return self.pyfsd.db_engine.execute(
                    exists().where(users_table.c.callsign == body["callsign"]).select()
                ).addCallback(selectAllProxy(checkIfExist))
        elif path == [b"modify"]:
            is_body, arg2 = checkBody(
                {"callsign": str, "password": MayExist[str], "rating": MayExist[int]},
                check_token=True,
            )
            if not is_body:
                return arg2
            else:
                if self.pyfsd.db_engine is None:
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
                values = {}
                if password is not None:
                    values["password"] = password
                if rating is not None:
                    values["rating"] = rating

                def sayDone(_: "TwistedResultProxy") -> None:
                    request.write(b'{"message": "OK"}')
                    request.finish()

                def checkIfExist(result: List[Tuple[bool]]) -> None:
                    if not result[0][0]:
                        request.setResponseCode(404)
                        request.write(b'{"message": "User not found"}')
                        request.finish()
                    else:
                        self.pyfsd.db_engine.execute(  # type: ignore[union-attr]
                            users_table.update(
                                users_table.c.callsign == body["callsign"]
                            ).values(**values)
                        ).addCallback(sayDone)

                return self.pyfsd.db_engine.execute(
                    exists().where(users_table.c.callsign == body["callsign"]).select()
                ).addCallback(selectAllProxy(checkIfExist))
        elif path == [b"login"]:
            is_body, arg2 = checkBody(
                {"callsign": str, "password": str},
                check_token=True,
            )
            if not is_body:
                return arg2
            else:
                if self.pyfsd.db_engine is None:
                    request.setResponseCode(503)
                    return {"message": "Service Unavailable"}
                body = arg2

                if is_sha256_regex.match(body["password"]) is None:
                    request.setResponseCode(400)
                    return {"message": "Password must hashed by sha256"}

                def handler(result: List[Tuple[str, int]]) -> None:
                    if len(result) == 0:
                        request.write(b'{"exist": false}')
                    else:
                        hashed_password, rating = result[0]
                        success = (
                            b"true" if hashed_password == body["password"] else b"false"
                        )
                        request.write(
                            b'{"exist": true, "success": %s, "rating": %d}'
                            % (success, rating)
                        )
                    request.finish()

                return self.pyfsd.db_engine.execute(
                    select([users_table.c.password, users_table.c.rating]).where(
                        users_table.c.callsign == body["callsign"]
                    )
                ).addCallback(selectAllProxy(handler))
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
                    request.content.read().decode(  # type: ignore[union-attr]
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
            is_body, arg2 = checkBody({"callsign": str}, check_token=True)
            if not is_body:
                return arg2
            else:
                if self.pyfsd.db_engine is None:
                    request.setResponseCode(503)
                    return {"message": "Service Unavailable"}
                body = arg2

                def sayDone(_: "TwistedResultProxy") -> None:
                    request.write(b'{"message": "OK"}')
                    request.finish()

                def checkIfExist(result: List[Tuple[bool]]) -> None:
                    if not result[0][0]:
                        request.setResponseCode(404)
                        request.write(b'{"message": "User not found"}')
                        request.finish()
                    else:
                        self.pyfsd.db_engine.execute(  # type: ignore[union-attr]
                            users_table.delete(
                                users_table.c.callsign == body["callsign"]
                            )
                        ).addCallback(sayDone)

                return self.pyfsd.db_engine.execute(
                    exists().where(users_table.c.callsign == body["callsign"]).select()
                ).addCallback(selectAllProxy(checkIfExist))
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
