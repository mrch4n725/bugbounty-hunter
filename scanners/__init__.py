from scanners.base import ScannerBase
from scanners.xss import XSSScanner
from scanners.headers import HeadersScanner
from scanners.sqli import SQLiScanner
from scanners.ssrf import SSRFScanner
from scanners.clickjacking import ClickjackingScanner
from scanners.csrf import CSRFScanner
from scanners.insecure_forms import InsecureFormsScanner
from scanners.http_methods import HttpMethodsScanner
from scanners.lfi import LFIScanner
from scanners.open_redirect import OpenRedirectScanner
from scanners.exposed_files import ExposedFilesScanner
from scanners.directory_fuzz import DirectoryFuzzScanner
from scanners.subdomain_takeover import SubdomainTakeoverScanner
from scanners.sensitive_data import SensitiveDataScanner
from scanners.ssti import SSTIScanner
from scanners.rate_limiting import RateLimitingScanner
from scanners.blind_xss import BlindXSSScanner
from scanners.xxe import XXEScanner
from scanners.command_injection import CommandInjectionScanner
from scanners.graphql import GraphQLScanner
from scanners.idor import IdorScannerAdapter
from scanners.openapi import OpenAPIScanner
from scanners.authorization import AuthorizationScanner
from scanners.cors import CORSScanner
from scanners.jwt import JWTScanner
from scanners.auth_bypass import AuthBypassScanner

__all__ = [
    "ScannerBase",
    "XSSScanner",
    "HeadersScanner",
    "SQLiScanner",
    "SSRFScanner",
    "ClickjackingScanner",
    "CSRFScanner",
    "InsecureFormsScanner",
    "HttpMethodsScanner",
    "LFIScanner",
    "OpenRedirectScanner",
    "ExposedFilesScanner",
    "DirectoryFuzzScanner",
    "SubdomainTakeoverScanner",
    "SensitiveDataScanner",
    "SSTIScanner",
    "RateLimitingScanner",
    "BlindXSSScanner",
    "XXEScanner",
    "CommandInjectionScanner",
    "GraphQLScanner",
    "IdorScannerAdapter",
    "OpenAPIScanner",
    "AuthorizationScanner",
    "CORSScanner",
    "JWTScanner",
    "AuthBypassScanner",
]


def discover_scanner_classes() -> dict[str, type[ScannerBase]]:
    """Return dict of {SCANNER_NAME: ScannerBase_subclass} from the scanners package."""
    found: dict[str, type[ScannerBase]] = {}
    for name, obj in list(globals().items()):
        if (isinstance(obj, type) and issubclass(obj, ScannerBase)
                and obj is not ScannerBase):
            found[obj.SCANNER_NAME] = obj
    return found
