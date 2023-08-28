import base64
import hashlib
import pathlib
from pprint import pprint

import httpx
from asn1crypto import algos, x509
from pyhanko.keys import load_cert_from_pemder
from pyhanko.sign import Signer
from pyhanko.sign.general import load_cert_from_pemder
from pyhanko_certvalidator.registry import SimpleCertificateStore
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# import logging
# logging.basicConfig(
#     level=logging.DEBUG,
#     format="[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s",
# )


class RSSPClient:
    def __init__(self):
        self.access_token: str | None = None
        self.sad: str | None = None
        self.rp_user = "rsspdemo"
        self.rp_password = "12345678"
        self.rp_signature = "f3eL/n2q5rLn3SdzGfvl1V4MzgPqM68M4TDVqF2fRHarKFQBVQnJU36DPtufu3ofyGVrsq9OgYh3Nujrx7/CUCiKd8I1Qms1y946jEo6wi55ietUQ6vW6/riMwG0blknbb7Wj5tP4SDe1upNydwetgwvaNEKEfv6kubvNqJVkYCo+bFr2rcWV/u1s+i3L1wv4hRIpLZx0Je5IGurGgf2XkGWVhD6x8/AXyy/qmrZ3IzHnFaiWOuy2Dv+NzVLSR0NPU+Zr3btTYMa/ZUa1YYJjrs6c1XLiiwLMJURac/C5j6i5VSRfTQDSHUkIOfTDtN6oRVLZ5ewQ0aQc6tW/FuM2w=="
        self.rp_key = pathlib.Path("rssp.key").read_text()
        self.refresh_token = "-EowQhb5L22B5KHuv0FXRdTpKXEbUmt8/XpDyhS/2wENtvMt_Rh8tRvuZ3dr/1xDZul0B4aXMipMNmdyBw9f9gAB5DUE185PWjF-Ukbei9tj2NLchtz8_UIIRYz4scCgOMOaZ1sjesMrpoTMoplcKX2VEQx6Of90Yg-XHVDrkymhItjf89grm.Vv/NIqsZZaTzYI1PlgzgfrhooUlFsWWo7lR/ssNBH41JQ6ZYqdyA6k6FAfTQNGPDIo-IJHE8KZ"


    def generate_authorization(self):
        timestamp = int(time.time() * 1000)
        print(timestamp)
        data2sign = self.rp_user + self.rp_password + self.rp_signature + str(timestamp)

        # Initialize the signer
        private_key = serialization.load_pem_private_key(
            self.rp_key.encode(),
            password=None
        )
        pkcs1_signature = private_key.sign(
            data2sign.encode(),
            padding=padding.PKCS1v15(),
            algorithm=hashes.SHA1()
        )

        # Convert the binary signature to Base64
        pkcs1_signature_base64 = base64.b64encode(pkcs1_signature).decode()

        credentials = base64.b64encode(
            (self.rp_user + ':' + self.rp_password + ':' + self.rp_signature + ':' + str(timestamp) + ':' + pkcs1_signature_base64).encode()
        ).decode()

        username = 'user_20230816'
        password = '12345678'
        authorization = 'SSL2 ' + credentials + ', Basic ' + base64.b64encode(('USERNAME' + ':' + username + ':' + password).encode()).decode()
        print(authorization)
        return authorization

    def login(self) -> str:
        response = httpx.post(
            "https://rssp.mobile-id.vn/rssp/v2/auth/login",
            json={
                "relyingParty": "RSSP",
                "rememberMeEnabled": False,
                "profile": "rssp-119.432-v2.0",
                "lang": "EN",
            },
            # headers={"Authorization": f"Bearer {self.refresh_token}"},
            headers={"Authorization": self.generate_authorization()},
        )
        data = response.json()
        print("Login response:")
        pprint(data)
        access_token = data["accessToken"]
        self.access_token = access_token

    def download_certificates(self) -> None:
        # folder with certificates is not empty
        if len(list(pathlib.Path("certificates").glob("*.der"))) > 0:
            return

        response = httpx.post(
            "https://rssp.mobile-id.vn/rssp/v2/credentials/info",
            json={
                "credentialID": "52fa1877-8163-47ca-913e-3d90afa3b584",
                "profile": "rssp-119.432-v2.0",
                "lang": "EN",
                "certInfoEnabled": True,
                "authInfoEnabled": True,
                "certificates": "chain",
            },
            headers={
                "Authorization": "Bearer " + self.access_token,
            },
        )
        data = response.json()
        print("Download certificates response:")
        pprint(data)
        pathlib.Path("certificates").mkdir(exist_ok=True)

        for idx, cert in enumerate(data["cert"]["certificates"]):
            filename = pathlib.Path(f"certificates/cert_{idx}.der")
            filename.write_bytes(base64.b64decode(cert))

    def authorize(self) -> None:
        assert self.access_token is not None

        response = httpx.post(
            "https://rssp.mobile-id.vn/rssp/v2/credentials/authorize",
            json={
                "credentialID": "52fa1877-8163-47ca-913e-3d90afa3b584",
                "authorizeCode": "12345678",
                "numSignatures": 100,
                "profile": "rssp-119.432-v2.0",
                "lang": "EN",
            },
            headers={
                "Authorization": "Bearer " + self.access_token,
            },
        )
        data = response.json()
        print("Authorize response:")
        pprint(data)
        self.sad = data["SAD"]

    def signHash(self, data: bytes) -> bytes:
        assert self.sad is not None
        assert self.access_token is not None

        doc_hash = base64.b64encode(data).decode()

        response = httpx.post(
            "https://rssp.mobile-id.vn/rssp/v2/signatures/signHash",
            json={
                "credentialID": "52fa1877-8163-47ca-913e-3d90afa3b584",
                "documentDigests": {
                    "hashes": [doc_hash],
                    "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1",  # SHA256
                },
                "operationMode": "S",
                "signAlgo": "1.2.840.113549.1.1.1",  # RSA
                "SAD": self.sad,
                "signAlgoParams": "BgkqhkiG9w0BAQo=",
                "profile": "rssp-119.432-v2.0",
                "lang": "EN",
            },
            headers={
                "Authorization": "Bearer " + self.access_token,
            },
        )
        data = response.json()
        print("SignHash response:")
        pprint(data)
        signature_str = data["signatures"][0]
        signature = base64.b64decode(signature_str)

        return signature


class RSSPSigner(Signer):
    def __init__(
        self,
        signing_cert: x509.Certificate,
        signature_mechanism: algos.SignedDigestAlgorithm,
        client: RSSPClient,
        other_certs=(),
    ):
        cr = SimpleCertificateStore()
        cr.register_multiple(other_certs)

        self.client = client

        super().__init__(
            signature_mechanism=signature_mechanism,
            signing_cert=signing_cert,
            cert_registry=cr,
        )

    async def async_sign_raw(
        self,
        data: bytes,
        digest_algorithm: str,
        dry_run=False,
    ) -> bytes:
        print("============ SIGNING ============")
        print("Digest algorithm:", digest_algorithm)
        print("Data:", data, len(data))
        doc_hash = hashlib.sha256(data).digest()
        print("Doc hash:", doc_hash)
        return self.client.signHash(doc_hash)


def load_rssp():
    client = RSSPClient()
    client.login()
    client.download_certificates()
    client.authorize()

    cert: x509.Certificate = load_cert_from_pemder("./certificates/cert_0.der")
    chain = (
        load_cert_from_pemder("./certificates/cert_1.der"),
        load_cert_from_pemder("./certificates/cert_2.der"),
    )

    signer = RSSPSigner(
        signing_cert=cert,
        other_certs=chain,
        signature_mechanism=algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
        client=client,
    )
    return {
        "cert": cert,
        "chain": chain,
        "signer": signer,
    }
