#!/usr/bin/env python3
"""STS for outside identities: an OIDC provider's JWTs and an LDAP directory's binds, with a fake directory here.

usage: lib_storage_federation.py PORT DIR LDAP_PORT

DIR holds jwks.json, which this writes before the runtime reads it, and the runtime's federation file names it.  The
credentials file has users builder (s3:* on build*) and reader (read only), each with a key.  One PASS or FAIL line
per assertion.
"""
import base64
import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

import boto3
import jwt
from botocore.config import Config
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.asymmetric import ec, rsa

PORT, DIR, LDAP_PORT = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
URL = "http://127.0.0.1:%d" % PORT
passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name, flush=True)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, str(detail)[:900]), flush=True)


def b64u(n):
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# ── the provider's keys ──
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ec_key = ec.generate_private_key(ec.SECP256R1())
stranger = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rn = rsa_key.public_key().public_numbers()
en = ec_key.public_key().public_numbers()
with open(os.path.join(DIR, "jwks.json"), "w") as f:
    json.dump({"keys": [
        {"kty": "RSA", "kid": "r1", "use": "sig", "alg": "RS256", "n": b64u(rn.n), "e": b64u(rn.e)},
        {"kty": "EC", "kid": "e1", "use": "sig", "crv": "P-256", "x": b64u(en.x), "y": b64u(en.y)},
    ]}, f)


def token(key=rsa_key, alg="RS256", kid="r1", **over):
    now = int(time.time())
    claims = {"iss": "https://idp.test", "aud": "storage", "sub": "u-1", "iat": now, "exp": now + 600,
              "policy": "reader"}
    claims.update(over)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


def form(fields):
    req = urllib.request.Request(URL + "/", data=urllib.parse.urlencode(fields).encode(), method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def code_of(body):
    try:
        return ET.fromstring(body).find(".//{*}Code").text
    except Exception:
        return body[:200]


def creds_of(body):
    root = ET.fromstring(body)
    c = root.find(".//{*}Credentials")
    return {k: c.find("{*}" + k).text for k in ("AccessKeyId", "SecretAccessKey", "SessionToken")}


def s3_with(c):
    return boto3.client("s3", endpoint_url=URL, region_name="us-east-1", aws_access_key_id=c["AccessKeyId"],
                        aws_secret_access_key=c["SecretAccessKey"], aws_session_token=c["SessionToken"],
                        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}))


def ok(fn):
    try:
        fn()
        return "ok"
    except ClientError as e:
        return e.response["Error"]["Code"]


def web(tok, arn="arn:aws:iam:::role/web", **extra):
    f = {"Action": "AssumeRoleWithWebIdentity", "Version": "2011-06-15", "RoleArn": arn, "RoleSessionName": "test",
         "WebIdentityToken": tok}
    f.update(extra)
    return form(f)


admin = boto3.client("s3", endpoint_url=URL, region_name="us-east-1", aws_access_key_id=os.environ["ADMIN_AK"],
                     aws_secret_access_key=os.environ["ADMIN_SK"], config=Config(s3={"addressing_style": "path"}))
admin.create_bucket(Bucket="build-out")
admin.put_object(Bucket="build-out", Key="seed", Body=b"seed")

# ── OIDC ──
sts = boto3.client("sts", endpoint_url=URL, region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
r = sts.assume_role_with_web_identity(RoleArn="arn:aws:iam:::role/web", RoleSessionName="ci-run", WebIdentityToken=token())
c = {k: r["Credentials"][k] for k in ("AccessKeyId", "SecretAccessKey", "SessionToken")}
check("an AWS SDK takes credentials for a provider's token", c["AccessKeyId"].startswith("ASIA"), r["Credentials"])
s = s3_with(c)
check("which sign as the user the claim names: it reads", ok(lambda: s.get_object(Bucket="build-out", Key="seed")) == "ok")
check("and may not write, as that user may not", ok(lambda: s.put_object(Bucket="build-out", Key="x", Body=b"x")) ==
      "AccessDenied")
st, body = web(token(), arn="arn:aws:iam:::role/ci")
check("a role line names the user a RoleArn signs as", st == 200, body)
if st == 200:
    b = s3_with(creds_of(body))
    check("and that user may write", ok(lambda: b.put_object(Bucket="build-out", Key="built", Body=b"b")) == "ok")
check("an EC P-256 key's token is taken too", web(token(ec_key, "ES256", "e1"))[0] == 200)
for name, tok, want in (
        ("a token another key signed", token(stranger), "InvalidIdentityToken"),
        ("a token for another client", token(aud="someone"), "InvalidIdentityToken"),
        ("a token of another issuer", token(iss="https://evil.test"), "InvalidIdentityToken"),
        ("an expired token", token(exp=int(time.time()) - 3600, iat=int(time.time()) - 7200), "ExpiredTokenException"),
        ("a token not yet valid", token(nbf=int(time.time()) + 3600), "InvalidIdentityToken"),
        ("an unsigned token", jwt.encode({"iss": "https://idp.test", "aud": "storage", "exp": int(time.time()) + 60,
                                          "policy": "reader"}, None, algorithm="none"), "InvalidIdentityToken"),
        ("a token signed with a shared secret", token("k" * 32, "HS256"), "InvalidIdentityToken"),
):
    st, body = web(tok)
    check("%s is refused %s" % (name, want), st == 400 and code_of(body) == want, (st, body))
st, body = web(token(policy="nobody"))
check("a claim naming no user is refused AccessDenied", st == 403 and code_of(body) == "AccessDenied", (st, body))
st, body = web(token(policy="builder,reader"))
check("a claim naming two users is refused, as a session signs as one", st == 403, (st, body))
st, body = web(token(), Policy=json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"}]}))
if st == 200:
    narrowed = s3_with(creds_of(body))
    check("a session Policy narrows the session", ok(lambda: narrowed.get_object(Bucket="build-out", Key="seed")) ==
          "AccessDenied")
else:
    check("a session Policy narrows the session", False, (st, body))

# ── LDAP, with a directory here that knows alice/secret and bob/hunter2 ──
seen = []


def ber_len(buf, i):
    n = buf[i]
    if n < 0x80:
        return n, i + 1
    k = n & 0x7F
    return int.from_bytes(buf[i + 1:i + 1 + k], "big"), i + 1 + k


def tlv(buf, i):
    tag = buf[i]
    n, j = ber_len(buf, i + 1)
    return tag, buf[j:j + n], j + n


def directory():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", LDAP_PORT))
    srv.listen(8)
    while True:
        cl, _ = srv.accept()
        try:
            data = cl.recv(65536)
            _, msg, _ = tlv(data, 0)
            _, mid, i = tlv(msg, 0)
            _, bind, _ = tlv(msg, i)
            _, _, j = tlv(bind, 0)
            _, dn, j = tlv(bind, j)
            _, pw, _ = tlv(bind, j)
            seen.append(dn.decode())
            good = {"uid=alice,ou=People,dc=test": b"secret", "uid=bob,ou=People,dc=test": b"hunter2"}
            code = 0 if good.get(dn.decode()) == pw else 49
            body = bytes([0x0A, 1, code, 0x04, 0, 0x04, 0])
            resp = bytes([0x02, len(mid)]) + mid + bytes([0x61, len(body)]) + body
            cl.sendall(bytes([0x30, len(resp)]) + resp)
            cl.recv(64)
        except Exception:
            pass
        finally:
            cl.close()


threading.Thread(target=directory, daemon=True).start()
time.sleep(0.2)


def ldap(user, pw):
    return form({"Action": "AssumeRoleWithLDAPIdentity", "Version": "2011-06-15", "LDAPUsername": user,
                 "LDAPPassword": pw})


st, body = ldap("alice", "secret")
check("a user the directory binds gets credentials", st == 200 and "<AccessKeyId>ASIA" in body, (st, body))
check("bound as the DN the template makes", "uid=alice,ou=People,dc=test" in seen, seen)
if st == 200:
    a = s3_with(creds_of(body))
    check("which sign as the user alice's line names", ok(lambda: a.put_object(Bucket="build-out", Key="al",
                                                                                 Body=b"a")) == "ok")
st, body = ldap("bob", "hunter2")
if st == 200:
    b = s3_with(creds_of(body))
    check("and anyone else as the * line's", ok(lambda: b.put_object(Bucket="build-out", Key="bo", Body=b"b")) ==
          "AccessDenied" and ok(lambda: b.get_object(Bucket="build-out", Key="seed")) == "ok")
else:
    check("and anyone else as the * line's", False, (st, body))
st, body = ldap("alice", "wrong")
check("a password the directory refuses is AccessDenied", st == 403 and code_of(body) == "AccessDenied", (st, body))
st, body = ldap("eve,ou=Admins", "pw")
check("a name with a DN's separator in it is escaped, not obeyed",
      "uid=eve\\,ou\\=Admins,ou=People,dc=test" in seen and st == 403, (seen[-1:], st, body))
st, body = ldap("alice", "")
check("an empty password is refused before the directory is asked", st == 400, (st, body))
print("  federation: PASS=%d FAIL=%d" % (passed, failed))
sys.exit(failed)
