import base64
import hmac
import hashlib
import random
import datetime
import requests
import argparse
import json

# COMPUTES SIGNATURE. Python2.x compatible
# note: python3 computes wrong signature


def _getargs():
    parser = argparse.ArgumentParser(description="Crossbar.io router: HTTP-signedCaller test")
    # required
    parser.add_argument("-key", action="store", required=True, help=".crossbar/config.json")
    parser.add_argument("-secret", action="store", required=True, help=".crossbar/config.json")
    parser.add_argument("-seq", action="store", required=True)
    parser.add_argument("-rpc", action="store", required=True)
    # optional
    parser.add_argument("-host", action="store", required=False)
    parser.add_argument("-port", action="store", required=False)
    parser.add_argument("-args", action="store", required=False)
    parser.add_argument("-data", action="store", required=False)
    args = parser.parse_args()
    if not args.host:
        args.host = '127.0.0.1'.encode('utf-8')
    if not args.port:
        args.port = '9000'.encode('utf-8')
    if not args.data:
        # test data
        args.data = {
            "epsilon": 42,
            "lambda": 32,
            "omicron": 22
        }
    if not args.args:
        args.args = "test"
    return args


def _wrap_rpc(p_args, p_data, procedure=None, timestamp=None):
    if not timestamp:
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if procedure is None:
        procedure = "my.remote.procedure.call"
    return timestamp, {
        "procedure": procedure,
        "args": p_args,
        "kwargs": {"data": p_data}
    }


def _compute_signature(key, secret, seq, body, timestamp=None):
    """
    Computes the signature.
    Described at:
    http://crossbar.io/docs/HTTP-Bridge-Services-Caller/
    Reference code is at:
    https://github.com/crossbario/crossbar/blob/master/crossbar/adapter/rest/common.py
    :return: key, incr, timestamp, nonce, signature
    """
    if timestamp is None:
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    nonce = random.randint(0, 2 ** 53)
    # Compute signature: HMAC[SHA256]_{secret} (key | timestamp | seq | nonce | body) => signature
    hm = hmac.new(secret, None, hashlib.sha256)
    hm.update(key)
    hm.update(timestamp.encode('utf-8'))
    hm.update(str(seq).encode('utf-8'))
    hm.update(str(nonce).encode('utf-8'))
    hm.update(json.dumps(body).encode('utf-8'))
    signature = base64.urlsafe_b64encode(hm.digest())
    return key, seq, timestamp, nonce, signature


def call_wamp(host, port, key, secret, seq, rpc, p_args, p_data):
    timestamped, body = _wrap_rpc([p_args], p_data, procedure=rpc)
    k, i, t, n, s = _compute_signature(
        bytes(key.encode('utf-8')),
        bytes(secret.encode('utf-8')),
        seq, body, timestamped
    )
    if type(s) is not str:
        print('signature computation')
    resp = requests.post(
        url="http://{host}:{port}/call?&key={key}&nonce={nonce}&signature={sig}&timestamp={ts}&seq={i}".format(
            host=host, port=port, key=k, nonce=n, sig=s, ts=timestamped, i=i),
        json=body
    )
    return resp


if __name__ == "__main__":
    import sys
    vinfo = sys.version_info
    if not (vinfo < (3, 0) and vinfo > (2, 5)):
        raise Exception("INCOMPATIBLE PYTHON VERSION.")
    args = _getargs()
    resp = call_wamp(args.host, args.port, args.key, args.secret, args.seq, args.rpc, args.args, args.data)
    print(resp.text)
