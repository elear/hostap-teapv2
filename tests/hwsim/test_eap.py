# EAP authentication tests
# Copyright (c) 2019-2024, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import base64
import logging
import random
logger = logging.getLogger()

import os

try:
    import OpenSSL
    openssl_imported = True
except ImportError:
    openssl_imported = False

import hostapd
from utils import alloc_fail, fail_test, wait_fail_trigger, HwsimSkip
from test_ap_eap import check_eap_capa, int_eap_server_params, eap_connect, \
    eap_reauth

def int_teap_server_params(eap_teap_auth=None,
                           eap_teap_separate_result=None, eap_teap_id=None,
                           eap_teap_method_sequence=None):
    params = int_eap_server_params()
    params['eap_fast_a_id'] = "101112131415161718191a1b1c1dff00"
    params['eap_fast_a_id_info'] = "test server 0"
    if eap_teap_auth:
        params['eap_teap_auth'] = eap_teap_auth
    if eap_teap_separate_result:
        params['eap_teap_separate_result'] = eap_teap_separate_result
    if eap_teap_id:
        params['eap_teap_id'] = eap_teap_id
    if eap_teap_method_sequence:
        params['eap_teap_method_sequence'] = eap_teap_method_sequence
    return params

def int_teapv2_server_params(eap_teapv2_auth=None,
                             eap_teapv2_separate_result=None,
                             eap_teapv2_id=None,
                             eap_teapv2_method_sequence=None,
                             eap_teapv2_request_action_pkcs10=None,
                             eap_teapv2_trusted_server_root=None):
    params = int_eap_server_params()
    params['eap_fast_a_id'] = "101112131415161718191a1b1c1dff00"
    params['eap_fast_a_id_info'] = "test server 0"
    if eap_teapv2_auth is not None:
        params['eap_teapv2_auth'] = eap_teapv2_auth
    if eap_teapv2_separate_result is not None:
        params['eap_teapv2_separate_result'] = eap_teapv2_separate_result
    if eap_teapv2_id is not None:
        params['eap_teapv2_id'] = eap_teapv2_id
    if eap_teapv2_method_sequence is not None:
        params['eap_teapv2_method_sequence'] = eap_teapv2_method_sequence
    if eap_teapv2_request_action_pkcs10 is not None:
        params['eap_teapv2_request_action_pkcs10'] = \
            eap_teapv2_request_action_pkcs10
    if eap_teapv2_trusted_server_root is not None:
        params['eap_teapv2_trusted_server_root'] = \
            eap_teapv2_trusted_server_root
    return params

def teapv2_generate_near_expiry_cert(logdir):
    if not openssl_imported:
        raise HwsimSkip("OpenSSL python module not available")

    with open("auth_serv/ca.pem", "rb") as f:
        cacert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                 f.read())
    with open("auth_serv/ca-key.pem", "rb") as f:
        cakey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                               f.read())

    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    cert = OpenSSL.crypto.X509()
    cert.set_serial_number(random.randint(1, 1000000))
    cert.gmtime_adj_notBefore(-365 * 24 * 3600)
    cert.gmtime_adj_notAfter(20 * 24 * 3600)
    cert.set_pubkey(key)
    subject = cert.get_subject()
    subject.CN = "teapv2-pkcs10"
    cert.set_issuer(cacert.get_subject())
    cert.sign(cakey, "sha256")

    cert_file = os.path.join(logdir, "teapv2-expiring.pem")
    key_file = os.path.join(logdir, "teapv2-expiring.key")
    with open(cert_file, "wb") as f:
        f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                cert))
    with open(key_file, "wb") as f:
        f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                               key))
    return cert_file, key_file

def test_eap_teap_eap_mschapv2(dev, apdev):
    """EAP-TEAP with inner EAP-MSCHAPv2"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")
    eap_reauth(dev[0], "TEAP")

def test_eap_teapv2_eap_mschapv2(dev, apdev):
    """EAP-TEAPV2 with inner EAP-MSCHAPV2"""
    check_eap_capa(dev[0], "TEAPV2")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teapv2_server_params()
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user",
                anonymous_identity="TEAPV2", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")
    eap_reauth(dev[0], "TEAPV2")

def test_eap_teapv2_trusted_server_root(dev, apdev):
    """EAP-TEAPV2 Trusted-Server-Root TLV"""
    check_eap_capa(dev[0], "TEAPV2")
    params = int_teapv2_server_params(
        eap_teapv2_trusted_server_root="auth_serv/ca.pem")
    hapd = hostapd.add_ap(apdev[0], params)
    net_id = eap_connect(dev[0], hapd, "TEAPV2", "user",
                         anonymous_identity="TEAPV2", password="password",
                         ca_cert="auth_serv/ca.pem",
                         phase2="auth=MSCHAPV2")

    if "OK" not in dev[0].request("SET update_config 1"):
        raise Exception("Failed to set update_config")
    dev[0].save_config()

    blobs = dev[0].request("LIST_BLOBS")
    blob_list = []
    for b in blobs.splitlines():
        b = b.strip()
        if not b:
            continue
        if b.startswith("blob "):
            b = b[5:]
        blob_list.append(b)
    trust_blob = next((b for b in blob_list
                       if b.startswith("teapv2-trusted-root-")), None)
    if not trust_blob:
        raise Exception("Trusted-Server-Root blob not stored")

    ca_cert = dev[0].request("GET_NETWORK %d ca_cert" % net_id)
    if not ca_cert.startswith("\"blob://"):
        raise Exception("Trusted-Server-Root not configured as trust anchor")
    if ca_cert[8:] != trust_blob + '\"':
        raise Exception("Unexpected trust anchor reference: " + ca_cert)

def test_eap_teapv2_pkcs10_request_action(dev, apdev, params):
    """EAP-TEAPV2 PKCS#10 Request-Action when client cert near expiry"""
    check_eap_capa(dev[0], "TEAPV2")
    if not openssl_imported:
        raise HwsimSkip("OpenSSL python module not available")

    client_cert, client_key = teapv2_generate_near_expiry_cert(params['logdir'])
    server_params = int_teapv2_server_params(
        eap_teapv2_auth="2", eap_teapv2_request_action_pkcs10="1")
    hapd = hostapd.add_ap(apdev[0], server_params)

    net_id = eap_connect(dev[0], hapd, "TEAPV2", "/CN=teapv2-pkcs10",
                         anonymous_identity="TEAPV2",
                         ca_cert="auth_serv/ca.pem",
                         client_cert=client_cert, private_key=client_key)
    if "OK" not in dev[0].request("SET update_config 1"):
        raise Exception("Failed to set update_config")
    dev[0].save_config()
    conf_file = os.path.join(params['logdir'],
                             "p2p%s.conf" % dev[0].ifname[4:])
    with open(conf_file, "r") as f:
        conf_data = f.read()
    if "update_config=1" not in conf_data:
        raise Exception("update_config=1 not stored in config file")

    blobs = dev[0].request("LIST_BLOBS")
    blob_list = []
    for b in blobs.splitlines():
        b = b.strip()
        if not b:
            continue
        if b.startswith("blob "):
            b = b[5:]
        blob_list.append(b)
    key_blob = next((b for b in blob_list if b.startswith("teapv2-user-key")),
                    None)
    cert_blob = next((b for b in blob_list if b.startswith("teapv2-user-cert")),
                     None)
    if not key_blob:
        raise Exception("PKCS#10 response blob not stored")
    if not cert_blob:
        raise Exception("PKCS#7 certificate blob not stored")

    cert_data = dev[0].request("GET_BLOB " + cert_blob)
    if not cert_data:
        raise Exception("Failed to read PKCS#7 certificate blob")
    if "BEGIN CERTIFICATE" not in cert_data:
        raise Exception("Stored PKCS#7 certificate blob missing certificate")
    if "client_cert=\"blob://%s\"" % cert_blob not in conf_data:
        raise Exception("PKCS#7 client_cert not stored in config file")
    client_cert_ref = dev[0].request("GET_NETWORK %d client_cert" % net_id)
    if client_cert_ref != "\"blob://" + cert_blob + '\"':
        raise Exception("Stored PKCS#7 certificate not set as client_cert")

def test_eap_teap_eap_pwd(dev, apdev):
    """EAP-TEAP with inner EAP-PWD"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "PWD")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user-pwd-2",
                anonymous_identity="TEAP", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=PWD")

def test_eap_teapv2_eap_pwd(dev, apdev):
    """EAP-TEAPV2 with inner EAP-PWD"""
    check_eap_capa(dev[0], "TEAPV2")
    check_eap_capa(dev[0], "PWD")
    params = int_teapv2_server_params()
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user-pwd-2",
                anonymous_identity="TEAPV2", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=PWD")

def test_eap_teap_eap_eke(dev, apdev):
    """EAP-TEAP with inner EAP-EKE"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "EKE")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user-eke-2",
                anonymous_identity="TEAP", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=EKE")

def test_eap_teapv2_eap_eke(dev, apdev):
    """EAP-TEAPV2 with inner EAP-EKE"""
    check_eap_capa(dev[0], "TEAPV2")
    check_eap_capa(dev[0], "EKE")
    params = int_teapv2_server_params()
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user-eke-2",
                anonymous_identity="TEAPV2", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=EKE")

def test_eap_teap_basic_password_auth(dev, apdev):
    """EAP-TEAP with Basic-Password-Auth"""
    check_eap_capa(dev[0], "TEAP")
    params = int_teap_server_params(eap_teap_auth="1")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP", password="password",
                ca_cert="auth_serv/ca.pem")

def test_eap_teapv2_basic_password_auth(dev, apdev):
    """EAP-TEAPV2 with Basic-Password-Auth"""
    check_eap_capa(dev[0], "TEAPV2")
    params = int_teapv2_server_params(eap_teapv2_auth="1")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user",
                anonymous_identity="TEAPV2", password="password",
                ca_cert="auth_serv/ca.pem")

def test_eap_teap_basic_password_auth_failure(dev, apdev):
    """EAP-TEAP with Basic-Password-Auth failure"""
    check_eap_capa(dev[0], "TEAP")
    params = int_teap_server_params(eap_teap_auth="1")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP", password="incorrect",
                ca_cert="auth_serv/ca.pem", expect_failure=True)

def test_eap_teapv2_basic_password_auth_failure(dev, apdev):
    """EAP-TEAPV2 with Basic-Password-Auth failure"""
    check_eap_capa(dev[0], "TEAPV2")
    params = int_teapv2_server_params(eap_teapv2_auth="1")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user",
                anonymous_identity="TEAPV2", password="incorrect",
                ca_cert="auth_serv/ca.pem", expect_failure=True)

def test_eap_teap_basic_password_auth_no_password(dev, apdev):
    """EAP-TEAP with Basic-Password-Auth and no password configured"""
    check_eap_capa(dev[0], "TEAP")
    params = int_teap_server_params(eap_teap_auth="1")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP",
                ca_cert="auth_serv/ca.pem", expect_failure=True)

def test_eap_teapv2_basic_password_auth_no_password(dev, apdev):
    """EAP-TEAPV2 with Basic-Password-Auth and no password configured"""
    check_eap_capa(dev[0], "TEAPV2")
    params = int_teapv2_server_params(eap_teapv2_auth="1")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user",
                anonymous_identity="TEAPV2",
                ca_cert="auth_serv/ca.pem", expect_failure=True)

def test_eap_teap_basic_password_auth_id0(dev, apdev):
    """EAP-TEAP with Basic-Password-Auth (eap_teap_id=0)"""
    run_eap_teap_basic_password_auth_id(dev, apdev, 0)

def test_eap_teap_basic_password_auth_id1(dev, apdev):
    """EAP-TEAP with Basic-Password-Auth (eap_teap_id=1)"""
    run_eap_teap_basic_password_auth_id(dev, apdev, 1)

def test_eap_teap_basic_password_auth_id2(dev, apdev):
    """EAP-TEAP with Basic-Password-Auth (eap_teap_id=2)"""
    run_eap_teap_basic_password_auth_id(dev, apdev, 2, failure=True)

def test_eap_teap_basic_password_auth_id3(dev, apdev):
    """EAP-TEAP with Basic-Password-Auth (eap_teap_id=3)"""
    run_eap_teap_basic_password_auth_id(dev, apdev, 3)

def test_eap_teap_basic_password_auth_id4(dev, apdev):
    """EAP-TEAP with Basic-Password-Auth (eap_teap_id=4)"""
    run_eap_teap_basic_password_auth_id(dev, apdev, 4)

def test_eap_teapv2_basic_password_auth_id0(dev, apdev):
    """EAP-TEAPV2 with Basic-Password-Auth (eap_teapv2_id=0)"""
    run_eap_teapv2_basic_password_auth_id(dev, apdev, 0)

def test_eap_teapv2_basic_password_auth_id1(dev, apdev):
    """EAP-TEAPV2 with Basic-Password-Auth (eap_teapv2_id=1)"""
    run_eap_teapv2_basic_password_auth_id(dev, apdev, 1)

def test_eap_teapv2_basic_password_auth_id2(dev, apdev):
    """EAP-TEAPV2 with Basic-Password-Auth (eap_teapv2_id=2)"""
    run_eap_teapv2_basic_password_auth_id(dev, apdev, 2, failure=True)

def test_eap_teapv2_basic_password_auth_id3(dev, apdev):
    """EAP-TEAPV2 with Basic-Password-Auth (eap_teapv2_id=3)"""
    run_eap_teapv2_basic_password_auth_id(dev, apdev, 3)

def test_eap_teapv2_basic_password_auth_id4(dev, apdev):
    """EAP-TEAPV2 with Basic-Password-Auth (eap_teapv2_id=4)"""
    run_eap_teapv2_basic_password_auth_id(dev, apdev, 4)

def run_eap_teap_basic_password_auth_id(dev, apdev, eap_teap_id, failure=False):
    check_eap_capa(dev[0], "TEAP")
    params = int_teap_server_params(eap_teap_auth="1",
                                    eap_teap_id=str(eap_teap_id))
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP", password="password",
                ca_cert="auth_serv/ca.pem",
                expect_failure=failure)

def run_eap_teapv2_basic_password_auth_id(dev, apdev, eap_teapv2_id,
                                         failure=False):
    check_eap_capa(dev[0], "TEAPV2")
    params = int_teapv2_server_params(eap_teapv2_auth="1",
                                      eap_teapv2_id=str(eap_teapv2_id))
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user",
                anonymous_identity="TEAPV2", password="password",
                ca_cert="auth_serv/ca.pem",
                expect_failure=failure)

def test_eap_teap_basic_password_auth_machine(dev, apdev):
    """EAP-TEAP with Basic-Password-Auth using machine credential"""
    check_eap_capa(dev[0], "TEAP")
    params = int_teap_server_params(eap_teap_auth="1", eap_teap_id="2")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "",
                anonymous_identity="TEAP",
                machine_identity="machine", machine_password="machine-password",
                ca_cert="auth_serv/ca.pem")

def test_eap_teapv2_basic_password_auth_machine(dev, apdev):
    """EAP-TEAPV2 with Basic-Password-Auth using machine credential"""
    check_eap_capa(dev[0], "TEAPV2")
    params = int_teapv2_server_params(eap_teapv2_auth="1",
                                      eap_teapv2_id="2")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "",
                anonymous_identity="TEAPV2",
                machine_identity="machine", machine_password="machine-password",
                ca_cert="auth_serv/ca.pem")

def test_eap_teap_basic_password_auth_user_and_machine(dev, apdev):
    """EAP-TEAP with Basic-Password-Auth using user and machine credentials"""
    check_eap_capa(dev[0], "TEAP")
    params = int_teap_server_params(eap_teap_auth="1", eap_teap_id="5")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user", password="password",
                anonymous_identity="TEAP",
                machine_identity="machine", machine_password="machine-password",
                ca_cert="auth_serv/ca.pem")

def test_eap_teapv2_basic_password_auth_user_and_machine(dev, apdev):
    """EAP-TEAPV2 with Basic-Password-Auth using user and machine credentials"""
    check_eap_capa(dev[0], "TEAPV2")
    params = int_teapv2_server_params(eap_teapv2_auth="1",
                                      eap_teapv2_id="5")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user", password="password",
                anonymous_identity="TEAPV2",
                machine_identity="machine", machine_password="machine-password",
                ca_cert="auth_serv/ca.pem")

def test_eap_teap_basic_password_auth_user_and_machine_fail_user(dev, apdev):
    """EAP-TEAP with Basic-Password-Auth using user and machine credentials (fail user)"""
    check_eap_capa(dev[0], "TEAP")
    params = int_teap_server_params(eap_teap_auth="1", eap_teap_id="5")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user", password="wrong-password",
                anonymous_identity="TEAP",
                machine_identity="machine", machine_password="machine-password",
                ca_cert="auth_serv/ca.pem",
                expect_failure=True)

def test_eap_teapv2_basic_password_auth_user_and_machine_fail_user(dev, apdev):
    """EAP-TEAPV2 with Basic-Password-Auth using user and machine credentials (fail user)"""
    check_eap_capa(dev[0], "TEAPV2")
    params = int_teapv2_server_params(eap_teapv2_auth="1",
                                      eap_teapv2_id="5")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user", password="wrong-password",
                anonymous_identity="TEAPV2",
                machine_identity="machine", machine_password="machine-password",
                ca_cert="auth_serv/ca.pem",
                expect_failure=True)

def test_eap_teap_basic_password_auth_user_and_machine_fail_machine(dev, apdev):
    """EAP-TEAP with Basic-Password-Auth using user and machine credentials (fail machine)"""
    check_eap_capa(dev[0], "TEAP")
    params = int_teap_server_params(eap_teap_auth="1", eap_teap_id="5")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user", password="password",
                anonymous_identity="TEAP",
                machine_identity="machine",
                machine_password="wrong-machine-password",
                ca_cert="auth_serv/ca.pem",
                expect_failure=True)

def test_eap_teapv2_basic_password_auth_user_and_machine_fail_machine(dev, apdev):
    """EAP-TEAPV2 with Basic-Password-Auth using user and machine credentials (fail machine)"""
    check_eap_capa(dev[0], "TEAPV2")
    params = int_teapv2_server_params(eap_teapv2_auth="1",
                                      eap_teapv2_id="5")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user", password="password",
                anonymous_identity="TEAPV2",
                machine_identity="machine",
                machine_password="wrong-machine-password",
                ca_cert="auth_serv/ca.pem",
                expect_failure=True)

def test_eap_teap_basic_password_auth_user_and_machine_no_machine(dev, apdev):
    """EAP-TEAP with Basic-Password-Auth using user and machine credentials (no machine)"""
    check_eap_capa(dev[0], "TEAP")
    params = int_teap_server_params(eap_teap_auth="1", eap_teap_id="5")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user", password="password",
                anonymous_identity="TEAP",
                ca_cert="auth_serv/ca.pem",
                expect_failure=True)

def test_eap_teapv2_basic_password_auth_user_and_machine_no_machine(dev, apdev):
    """EAP-TEAPV2 with Basic-Password-Auth using user and machine credentials (no machine)"""
    check_eap_capa(dev[0], "TEAPV2")
    params = int_teapv2_server_params(eap_teapv2_auth="1",
                                      eap_teapv2_id="5")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user", password="password",
                anonymous_identity="TEAPV2",
                ca_cert="auth_serv/ca.pem",
                expect_failure=True)

def test_eap_teap_peer_outer_tlvs(dev, apdev):
    """EAP-TEAP with peer Outer TLVs"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                phase1="teap_test_outer_tlvs=1")

def test_eap_teapv2_peer_outer_tlvs(dev, apdev):
    """EAP-TEAPV2 with peer Outer TLVs"""
    check_eap_capa(dev[0], "TEAPV2")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teapv2_server_params()
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user",
                anonymous_identity="TEAPV2", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                phase1="teapv2_test_outer_tlvs=1")

def test_eap_teap_eap_mschapv2_separate_result(dev, apdev):
    """EAP-TEAP with inner EAP-MSCHAPv2 and separate message for Result TLV"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teap_server_params(eap_teap_separate_result="1")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")

def test_eap_teapv2_eap_mschapv2_separate_result(dev, apdev):
    """EAP-TEAPV2 with inner EAP-MSCHAPv2 and separate message for Result TLV"""
    check_eap_capa(dev[0], "TEAPV2")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teapv2_server_params(eap_teapv2_separate_result="1")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user",
                anonymous_identity="TEAPV2", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")

def test_eap_teap_eap_mschapv2_id0(dev, apdev):
    """EAP-TEAP with inner EAP-MSCHAPv2 (eap_teap_id=0)"""
    run_eap_teap_eap_mschapv2_id(dev, apdev, 0)

def test_eap_teap_eap_mschapv2_id1(dev, apdev):
    """EAP-TEAP with inner EAP-MSCHAPv2 (eap_teap_id=1)"""
    run_eap_teap_eap_mschapv2_id(dev, apdev, 1)

def test_eap_teap_eap_mschapv2_id2(dev, apdev):
    """EAP-TEAP with inner EAP-MSCHAPv2 (eap_teap_id=2)"""
    run_eap_teap_eap_mschapv2_id(dev, apdev, 2, failure=True)

def test_eap_teap_eap_mschapv2_id3(dev, apdev):
    """EAP-TEAP with inner EAP-MSCHAPv2 (eap_teap_id=3)"""
    run_eap_teap_eap_mschapv2_id(dev, apdev, 3)

def test_eap_teap_eap_mschapv2_id4(dev, apdev):
    """EAP-TEAP with inner EAP-MSCHAPv2 (eap_teap_id=4)"""
    run_eap_teap_eap_mschapv2_id(dev, apdev, 4)

def test_eap_teapv2_eap_mschapv2_id0(dev, apdev):
    """EAP-TEAPV2 with inner EAP-MSCHAPv2 (eap_teapv2_id=0)"""
    run_eap_teapv2_eap_mschapv2_id(dev, apdev, 0)

def test_eap_teapv2_eap_mschapv2_id1(dev, apdev):
    """EAP-TEAPV2 with inner EAP-MSCHAPv2 (eap_teapv2_id=1)"""
    run_eap_teapv2_eap_mschapv2_id(dev, apdev, 1)

def test_eap_teapv2_eap_mschapv2_id2(dev, apdev):
    """EAP-TEAPV2 with inner EAP-MSCHAPv2 (eap_teapv2_id=2)"""
    run_eap_teapv2_eap_mschapv2_id(dev, apdev, 2, failure=True)

def test_eap_teapv2_eap_mschapv2_id3(dev, apdev):
    """EAP-TEAPV2 with inner EAP-MSCHAPv2 (eap_teapv2_id=3)"""
    run_eap_teapv2_eap_mschapv2_id(dev, apdev, 3)

def test_eap_teapv2_eap_mschapv2_id4(dev, apdev):
    """EAP-TEAPV2 with inner EAP-MSCHAPv2 (eap_teapv2_id=4)"""
    run_eap_teapv2_eap_mschapv2_id(dev, apdev, 4)

def run_eap_teap_eap_mschapv2_id(dev, apdev, eap_teap_id, failure=False):
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teap_server_params(eap_teap_id=str(eap_teap_id))
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                expect_failure=failure)

def run_eap_teapv2_eap_mschapv2_id(dev, apdev, eap_teapv2_id, failure=False):
    check_eap_capa(dev[0], "TEAPV2")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teapv2_server_params(eap_teapv2_id=str(eap_teapv2_id))
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user",
                anonymous_identity="TEAPV2", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                expect_failure=failure)

def test_eap_teap_eap_mschapv2_machine(dev, apdev):
    """EAP-TEAP with inner EAP-MSCHAPv2 using machine credential"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teap_server_params(eap_teap_id="2")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "",
                anonymous_identity="TEAP",
                machine_identity="machine", machine_password="machine-password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")

def test_eap_teapv2_eap_mschapv2_machine(dev, apdev):
    """EAP-TEAPV2 with inner EAP-MSCHAPv2 using machine credential"""
    check_eap_capa(dev[0], "TEAPV2")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teapv2_server_params(eap_teapv2_id="2")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "",
                anonymous_identity="TEAPV2",
                machine_identity="machine", machine_password="machine-password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")

def test_eap_teap_eap_mschapv2_user_and_machine(dev, apdev):
    """EAP-TEAP with inner EAP-MSCHAPv2 using user and machine credentials"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teap_server_params(eap_teap_id="5")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user", password="password",
                anonymous_identity="TEAP",
                machine_identity="machine", machine_password="machine-password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")

def test_eap_teapv2_eap_mschapv2_user_and_machine(dev, apdev):
    """EAP-TEAPV2 with inner EAP-MSCHAPv2 using user and machine credentials"""
    check_eap_capa(dev[0], "TEAPV2")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teapv2_server_params(eap_teapv2_id="5")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user", password="password",
                anonymous_identity="TEAPV2",
                machine_identity="machine", machine_password="machine-password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")

def test_eap_teap_eap_mschapv2_user_and_machine_seq1(dev, apdev):
    """EAP-TEAP with inner EAP-MSCHAPv2 using user and machine credentials (seq1)"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teap_server_params(eap_teap_id="5",
                                    eap_teap_method_sequence="1")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user", password="password",
                anonymous_identity="TEAP",
                machine_identity="machine", machine_password="machine-password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")

def test_eap_teapv2_eap_mschapv2_user_and_machine_seq1(dev, apdev):
    """EAP-TEAPV2 with inner EAP-MSCHAPv2 using user and machine credentials (seq1)"""
    check_eap_capa(dev[0], "TEAPV2")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teapv2_server_params(eap_teapv2_id="5",
                                      eap_teapv2_method_sequence="1")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user", password="password",
                anonymous_identity="TEAPV2",
                machine_identity="machine", machine_password="machine-password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")

def test_eap_teap_eap_mschapv2_user_and_machine_fail_user(dev, apdev):
    """EAP-TEAP with inner EAP-MSCHAPv2 using user and machine credentials (fail user)"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teap_server_params(eap_teap_id="5")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user", password="wrong-password",
                anonymous_identity="TEAP",
                machine_identity="machine", machine_password="machine-password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                expect_failure=True)

def test_eap_teapv2_eap_mschapv2_user_and_machine_fail_user(dev, apdev):
    """EAP-TEAPV2 with inner EAP-MSCHAPv2 using user and machine credentials (fail user)"""
    check_eap_capa(dev[0], "TEAPV2")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teapv2_server_params(eap_teapv2_id="5")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user", password="wrong-password",
                anonymous_identity="TEAPV2",
                machine_identity="machine", machine_password="machine-password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                expect_failure=True)

def test_eap_teap_eap_mschapv2_user_and_machine_fail_machine(dev, apdev):
    """EAP-TEAP with inner EAP-MSCHAPv2 using user and machine credentials (fail machine)"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teap_server_params(eap_teap_id="5")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user", password="password",
                anonymous_identity="TEAP",
                machine_identity="machine",
                machine_password="wrong-machine-password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                expect_failure=True)

def test_eap_teapv2_eap_mschapv2_user_and_machine_fail_machine(dev, apdev):
    """EAP-TEAPV2 with inner EAP-MSCHAPv2 using user and machine credentials (fail machine)"""
    check_eap_capa(dev[0], "TEAPV2")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teapv2_server_params(eap_teapv2_id="5")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user", password="password",
                anonymous_identity="TEAPV2",
                machine_identity="machine",
                machine_password="wrong-machine-password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                expect_failure=True)

def test_eap_teap_eap_mschapv2_user_and_machine_no_machine(dev, apdev):
    """EAP-TEAP with inner EAP-MSCHAPv2 using user and machine credentials (no machine)"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teap_server_params(eap_teap_id="5")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user", password="password",
                anonymous_identity="TEAP",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                expect_failure=True)

def test_eap_teapv2_eap_mschapv2_user_and_machine_no_machine(dev, apdev):
    """EAP-TEAPV2 with inner EAP-MSCHAPV2 using user and machine credentials (no machine)"""
    check_eap_capa(dev[0], "TEAPV2")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teapv2_server_params(eap_teapv2_id="5")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user", password="password",
                anonymous_identity="TEAPV2",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                expect_failure=True)

def test_eap_teap_eap_mschapv2_user_and_eap_tls_machine(dev, apdev):
    """EAP-TEAP with inner EAP-MSCHAPv2 user and EAP-TLS machine credentials"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "MSCHAPV2")
    check_eap_capa(dev[0], "TLS")
    params = int_teap_server_params(eap_teap_id="5")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user", password="password",
                anonymous_identity="TEAP",
                machine_identity="cert user",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                machine_phase2="auth=TLS",
                machine_ca_cert="auth_serv/ca.pem",
                machine_client_cert="auth_serv/user.pem",
                machine_private_key="auth_serv/user.key")

def test_eap_teapv2_eap_mschapv2_user_and_eap_tls_machine(dev, apdev):
    """EAP-TEAPV2 with inner EAP-MSCHAPv2 user and EAP-TLS machine credentials"""
    check_eap_capa(dev[0], "TEAPV2")
    check_eap_capa(dev[0], "MSCHAPV2")
    check_eap_capa(dev[0], "TLS")
    params = int_teapv2_server_params(eap_teapv2_id="5")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user", password="password",
                anonymous_identity="TEAPV2",
                machine_identity="cert user",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                machine_phase2="auth=TLS",
                machine_ca_cert="auth_serv/ca.pem",
                machine_client_cert="auth_serv/user.pem",
                machine_private_key="auth_serv/user.key")

def test_eap_teap_fragmentation(dev, apdev):
    """EAP-TEAP with fragmentation"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                fragment_size="100")

def test_eap_teapv2_fragmentation(dev, apdev):
    """EAP-TEAPV2 with fragmentation"""
    check_eap_capa(dev[0], "TEAPV2")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teapv2_server_params()
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user",
                anonymous_identity="TEAPV2", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                fragment_size="100")

def test_eap_teap_tls_cs_sha1(dev, apdev):
    """EAP-TEAP with TLS cipher suite that uses SHA-1"""
    run_eap_teap_tls_cs(dev, apdev, "AES128-SHA")

def test_eap_teap_tls_cs_sha256(dev, apdev):
    """EAP-TEAP with TLS cipher suite that uses SHA-256"""
    run_eap_teap_tls_cs(dev, apdev, "AES128-SHA256")

def test_eap_teap_tls_cs_sha384(dev, apdev):
    """EAP-TEAP with TLS cipher suite that uses SHA-384"""
    run_eap_teap_tls_cs(dev, apdev, "AES256-GCM-SHA384")

def test_eap_teapv2_tls_cs_sha1(dev, apdev):
    """EAP-TEAPV2 with TLS cipher suite that uses SHA-1"""
    run_eap_teapv2_tls_cs(dev, apdev, "AES128-SHA")

def test_eap_teapv2_tls_cs_sha256(dev, apdev):
    """EAP-TEAPV2 with TLS cipher suite that uses SHA-256"""
    run_eap_teapv2_tls_cs(dev, apdev, "AES128-SHA256")

def test_eap_teapv2_tls_cs_sha384(dev, apdev):
    """EAP-TEAPV2 with TLS cipher suite that uses SHA-384"""
    run_eap_teapv2_tls_cs(dev, apdev, "AES256-GCM-SHA384")

def run_eap_teap_tls_cs(dev, apdev, cipher):
    check_eap_capa(dev[0], "TEAP")
    tls = dev[0].request("GET tls_library")
    if not tls.startswith("OpenSSL") and not tls.startswith("wolfSSL"):
        raise HwsimSkip("TLS library not supported for TLS CS configuration: " + tls)
    params = int_teap_server_params(eap_teap_auth="1")
    params['openssl_ciphers'] = cipher
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP", password="password",
                ca_cert="auth_serv/ca.pem")

def run_eap_teapv2_tls_cs(dev, apdev, cipher):
    check_eap_capa(dev[0], "TEAPV2")
    tls = dev[0].request("GET tls_library")
    if not tls.startswith("OpenSSL") and not tls.startswith("wolfSSL"):
        raise HwsimSkip("TLS library not supported for TLS CS configuration: " + tls)
    params = int_teapv2_server_params(eap_teapv2_auth="1")
    params['openssl_ciphers'] = cipher
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "user",
                anonymous_identity="TEAPV2", password="password",
                ca_cert="auth_serv/ca.pem")

def wait_eap_proposed(dev, wait_trigger=None):
    ev = dev.wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAP start")
    if wait_trigger:
        wait_fail_trigger(dev, wait_trigger)
    dev.request("REMOVE_NETWORK all")
    dev.wait_disconnected()
    dev.dump_monitor()

def test_eap_teap_errors(dev, apdev):
    """EAP-TEAP local errors"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP",
                   scan_freq="2412",
                   eap="TEAP", identity="user", password="password",
                   anonymous_identity="TEAP",
                   ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                   wait_connect=False)
    wait_eap_proposed(dev[0])

    tests = [(1, "eap_teap_tlv_eap_payload"),
             (1, "eap_teap_process_eap_payload_tlv"),
             (1, "eap_teap_compound_mac"),
             (1, "eap_teap_tlv_result"),
             (1, "eap_peer_select_phase2_methods"),
             (1, "eap_peer_tls_ssl_init"),
             (1, "eap_teap_session_id"),
             (1, "wpabuf_alloc;=eap_teap_process_crypto_binding"),
             (1, "eap_peer_tls_encrypt"),
             (1, "eap_peer_tls_decrypt"),
             (1, "eap_teap_getKey"),
             (1, "eap_teap_session_id"),
             (1, "eap_teap_init")]
    for count, func in tests:
        with alloc_fail(dev[0], count, func):
            dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP",
                           scan_freq="2412",
                           eap="TEAP", identity="user", password="password",
                           anonymous_identity="TEAP",
                           ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                           wait_connect=False)
            wait_eap_proposed(dev[0], wait_trigger="GET_ALLOC_FAIL")

    tests = [(1, "eap_teap_derive_eap_msk"),
             (1, "eap_teap_derive_eap_emsk"),
             (1, "eap_teap_write_crypto_binding"),
             (1, "eap_teap_process_crypto_binding"),
             (1, "eap_teap_derive_msk;eap_teap_process_crypto_binding"),
             (1, "eap_teap_compound_mac;eap_teap_process_crypto_binding"),
             (1, "eap_teap_derive_imck")]
    for count, func in tests:
        with fail_test(dev[0], count, func):
            dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP",
                           scan_freq="2412",
                           eap="TEAP", identity="user", password="password",
                           anonymous_identity="TEAP",
                           ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                           wait_connect=False)
            wait_eap_proposed(dev[0], wait_trigger="GET_FAIL")

def test_eap_teapv2_errors(dev, apdev):
    """EAP-TEAPV2 local errors"""
    check_eap_capa(dev[0], "TEAPV2")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teapv2_server_params()
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP",
                   scan_freq="2412",
                   eap="TEAPV2", identity="user", password="password",
                   anonymous_identity="TEAPV2",
                   ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                   wait_connect=False)
    wait_eap_proposed(dev[0])

    tests = [(1, "eap_teapv2_tlv_eap_payload"),
             (1, "eap_teapv2_process_eap_payload_tlv"),
             (1, "eap_teapv2_compound_mac"),
             (1, "eap_teapv2_tlv_result"),
             (1, "eap_peer_tls_ssl_init"),
             (1, "eap_teapv2_session_id"),
             (1, "wpabuf_alloc;=eap_teapv2_process_crypto_binding"),
             (1, "eap_peer_tls_encrypt"),
             (1, "eap_peer_tls_decrypt"),
             (1, "eap_teapv2_getKey"),
             (1, "eap_teapv2_session_id"),
             (1, "eap_teapv2_init")]
    for count, func in tests:
        with alloc_fail(dev[0], count, func):
            dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP",
                           scan_freq="2412",
                           eap="TEAPV2", identity="user", password="password",
                           anonymous_identity="TEAPV2",
                           ca_cert="auth_serv/ca.pem",
                           phase2="auth=MSCHAPV2",
                           wait_connect=False)
            wait_eap_proposed(dev[0], wait_trigger="GET_ALLOC_FAIL")

    tests = [(1, "eap_teapv2_derive_eap_msk"),
             (1, "eap_teapv2_derive_eap_emsk"),
             (1, "eap_teapv2_write_crypto_binding"),
             (1, "eap_teapv2_process_crypto_binding"),
             (1, "eap_teapv2_derive_msk;eap_teapv2_process_crypto_binding"),
             (1, "eap_teapv2_compound_mac;eap_teapv2_process_crypto_binding"),
             (1, "eap_teapv2_derive_imck")]
    for count, func in tests:
        with fail_test(dev[0], count, func):
            dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP",
                           scan_freq="2412",
                           eap="TEAPV2", identity="user", password="password",
                           anonymous_identity="TEAPV2",
                           ca_cert="auth_serv/ca.pem",
                           phase2="auth=MSCHAPV2",
                           wait_connect=False)
            wait_eap_proposed(dev[0], wait_trigger="GET_FAIL")

def test_eap_teap_errors2(dev, apdev):
    """EAP-TEAP local errors 2 (Basic-Password-Auth specific)"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teap_server_params(eap_teap_auth="1")
    hapd = hostapd.add_ap(apdev[0], params)

    tests = [(1, "eap_teap_process_basic_auth_req")]
    for count, func in tests:
        with alloc_fail(dev[0], count, func):
            dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP",
                           scan_freq="2412",
                           eap="TEAP", identity="user", password="password",
                           anonymous_identity="TEAP",
                           ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                           wait_connect=False)
            wait_eap_proposed(dev[0], wait_trigger="GET_ALLOC_FAIL")

    tests = [(1, "eap_teap_derive_imck")]
    for count, func in tests:
        with fail_test(dev[0], count, func):
            dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP",
                           scan_freq="2412",
                           eap="TEAP", identity="user", password="password",
                           anonymous_identity="TEAP",
                           ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                           wait_connect=False)
            wait_eap_proposed(dev[0], wait_trigger="GET_FAIL")

def test_eap_teapv2_errors2(dev, apdev):
    """EAP-TEAPV2 local errors 2 (Basic-Password-Auth specific)"""
    check_eap_capa(dev[0], "TEAPV2")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teapv2_server_params(eap_teapv2_auth="1")
    hapd = hostapd.add_ap(apdev[0], params)

    tests = [(1, "eap_teapv2_process_basic_auth_req")]
    for count, func in tests:
        with alloc_fail(dev[0], count, func):
            dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP",
                           scan_freq="2412",
                           eap="TEAPV2", identity="user", password="password",
                           anonymous_identity="TEAPV2",
                           ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                           wait_connect=False)
            wait_eap_proposed(dev[0], wait_trigger="GET_ALLOC_FAIL")

def test_eap_teap_eap_vendor(dev, apdev):
    """EAP-TEAP with inner EAP-vendor"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "VENDOR-TEST")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "vendor-test-2",
                anonymous_identity="TEAP",
                ca_cert="auth_serv/ca.pem", phase2="auth=VENDOR-TEST")

def test_eap_teapv2_eap_vendor(dev, apdev):
    """EAP-TEAPV2 with inner EAP-vendor"""
    check_eap_capa(dev[0], "TEAPV2")
    check_eap_capa(dev[0], "VENDOR-TEST")
    params = int_teapv2_server_params()
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAPV2", "vendor-test-2",
                anonymous_identity="TEAPV2",
                ca_cert="auth_serv/ca.pem", phase2="auth=VENDOR-TEST")

def test_eap_teap_client_cert(dev, apdev):
    """EAP-TEAP with client certificate in Phase 1"""
    check_eap_capa(dev[0], "TEAP")
    params = int_teap_server_params(eap_teap_auth="2")
    hapd = hostapd.add_ap(apdev[0], params)

    # verify server accept a client with certificate, but no Phase 2
    # configuration
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP",
                client_cert="auth_serv/user.pem",
                private_key="auth_serv/user.key",
                ca_cert="auth_serv/ca.pem")
    dev[0].dump_monitor()
    res = eap_reauth(dev[0], "TEAP")
    if res['tls_session_reused'] != '1':
        # This is not yet supported without PAC.
        logger.info("EAP-TEAP could not use session ticket")
        #raise Exception("EAP-TEAP could not use session ticket")

    # verify server accepts a client without certificate
    eap_connect(dev[1], hapd, "TEAP", "user",
                anonymous_identity="TEAP", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")

def test_eap_teapv2_client_cert(dev, apdev):
    """EAP-TEAPV2 with client certificate in Phase 1"""
    check_eap_capa(dev[0], "TEAPV2")
    params = int_teapv2_server_params(eap_teapv2_auth="2")
    hapd = hostapd.add_ap(apdev[0], params)

    # verify server accept a client with certificate, but no Phase 2
    # configuration
    eap_connect(dev[0], hapd, "TEAPV2", "user",
                anonymous_identity="TEAPV2",
                client_cert="auth_serv/user.pem",
                private_key="auth_serv/user.key",
                ca_cert="auth_serv/ca.pem")
    dev[0].dump_monitor()
    res = eap_reauth(dev[0], "TEAPV2")
    if res['tls_session_reused'] != '1':
        # This is not yet supported without PAC.
        logger.info("EAP-TEAPV2 could not use session ticket")
        #raise Exception("EAP-TEAPV2 could not use session ticket")

    # verify server accepts a client without certificate
    eap_connect(dev[1], hapd, "TEAPV2", "user",
                anonymous_identity="TEAPV2", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")
