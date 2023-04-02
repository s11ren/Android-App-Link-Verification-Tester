#!/usr/bin/env python3

import subprocess

KEYTOOL_PATH = 'keytool'
APKSIGNER_PATH = 'apksigner'

def get_sha256_cert_fingerprint(apk):
    apk_cert = subprocess.Popen(
        KEYTOOL_PATH + ' -printcert -jarfile ' + apk, shell=True, stdout=subprocess.PIPE
    ).stdout.read().decode()

    # add sha256sum recovery when apk is not signed with scheme v1 (jar signature)
    if 'Not a signed jar file' in apk_cert:
    apk_cert = subprocess.Popen(
        APKSIGNER_PATH + ' verify --print-certs ' + apk, shell=True, stdout=subprocess.PIPE
    ).stdout.read().decode()    
    components = apk_cert.split('SHA-256 digest: ')  
    if len(components) > 1:
        sha256sum = components[1].split('\n')[0]
        return ':'.join(sha256sum[i:i+2] for i in range(0, len(sha256sum), 2)).upper()

    if 'SHA256: ' in apk_cert:
        components = apk_cert.split('SHA256: ')
        if len(components) > 1:
            return components[1].split('\n')[0]
    return None