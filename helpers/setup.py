import helpers.get_schemes
import helpers.adb
import argparse
import os

def is_valid_file(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return arg

def get_parsed_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-apk',
                        dest='apk',
                        required=False,
                        metavar="FILE", 
    					type=lambda x: helpers.setup.is_valid_file(parser, x),
                        help='Path to the APK')
    parser.add_argument('-p', '--package',
                        dest="package",
                        required=True,
    					type=str,
                        help='Package identifier, e.g.: com.myorg.appname')
    parser.add_argument('-m', '--manifest', 
                        dest="manifest",
                        required=False,
                        metavar="FILE", 
    					type=lambda x: helpers.setup.is_valid_file(parser, x),
                        help='Path to the AndroidManifest.xml file')
    parser.add_argument('-s', '--strings',
                        dest="strings",
                        required=False,
                        metavar="FILE", 
    					type=lambda x: helpers.setup.is_valid_file(parser, x),
                        help='Path to the strings.xml file')
    parser.add_argument('--verify',
                        dest='verify',
                        required=False,
                        action='store_true',
                        help='Whether or not the script should verify the App Links (default: False)')
    parser.add_argument('--clear',
                        dest='clear',
                        required=False,
                        action='store_true',
                        help='Whether or not the script should delete the decompiled directory after running (default: False)')
    return parser.parse_args()

def decompile_apk(apk):
    os.system("apktool d " + apk)

def check_device_configs(package, apk):
    devices = helpers.adb.adbdevices()
    if len(devices) == 0:
        print("No devices were detected by adb")
        exit()
    if not helpers.adb.package_is_installed(package):
        if apk is None:
            print("Package is not installed and APK was not specified ...")
        else:
            print("Package is not installed ...")
            os.system("adb install " + apk)

def write_deeplinks_to_file(activity_handlers, poc_filename):
    html = "<!DOCTYPE html>\n<html>\n<body>\n<div>\n"
    for activity, handlers in activity_handlers.items():
        html += '<h3>' + activity + '</h3>\n'
        for deeplink in sorted(handlers):
            if "http" in deeplink:
                html += '<a href="' + deeplink + '">' + deeplink + '</a></br>'
    html += "</div>\n</body>\n</html>"
    html_file = open(poc_filename, 'w')
    html_file.write(html)
    html_file.close()        