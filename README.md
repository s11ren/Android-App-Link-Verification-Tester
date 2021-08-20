# Android Deep Link Analyser

Tool that helps with enumerating an Android application's deep links, and checking if the App Links are correctly verified.

You can read more about App Link Verification [here](https://developer.android.com/training/app-links/verify-site-associations).

Supports 4 operation modes:

* `list-all`: lists all deeplink URIs registered by the application, regardless of format
* `list-applinks`: lists all Android App Links registered by the application
* `build-poc`: creates an HTML page with links to all the registered Android App Links in order to simplify the process of testing their verification process
* `launch-poc`: sends the HTML page to a connected device, and opens it with Chrome

### Installation

```
python3 -m pip install -r requirements.txt
```

**Important Notes**

If you want to provide an `.apk` file instead of the `AndroidManifest.xml` and `strings.xml`, then you need to have [apktool](https://ibotpeaches.github.io/Apktool/) installed and accessible on the `$PATH`.

If you want to use the `launch-poc` operation mode, you need to have [adb](https://developer.android.com/studio/command-line/adb) installed and accessible on the `$PATH`.

### Usage

```
~ python3 deeplink_analyser.py --help
usage: deeplink_analyser.py [-h] [-apk FILE] -p PACKAGE [-m FILE] [-s FILE]
                            -op OP [--clear]

optional arguments:
  -h, --help            show this help message and exit
  -apk FILE             Path to the APK
  -p PACKAGE, --package PACKAGE
                        Package identifier, e.g.: com.myorg.appname
  -m FILE, --manifest FILE
                        Path to the AndroidManifest.xml file
  -s FILE, --strings FILE
                        Path to the strings.xml file
  -op OP, --operation-mode OP
                        Operation mode: can be "list-all", "list-applinks", "build-poc" or "launch-poc"
  --clear               Whether or not the script should delete the decompiled
                        directory after running (default: False)
```
