import sys
from distutils.core import setup

install_requires = ['gatt', 'dbus-python', 'gobject']

if hasattr(sys, 'real_prefix'):
    # inside virtualenv
    install_requires.extend(['vext', 'vext.gi'])

setup(
    name="mos-ble",
    version="0.1.0",
    description="A tool to talk rpc to Mongoose-OS devices over gatts",
    author="Kiril Zyapkov",
    author_email="kiril.zyapkov@gmail.com",
    url="http://github.com/kzyapkov/mos-ble",
    py_modules=['mos_ble'],
    install_requires=install_requires,
    entry_points = {
        'console_scripts': ['mos-ble=mos_ble:main'],
    }
)

