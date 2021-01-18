import sys
from distutils.core import setup


setup(
    name="mos-ble",
    version="0.2.0",
    description="A tool to talk rpc to Mongoose-OS devices over gatts",
    author="Kiril Zyapkov",
    author_email="kiril.zyapkov@gmail.com",
    url="http://github.com/kzyapkov/mos-ble",
    py_modules=['mos_ble'],
    install_requires=['bleak'],
    entry_points = {
        'console_scripts': ['mos-ble=mos_ble:main'],
    }
)

