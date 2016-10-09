import py2exe
from distutils.core import setup

setup(
    windows=["main.py"], zipfile=None, requires=['requests']
)
