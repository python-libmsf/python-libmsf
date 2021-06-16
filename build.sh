#!/bin/sh
rm -rf dist/
rm -rf libmsf.egg-info/
python3.6 setup.py sdist
pip3.6 wheel --no-index --no-deps --wheel-dir dist dist/*.tar.gz
python3.6 -m twine upload --repository pypi dist/*