from setuptools import setup, find_packages
import pathlib

here = pathlib.Path(__file__).parent
requirements = (here / "requirements.txt").read_text().splitlines()

setup(
    name="stahlta",
    version="0.1",
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "stahlta = components.main.stahlta:stahlta_asyncio_run",
            "stahlta-gui = components.main.stahlta:stahltagui_main"
        ],
    },
)