<p align="left">
  <a href="https://www.python.org" alt="python">
    <img src="https://img.shields.io/badge/3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue?logo=python&logoColor=white&logoSize=auto&label=python&labelColor=grey" alt="Python"></a>
  <a href="https://pypi.org/project/grypereport/" alt="pypi">
    <img src="https://img.shields.io/pypi/v/grypereport?logo=pypi&logoColor=white&color=%2390A1B9" alt="PyPI"></a>
  <a href="https://github.com/amarienko/GrypeReport" alt="github tag">
    <img src="https://img.shields.io/github/v/tag/amarienko/GrypeReport?logo=github&color=orange" alt="GitHub"></a>
  <a href="https://opensource.org/licenses/MIT" alt="License">
    <img src="https://img.shields.io/github/license/amarienko/GrypeReport"/></a>
  <a href="https://github.com/psf/black" alt="black">
    <img src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>
</p>

# GrypeReport
`grypereport` is a lightweight CLI tool for generating custom reports from the standard JSON output of the [Grype](https://github.com/anchore/grype) vulnerability scanner. `grypereport` generates reports on detected vulnerabilities, exports them to CSV, and integrates with [TeamCity](https://www.jetbrains.com/teamcity/) by publishing a build tag with the total and critical vulnerability counts via TeamCity Service Messages.

**Disclaimer**: [Grype](https://github.com/anchore/grype) and [TeamCity](https://www.jetbrains.com/teamcity/) are trademarks and copyrights of their respective owners, this project is not affiliated with, endorsed by, or sponsored by them.
