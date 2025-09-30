# GrypeReport
`grypereport` is a lightweight CLI tool for generating custom reports from the standard JSON output of the [Grype](https://github.com/anchore/grype) vulnerability scanner. `grypereport` generates reports on detected vulnerabilities, exports them to CSV, and integrates with [TeamCity](https://www.jetbrains.com/teamcity/) by publishing a build tag with the total and critical vulnerability counts via TeamCity Service Messages.

**Disclaimer**: [Grype](https://github.com/anchore/grype) and [TeamCity](https://www.jetbrains.com/teamcity/) are trademarks and copyrights of their respective owners, this project is not affiliated with, endorsed by, or sponsored by them.
