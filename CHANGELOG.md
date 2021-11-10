# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to the following versioning pattern:

Given a version number MAJOR.MINOR.PATCH, increment:

- MAJOR version when **breaking changes** are introduced;
- MINOR version when **backwards compatible changes** are introduced;
- PATCH version when backwards compatible bug **fixes** are implemented.


## [Unreleased]
### Fixed
- point at infinity verification in signature and public key
- missing :crypto Erlang application reference to mix.exs
### Changed
- internal files and modules structure
- internal .Data structs to be integrated into the respective modules

## [1.0.1] - 2021-11-04
### Fixed
- signature r and s range check

## [1.0.0] - 2020-04-14
### Added
- first official version
