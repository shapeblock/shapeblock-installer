# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

### Added

- Install container registry
- Install kpack
- Install kpack cluster stores and cluster stacks

### Changed

- Fix cron job creation

### Removed

- Removed resource constraints on backend and frontend.
- Epinio is no longer installed.

## [1.0.4] - 2024-12-19

### Added

- Installer accepts app name, first and last name

### Changed

- Changed the way the app name is slugified
- Changed the way the dashboard ConfigMaps are applied

### Removed

- Removed resource constraints on backend.

### Added

- Added Prometheus Stack with Grafana dashboards
