# `QubesDB` implementation for Windows.

- TODO: installer for win10 QWT
- TODO: integrate with Qubes builder

### Environment variables

- `QUBES_INCLUDES` must contain paths containing `windows-utils` and `libvchan` includes. Normally it's `<src>/qubes-windows-utils/include;<src>/qubes-core-vchan-xen/windows/include`.
- `QUBES_LIBS` must contain paths containing `windows-utils` and `libvchan` libraries. Normally it's `<src>/qubes-windows-utils/bin;<src>/qubes-core-vchan-xen/windows/bin`.

## Command-line build

`EWDK_PATH` env variable must be set to the root of MS Enterprise WDK for Windows 10/Visual Studio 2022. 

`build.cmd` script builds the solution from command line using the EWDK (no need for external VS installation).

Usage: `build.cmd Release|Debug`
