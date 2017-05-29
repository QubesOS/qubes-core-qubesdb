RPM_SPEC_FILES := rpm_spec/qubes-db.spec

ifeq ($(PACKAGE_SET),dom0)
  RPM_SPEC_FILES += rpm_spec/qubes-db-dom0.spec

else ifeq ($(PACKAGE_SET),vm)
  ifneq ($(filter $(DISTRIBUTION), debian qubuntu),)
    DEBIAN_BUILD_DIRS := debian
    SOURCE_COPY_IN := source-debian-quilt-copy-in
  endif

  RPM_SPEC_FILES += rpm_spec/qubes-db-vm.spec
  ARCH_BUILD_DIRS := archlinux
endif

ifeq ($(PACKAGE_SET),vm)
  WIN_SOURCE_SUBDIRS := windows
  WIN_COMPILER := msbuild
  WIN_OUTPUT_LIBS = bin
  WIN_OUTPUT_HEADERS = ../include
  WIN_BUILD_DEPS = core-vchan-$(BACKEND_VMM) windows-utils
  WIN_PREBUILD_CMD = set_version.bat && powershell -executionpolicy bypass set_version.ps1
endif

source-debian-quilt-copy-in:
	$(shell $(ORIG_SRC)/debian-quilt $(ORIG_SRC)/series-debian-vm.conf $(CHROOT_DIR)/$(DIST_SRC)/debian/patches)

# vim: filetype=make
