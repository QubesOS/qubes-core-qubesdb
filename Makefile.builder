RPM_SPEC_FILES := rpm_spec/qubes-db.spec

ifeq ($(PACKAGE_SET),dom0)
  RPM_SPEC_FILES += rpm_spec/qubes-db-dom0.spec

else ifeq ($(PACKAGE_SET),vm)
  ifneq ($(filter $(DISTRIBUTION), debian qubuntu),)
    DEBIAN_BUILD_DIRS := debian
    SOURCE_COPY_IN := source-debian-quilt-copy-in
  endif

  RPM_SPEC_FILES += rpm_spec/qubes-db-vm.spec
endif

WIN_SOURCE_SUBDIRS := .
WIN_COMPILER := mingw
WIN_PACKAGE_CMD := make msi
WIN_BUILD_DEPS = core-vchan-$(BACKEND_VMM)

source-debian-quilt-copy-in: VERSION = $(shell cat $(ORIG_SRC)/version)
source-debian-quilt-copy-in: ORIG_FILE = "$(CHROOT_DIR)/$(DIST_SRC)/../qubesdb_$(VERSION).orig.tar.gz"
source-debian-quilt-copy-in:
	-$(shell $(ORIG_SRC)/debian-quilt $(ORIG_SRC)/series-debian-vm.conf $(CHROOT_DIR)/$(DIST_SRC)/debian/patches)
	tar cvfz $(ORIG_FILE) --exclude-vcs --exclude=debian -C $(CHROOT_DIR)/$(DIST_SRC) .

# vim: filetype=make
