RPMS_DIR = rpm/
VERSION = $(shell cat version)

help:
	@echo "make all                   -- compile all binaries"
	@echo "make rpms-vm               -- generate binary rpm packages for VM"
	@echo "make rpms-dom0               -- generate binary rpm packages for Dom0"

rpms-dom0:
	PACKAGE_SET=dom0 rpmbuild --define "_rpmdir $(RPMS_DIR)" -bb rpm_spec/qubes-db.spec

rpms-vm:
	PACKAGE_SET=vm rpmbuild --define "_rpmdir $(RPMS_DIR)" -bb rpm_spec/qubes-db.spec

all:
	$(MAKE) -C daemon
	$(MAKE) -C client
	$(MAKE) -C python

clean:
	$(MAKE) -C daemon clean
	$(MAKE) -C client clean
	$(MAKE) -C python clean

install:
	$(MAKE) -C daemon install
	$(MAKE) -C client install
	$(MAKE) -C python install
	$(MAKE) -C include install

msi:
	$(MAKE) -C python install PYTHON_PREFIX_ARG=--prefix=. DESTDIR=python27
	candle -arch x64 -dversion=$(VERSION) installer.wxs
	light -o core-qubesdb.msm installer.wixobj
