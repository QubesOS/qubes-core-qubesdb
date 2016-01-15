#
# This is the SPEC file for creating binary and source RPMs for the Qubes DB.
#
#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2013  Marek Marczykowski <marmarek@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#

%{!?version: %define version %(cat version)}
%{!?backend_vmm: %define backend_vmm %(echo $BACKEND_VMM)}
%if "%(echo $PACKAGE_SET)" == "dom0"
%define install_dom0_service 1
%endif

%{!?python_sitearch: %define python_sitearch %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib(1)")}

Name:		qubes-db
Version:	%{version}
Release:	1%{?dist}
Summary:	QubesDB tools

Group:		Qubes
License:	GPL
URL:		http://www.qubes-os.org/

BuildRequires:	qubes-libvchan-%{backend_vmm}-devel
BuildRequires:	systemd-devel
BuildRequires:	python-devel
Requires:	qubes-libvchan-%{backend_vmm}
# XXX: VMM specific
Requires:   xen-libs >= 2001:4.6.1-20

%define _builddir %(pwd)

%description
QubesDB management tools and daemon.

%package libs
Summary:	QubesDB libs
Group:		Qubes

%description libs
QubesDB client library.

%package devel
Summary:	QubesDB client header files
Group:		Qubes
Requires:	qubes-db-libs

%description devel
Header files for QubesDB client library and daemon protocol.

%prep
# we operate on the current directory, so no need to unpack anything
# symlink is to generate useful debuginfo packages
rm -f %{name}-%{version}
ln -sf . %{name}-%{version}
%setup -T -D

%build
make %{?_smp_mflags} all

%install
make install DESTDIR=%{buildroot} LIBDIR=%{_libdir} BINDIR=%{_bindir} SBINDIR=%{_sbindir}


%files
%doc
%{_bindir}/qubesdb-cmd
%{_bindir}/qubesdb-read
%{_bindir}/qubesdb-write
%{_bindir}/qubesdb-rm
%{_bindir}/qubesdb-multiread
%{_bindir}/qubesdb-list
%{_bindir}/qubesdb-watch
%{_sbindir}/qubesdb-daemon

%files libs
%{_libdir}/libqubesdb.so
%{python_sitearch}/QubesDB-*egg-info
%{python_sitearch}/qubesdb.so

%files devel
/usr/include/qubesdb.h
/usr/include/qubesdb-client.h

%changelog

