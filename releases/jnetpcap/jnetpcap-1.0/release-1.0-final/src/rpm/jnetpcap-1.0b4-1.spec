#
#   RPM package specification for JNETPCAP
#
%define JNETPCAP_VERSION @pkg.version@
%define JNETPCAP jnetpcap-%{JNETPCAP_VERSION}

Summary: A libpcap java wrapper
Name: jnetpcap
Version: %{JNETPCAP_VERSION}
Release: linux
License: LGPL
Group: Development/Java
Packager: Sly Technologies, Inc. <http://slytechs.com>
Vendor: Sly Technologies, Inc <http://jnetpcap.sf.net>
Distribution: jnetpcap <http://jnetpcap.sf.net>


%description
jNetPcap is a java wrapper around libpcap. It provides all of the same methods
using similar style of API as the native counter part. All the native libpcap
structures and methods are tightly and accurately peered with each other,
providing entire libpcap environment under java.

%prep

%build
pwd

%install

%files
%doc LICENSE.txt RELEASE_NOTES.txt CHANGE_LOG.txt javadoc

/usr/lib/libjnetpcap.so
/usr/share/java/%{JNETPCAP}.jar
