#
#   RPM package specification for JNETPCAP
#
%define VERSION @pkg.version@
%define RELEASE @platform.os.name@
%define JNETPCAP jnetpcap-%{VERSION}

Summary: A libpcap java wrapper
Name: jnetpcap
Version: %{VERSION}
Release: %{RELEASE}
License: LGPL
Group: Development/Java
Packager: Sly Technologies, Inc. <http://www.slytechs.com>
Vendor: Sly Technologies, Inc <http://www.slytechs.com>
Distribution: jnetpcap <http://jnetpcap.org>
Requires: libpcap >= 0.8.0
Provides: java-libpcap, java-packet-capture


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
%doc LICENSE.txt RELEASE_NOTES.txt CHANGE_LOG.txt

/usr/lib/libjnetpcap.so.%{VERSION}
/usr/share/java/%{JNETPCAP}.jar

%post
ln -s /usr/lib/libjnetpcap.so.%{VERSION} /usr/lib/libjnetpcap.so
ln -s /usr/share/java/jnetpcap-%{VERSION}.jar /usr/share/java/jnetpcap.jar

%postun
rm -f /usr/lib/libjnetpcap.so
rm -f /usr/share/java/jnetpcap.jar
