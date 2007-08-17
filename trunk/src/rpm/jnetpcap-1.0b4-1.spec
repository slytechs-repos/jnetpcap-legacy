#
#   RPM package specification for jpcap
#
%define JNETPCAP_VERSION 1.0b4
%define JNETPCAP jnetpcap-%JNETPCAP_VERSION

Summary: A libpcap java wrapper
Name: jnetpcap
Version: %JNETPCAP_VERSION
Release: 1
Copyright: LGPL
Group: Development/Java
Packager: Mark Bednarczyk <mark@slytechs.com>
Source: http://downloads.sourceforge.net/jnetpcap/jnetpcap-1.0b3-win32.zip
Vendor: <http://jnetpcap.sf.net>
# Distribution: jnetpcap <http://jnetpcap.sf.net>

BuildRequires: j2sdk >= 1.5, libpcap >= 0.8
Requires: j2sdk >= 1.5, libpcap >= 0.8
BuildRoot: /tmp/%{name}-%JNETPCAP_VERSION-pkgroot

%description
jNetPcap is a java wrapper around libpcap. It provides all of the same methods
using similar style of API as the native counter part. All the native libpcap
structures and methods are tightly and accurately peered with each other,
providing entire libpcap environment under java.

%prep

%setup

%build
PROJECT_HOME=/usr/src/redhat/BUILD/%JNETPCAP
cd $PROJECT_HOME
ant clean package

%pre 

%install
cd $PROJECT_HOME


%post

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(+r,nobody,nobody)
%doc docs/RELEASE_NOTES docs/CHANGE_LOG

/usr/lib/libjnetpcap.so
/usr/lib/%JNETPCAP/%JNETPCAP.jar
/usr/lib/%jpcap/jars/javadoc_net.sourceforge.%jpcap.jar
/usr/lib/%jpcap/thirdParty/jars/dev-classes_net.ultrametrics-0.03.jar
/usr/lib/%jpcap/thirdParty/jars/fooware_CommandLine-1.0.jar
/usr/lib/%jpcap/properties/tool.properties
/usr/lib/%jpcap/properties/simulator.properties


%changelog
* Friday August 17 2007 Mark Bednarczyk <mark@slytechs.com>

- Initial RPM build
