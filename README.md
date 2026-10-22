<img src="https://user-images.githubusercontent.com/1423657/55069501-8348c400-5084-11e9-9931-fefe0f9874a7.png" width=200/>


CaptAgent
=========

### The Next-Generation HEP Capture Agent for [Homer](https://github.com/sipcapture/homer)
-------------
![HEP](https://img.shields.io/badge/proto-hep_eep-blue.svg)
![HEP](https://img.shields.io/badge/proto-sip-brightgreen.svg)
![HEP](https://img.shields.io/badge/proto-rtcp-brightgreen.svg)
![HEP](https://img.shields.io/badge/proto-rtcp_xr-brightgreen.svg)
![HEP](https://img.shields.io/badge/proto-rtp_stats-brightgreen.svg)
![HEP](https://img.shields.io/badge/proto-ss7_isup-brightgreen.svg)
![HEP](https://img.shields.io/badge/proto-epan-orange.svg)
![HEP](https://img.shields.io/badge/proto-diameter-orange.svg)
![HEP](https://img.shields.io/badge/proto-tls_rsa-orange.svg)

Captagent is a powerful, flexible, completely modular HEP packet capture and mirroring framework for RTC, ready for _(virtually)_ any kind of IP protocol and encapsulation method - past, present - and future.

### Status
[![Build Status](https://travis-ci.org/sipcapture/captagent.svg?branch=master)](https://travis-ci.org/sipcapture/captagent)

### Get Started
Setup & Configuration instructions are available on the Project [Wiki](https://github.com/sipcapture/captagent/wiki/Installation)

### Build Dependencies (DEB/RPM)

For local builds, install the required development tools and libraries first.

Debian/Ubuntu packages:
- m4
- automake
- autoconf
- libtool
- make
- gcc
- flex
- libfl-dev
- bison
- libexpat-dev
- libpcap-dev
- libjson-c-dev
- libuv1-dev

RHEL/Fedora packages:
- m4
- automake
- autoconf
- libtool
- make
- gcc
- flex
- flex-devel
- bison
- expat-devel
- libpcap-devel
- json-c-devel
- libuv-devel

Optional auto-install helper:
- The build script supports an opt-in dependency bootstrap for DEB/RPM systems.
- Run with AUTO_INSTALL_DEPS=1 to let build.sh install Flex and libfl/flex-devel automatically before autoreconf.
- Example: AUTO_INSTALL_DEPS=1 ./build.sh

-------------

### Support
If you found a bug or issue with the code, please raise an Issue on the project tracker.

If you want to send a PR, please make sure to indent your code using our [format script](https://github.com/sipcapture/captagent/blob/dev/format_code.sh)

If you have specific questions or require professional support please contact us at support@sipcapture.org

![HomerFlow](http://i.imgur.com/U7UBI.png)


---

### Fork Extensions

This fork (`slmingol/captagent`) adds modules not present upstream.

#### transport_erspan — GRE/ERSPAN Transport

Sends captured SIP/RTP encapsulated in GRE or ERSPAN (Type I/II/III) via raw socket
to a remote collector. Designed for deployments where the downstream probe (e.g. Ativa)
handles IP-fragmented GRE/ERSPAN at the network layer but does not correctly reassemble
TCP HEP streams or IP-fragmented UDP HEP datagrams.

**When to use:** Ribbon SBC → capture host → Ativa probe, when HEP UDP fragmentation or
TCP stream reassembly is unreliable end-to-end.

**Config** (`conf/transport_erspan.xml`):

```xml
<profile name="erspan" description="ERSPAN Transport" enable="true">
  <settings>
    <param name="capture-host"   value="192.0.2.1"/>  <!-- Ativa probe IP -->
    <!-- <param name="source-host" value="10.0.0.1"/> -->
    <param name="erspan-version" value="2"/>           <!-- 1=GRE-only 2=Type II 3=Type III -->
    <param name="session-id"     value="1"/>           <!-- 0-1023 -->
  </settings>
</profile>
```

Requires `CAP_NET_RAW` (Linux) or root (macOS) — same as pcap capture.

**Module location:** `src/modules/transport/erspan/`

#### max-hep-size — HEP Payload Limiting

Truncates oversized HEP packets before transmission. Kept in this fork for deployments
that need HEP payload size bounded to fit within a single MSS or MTU segment.

```xml
<param name="capture-proto" value="tcp"/>
<param name="max-hep-size"  value="1400"/>
```

---

### Developers
Contributions to our project are always welcome! If you intend to participate and help us improve CAPTAGENT, we kindly ask you to sign a [CLA (Contributor License Agreement)](http://cla.qxip.net) and coordinate at best with the existing team via the [homer-dev](http://groups.google.com/group/homer-dev) mailing list.


----------

##### If you use CAPTAGENT in production, please consider supporting us with a [donation](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=donation%40sipcapture%2eorg&lc=US&item_name=SIPCAPTURE&no_note=0&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHostedGuest)

[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=donation%40sipcapture%2eorg&lc=US&item_name=SIPCAPTURE&no_note=0&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHostedGuest)
