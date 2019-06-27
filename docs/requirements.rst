.. Requirements:

BIND Resource Requirements
==========================

.. _hw_req:

Hardware requirements
---------------------

DNS hardware requirements have traditionally been quite modest. For many
installations, servers that have been pensioned off from active duty
have performed admirably as DNS servers.

The DNSSEC features of BIND 9 may prove to be quite CPU intensive
however, so organizations that make heavy use of these features may wish
to consider larger systems for these applications. BIND 9 is fully
multithreaded, allowing full utilization of multiprocessor systems for
installations that need it.

.. _cpu_req:

CPU Requirements
----------------

CPU requirements for BIND 9 range from i486-class machines for serving
of static zones without caching, to enterprise-class machines if you
intend to process many dynamic updates and DNSSEC signed zones, serving
many thousands of queries per second.

.. _mem_req:

Memory Requirements
-------------------

The memory of the server has to be large enough to fit the cache and
zones loaded off disk. The ``max-cache-size`` option can be used to
limit the amount of memory used by the cache, at the expense of reducing
cache hit rates and causing more DNS traffic. It is still good practice
to have enough memory to load all zone and cache data into memory —
unfortunately, the best way to determine this for a given installation
is to watch the name server in operation. After a few weeks the server
process should reach a relatively stable size where entries are expiring
from the cache as fast as they are being inserted.

.. _intensive_env:

Name Server Intensive Environment Issues
----------------------------------------

For name server intensive environments, there are two alternative
configurations that may be used. The first is where clients and any
second-level internal name servers query a main name server, which has
enough memory to build a large cache. This approach minimizes the
bandwidth used by external name lookups. The second alternative is to
set up second-level internal name servers to make queries independently.
In this configuration, none of the individual machines needs to have as
much memory or CPU power as in the first alternative, but this has the
disadvantage of making many more external queries, as none of the name
servers share their cached data.

.. _supported_os:

Supported Operating Systems
---------------------------

ISC BIND 9 compiles and runs on a large number of Unix-like operating
systems and on Microsoft Windows Server 2003 and 2008, and Windows XP
and Vista. For an up-to-date list of supported systems, see the README
file in the top level directory of the BIND 9 source distribution.

