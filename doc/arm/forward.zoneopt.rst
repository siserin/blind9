.. code-block::

  <command>zone</command> <replaceable>string</replaceable> [ <replaceable>class</replaceable> ] {
  	<command>type</command> forward;
  	<command>delegation-only</command> <replaceable>boolean</replaceable>;
  	<command>forward</command> ( first | only );
  	<command>forwarders</command> [ port <replaceable>integer</replaceable> ] [ dscp <replaceable>integer</replaceable> ] { ( <replaceable>ipv4_address</replaceable> | <replaceable>ipv6_address</replaceable> ) [ port <replaceable>integer</replaceable> ] [ dscp <replaceable>integer</replaceable> ]; ... };
  };
