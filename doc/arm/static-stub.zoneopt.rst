.. code-block::

  <command>zone</command> <replaceable>string</replaceable> [ <replaceable>class</replaceable> ] {
  	<command>type</command> static-stub;
  	<command>allow-query</command> { <replaceable>address_match_element</replaceable>; ... };
  	<command>allow-query-on</command> { <replaceable>address_match_element</replaceable>; ... };
  	<command>forward</command> ( first | only );
  	<command>forwarders</command> [ port <replaceable>integer</replaceable> ] [ dscp <replaceable>integer</replaceable> ] { ( <replaceable>ipv4_address</replaceable> | <replaceable>ipv6_address</replaceable> ) [ port <replaceable>integer</replaceable> ] [ dscp <replaceable>integer</replaceable> ]; ... };
  	<command>max-records</command> <replaceable>integer</replaceable>;
  	<command>server-addresses</command> { ( <replaceable>ipv4_address</replaceable> | <replaceable>ipv6_address</replaceable> ); ... };
  	<command>server-names</command> { <replaceable>string</replaceable>; ... };
  	<command>zone-statistics</command> ( full | terse | none | <replaceable>boolean</replaceable> );
  };
