::

  <command>controls</command> {
  	<command>inet</command> ( <replaceable>ipv4_address</replaceable> | <replaceable>ipv6_address</replaceable> |
  	    * ) [ port ( <replaceable>integer</replaceable> | * ) ] allow
  	    { <replaceable>address_match_element</replaceable>; ... } [
  	    <command>keys</command> { <replaceable>string</replaceable>; ... } ] [ read-only
  	    <replaceable>boolean</replaceable> ];
  	<command>unix</command> <replaceable>quoted_string</replaceable> perm <replaceable>integer</replaceable>
  	    <command>owner</command> <replaceable>integer</replaceable> group <replaceable>integer</replaceable> [
  	    <command>keys</command> { <replaceable>string</replaceable>; ... } ] [ read-only
  	    <replaceable>boolean</replaceable> ];
  };
