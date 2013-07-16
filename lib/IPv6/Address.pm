package IPv6::Address;

# ABSTRACT: IPv6 Address class

use strict;
use warnings;
use Carp;
use Data::Dumper;
use Sub::Install;

use overload 
	'""' => \&to_string,
	'<=>' => \&n_cmp,
	fallback => 1;
	
my $DEBUG = 0;

sub debug {
	$DEBUG&&print STDERR $_[0];
	$DEBUG&&print STDERR "\n";
	
}

#takes a normal address as argument. Example 2001:648:2000::/48
sub new {
	my $class = shift(@_) or croak "incorrect call to new";
	my $ipv6_string = shift(@_) or croak "Cannot use an empty string as argument";
	my ($ipv6,$prefixlen) = ( $ipv6_string =~ /([0-9A-Fa-f:]+)\/(\d+)/ );
	croak "IPv6 address part not parsable" if (!defined($ipv6));
	croak "IPv6 prefix length part not parsable" if (!defined($prefixlen));
	debug("ipv6 is $ipv6, length is $prefixlen");
	my @arr;
	my @_parts = ( $ipv6 =~ /([0-9A-Fa-f]+)/g );
	my $nparts = scalar @_parts;
	if ($nparts != 8) {
		for(my $i=1;$i<=(8-$nparts);$i++) { push @arr,hex "0000" };
	} 

	my @parts = map { ($_ eq '::')? @arr : hex $_ } ( $ipv6 =~ /((?:[0-9A-Fa-f]+)|(?:::))/g ); 
	
	debug(join(":",map { sprintf "%04x",$_ } @parts));

	my $bitstr = pack 'n8',@parts;
	
	return bless { 
		bitstr => $bitstr,
		prefixlen => $prefixlen,
	},$class;		
}

#takes a bitstr (0101010101111010010....) and a prefix length as arguments
sub raw_new {
	my $class = $_[0];
	return bless { 
		bitstr => $_[1],
		prefixlen => $_[2],
	},$class;	
}

#returns the bitstr (11010111011001....)
sub get_bitstr {
	return $_[0]->{bitstr};
}


#returns the length of the IPv6 address prefix
sub get_prefixlen {
	return $_[0]->{prefixlen};
}

#returns a 1111100000 corresponding to the prefix length
sub get_mask_bitstr {
	generate_bitstr( $_[0]->get_prefixlen )
}	

sub get_masked_address_bitstr {
	generate_bitstr( $_[0]->get_prefixlen ) & $_[0]->get_bitstr;
}

sub generate_bitstr { 
	#TODO trick bellow is stupid ... fix
	pack 'B128',join('',( ( map { '1' } ( 1 .. $_[0] ) ) , ( map { '0' } ( 1 .. 128-$_[0] ) ) ));
}

#takes two bitstrs as arguments and returns their logical or as bitstr
sub bitstr_and {
	return $_[0] & $_[1]
}

#takes two bitstrs as arguments and returns their logical or as bitstr
sub bitstr_or {
	return $_[0] | $_[1]
}

#takes a bitstr and inverts it
sub bitstr_not {
	return ~ $_[0]
}

#converts a bitstr (111010010010....)  to a binary string 
sub from_str {
	my $str = shift(@_);
	return pack("B128",$str);
}

#converts from binary to literal bitstr
sub to_str {
	my $bitstr = shift(@_);
	return join('',unpack("B128",$bitstr));
}

sub contains {
	defined( my $self = shift(@_) ) or die 'incorrect call';
	defined( my $other = shift(@_) ) or die 'incorrect call';
	if (ref($other) eq '') {
		$other = __PACKAGE__->new($other);
	}
	return if ($self->get_prefixlen > $other->get_prefixlen);
	return 1 if $self->get_masked_address_bitstr eq ( generate_bitstr( $self->get_prefixlen ) & $other->get_bitstr );
	#return 1 if (substr($self->get_bitstr,0,$self->get_prefixlen) eq substr($other->get_bitstr,0,$self->get_prefixlen));
	return;
}

#returns the address part (2001:648:2000:0000:0000....)
sub addr_string {
	my $self = shift(@_);
	my $str = join(':',map { sprintf("%x",$_) } (unpack("nnnnnnnn",$self->get_bitstr)) );
	#print Dumper(@_);
	my %option = (@_) ;
	#print Dumper(\%option);
	if (defined($option{ipv4}) && $option{ipv4}) {
		my $str2 = join(':',map { sprintf("%04x",$_) } (unpack("nnnnnnnn",$self->get_bitstr)) );
		###print "string:",$str,"\n";
		$str = join(':',map { sprintf("%x",$_) } (unpack("nnnnnn",$self->get_bitstr)) ).':'.join('.',  map {sprintf("%d",hex $_)} ($str2 =~ /([0-9A-Fa-f]{2})([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2})([0-9A-Fa-f]{2})$/));
		#print STDERR $ipv4,"\n";
		
	}
	#print 'DEBUG:' . $str,"\n";
	return $str if defined(($option{nocompress}) && $option{nocompress});
	return '::' if($str eq '0:0:0:0:0:0:0:0');
	for(my $i=7;$i>1;$i--) {
		my $zerostr = join(':',split('','0'x$i));
		###print "DEBUG: $str $zerostr \n";
		if($str =~ /:$zerostr$/) {
			$str =~ s/:$zerostr$/::/;
			return $str;
		}
		elsif ($str =~ /:$zerostr:/) {
			$str =~ s/:$zerostr:/::/;
			return $str;
		}
		elsif ($str =~ /^$zerostr:/) {
			$str =~ s/^$zerostr:/::/;	
			return $str;
		} 
	}
	return $str;
}

#returns the full IPv6 address 
sub string {
	my $self = shift(@_);
	return $self->addr_string(@_).'/'.$self->get_prefixlen;
}

#to be used by the overload module
sub to_string {
	return $_[0]->string();
}

#splits the address to the order of two of the number given as first argument.
#example: if argument is 3, 2^3=8, address is split into 8 parts
sub split {
	my $self = shift(@_);
	my $split_length = shift(@_);#example: 3
	my $networks = 2**$split_length;#2**3 equals 8 prefixes
	my @bag = ();
	for(my $i=0;$i<$networks;$i++) { #from 0 to 7
		my $b_str = sprintf("%0${split_length}b",$i); # 001,010,011 and so on util 111 (7)
		my $addr_str = $self->get_bitstr; #get the original bitstring of the address
		substr($addr_str,$self->get_prefixlen,$split_length) = $b_str; #replace the correct 3 bits with $b_str
		debug $addr_str,"\n";
		push @bag,(__PACKAGE__->raw_new($addr_str,$self->get_prefixlen + $split_length)); #create and store the new addr
	}
	return @bag;
}

	
#applies the prefix length mask to the address. Does not return anything. Works on $self.
sub apply_mask {
	my $self = shift(@_);
	$self->{bitstr} = bitstr_and($self->get_bitstr,$self->get_mask_bitstr);
}	

sub first_address {
	my $bitstr = bitstr_and( $_[0]->get_bitstr , $_[0]->get_mask_bitstr );
	IPv6::Address->raw_new( $bitstr, $_[0]->get_prefixlen);
}

sub last_address {
	my $bitstr = bitstr_or( $_[0]->get_bitstr , bitstr_not( $_[0]->get_mask_bitstr ) );
	IPv6::Address->raw_new( $bitstr, $_[0]->get_prefixlen);
}
	

my %patterns = (
	unspecified => "^::\$",
	loopback => "^::1\$",
	multicast => "^ff",
);
my %binary_patterns = (
	"link-local unicast" => "^",
);


for my $item (keys %patterns) {
	Sub::Install::install_sub({
		code => sub {
			return ( shift(@_)->addr_string =~ /$patterns{$item}/i )? 1 : 0;
		},
		into => __PACKAGE__,
		as => 'is_'.$item,
	});
}



use strict;

#sub is_multicast {
	#in order for an address to be multicast ipv6, the first 8 bits must be 1. So:
#	return ($_[0]->get_bitstr =~ /^11111111/)? 1 :0;
#}	


sub ipv4_to_binarray {
	defined( my $ipv4 = shift ) or die 'Missing IPv4 address argument';
	my @parts = ( split('\.',$ipv4) );
	my @binarray = split('',join('',map { sprintf "%08b",$_ } @parts));
	#debug(Dumper(\@binarray));
	return @binarray;
}




#takes an IPv4 address and uses a part of it to enumerate inside the Ipv6 prefix of the object
#example: __PACKAGE__->new('2001:648:2001::/48')->enumerate_with_IPv4('0.0.0.1',0x0000ffff) will wield 2001:648::2001:0001::/64
#the return value will be a new IPv6::Address object, so the original object remains intact
sub enumerate_with_IPv4 {
	my ($self,$IPv4,$mask) = (@_) or die 'Incorrect call';
	my $binmask = sprintf "%032b",$mask;
	
	my @IPv4 = ipv4_to_binarray($IPv4);
	my $binary = '';
	for(my $i=0;$i<32;$i++) {
		#debug("$i ".substr($binmask,$i,1));
		$binary = $binary.$IPv4[$i] if substr($binmask,$i,1) == 1;
	}
	debug($binary);
	my $new_prefixlen = $self->get_prefixlen + length($binary);
	my $new_bitstr = to_str( $self->get_bitstr );
	debug($new_bitstr);
	substr($new_bitstr, ($self->get_prefixlen), length($binary)) = $binary;
	debug("old bitstring is ".$self->get_bitstr);
	debug("new bitstring is $new_bitstr");
	debug($new_prefixlen);
	
	return __PACKAGE__->raw_new(from_str($new_bitstr),$new_prefixlen);
}

sub enumerate_with_offset {
	my ($self,$offset,$desired_length) = (@_) or die 'Incorrect call';
	my $to_replace_len = $desired_length - $self->get_prefixlen;
	my $new_bitstr = to_str( $self->get_bitstr );
	my $offset_bitstr = sprintf("%0*b",$to_replace_len,$offset);
	debug("offset number is $offset (or: $offset_bitstr)");
	#consistency check
	die "Tried to replace $to_replace_len bits, but for $offset, ".length($offset_bitstr)." bits are required"
		if(length($offset_bitstr) > $to_replace_len);
	substr($new_bitstr, ($self->get_prefixlen), length($offset_bitstr) ) = $offset_bitstr;
	return __PACKAGE__->raw_new(from_str($new_bitstr),$desired_length);
}

sub increment {
	my ( $self , $offset ) = (@_) or die 'Incorrect call';

	my $max_int = 2**32-1;
	die 'Sorry, offsets beyond 2^32-1 are not acceptable' if( $offset > $max_int );
	die 'Sorry, cannot offset a /0 prefix. ' if ( $self->get_prefixlen == 0 );

	my $new_bitstr = to_str( $self->get_bitstr ); #will use it to store the new bitstr

	$DEBUG && print STDERR "Original bitstring is $new_bitstr\n";

	# 0..127
	my $start = ($self->get_prefixlen>=32)? $self->get_prefixlen - 32 : 0 ;
	my $len = $self->get_prefixlen - $start;

	$DEBUG && print STDERR "will replace from pos $start (from 0) and for $len len\n";

	# extract start..start+len part, 0-pad to 32 bits, pack into a network byte order $n
	my $n = unpack('N',pack('B32',sprintf("%0*s",32,substr($new_bitstr, $start , $len ))));

	$DEBUG && print STDERR "Original n=".$n."\n";
	$n += $offset;
	$DEBUG && print STDERR "Result n=".$n."\n";

	die "Sorry, address part exceeded $max_int" if( $n > $max_int ); #just a precaution

	# repack the $n into a 32bit network ordered integer, convert into "1000101010101..." string
	my $bstr = unpack( "B32", pack( 'N' , $n )  );

	$DEBUG && print STDERR "Replacement bitstr is $bstr\n";
	die 'internal error. Address should be 32-bits long' unless (length($bstr) == 32); #another precaution
			
	#replace into new_bitstr from start and for len with bstr up for len bytes counting from the *end*
	substr( $new_bitstr , $start , $len ) = substr( $bstr, - $len); 

	# result is ready, return it
	return __PACKAGE__->raw_new(from_str($new_bitstr),$self->get_prefixlen);
}

sub nxx_parts {
	unpack($_[1],$_[0]->get_bitstr)  
}

#@TODO add tests for this method
sub n16_parts {
	( $_[0]->nxx_parts('nnnnnnnn') )
}

#@TODO add tests for this method
sub n32_parts {
	( $_[0]->nxx_parts('NNNN') )
}

#@TODO add tests for this method
sub n_cmp { 
	my @a = $_[0]->n32_parts;
	my @b = $_[1]->n32_parts;
	for ( 0 .. 3 ) {
		my $cmp = ( $a[$_] <=> $b[$_] ); 
		return $cmp if ( $cmp != 0 );
	} 
	return 0;
}

sub n_sort { 
	return sort { $a <=> $b } @_;
}

sub increment_multiple_prefixes {
	defined( my $offset = shift ) or die 'incorrect call';
	my %prefixes = @_ or confess 'no prefixes given';
	my %real_prefixes = map { $_ => IPv6::Address->new( $_ ) } keys %prefixes;
	my @sorted_prefixes = sort { $real_prefixes{$a} <=> $real_prefixes{$b} } keys %prefixes;

	my $offset_orig = $offset;

	for( @sorted_prefixes ) {
		my $length = $prefixes{ $_ };
		if( 1 + $offset >  $length   ) {
			$offset -= $length ;
			next;
		}
		else {
			my $ipv6 = $real_prefixes{ $_ } ;
			return $ipv6->increment( $offset );
		}
	}
	die "cannot increment offset $offset_orig on ".join(',',@sorted_prefixes);
}

sub radius_string {
	defined(my $self = shift) or die 'Missing argument';
	#Framed-IPv6-Prefix := 0x0040200106482001beef
	my $partial_bitstr = substr(to_str( $self->get_bitstr ),0,$self->get_prefixlen);
	my $remain = $self->get_prefixlen % 8;
	if($remain > 0) {
		$partial_bitstr = $partial_bitstr . '0'x(8 - $remain);
	}
	return '0x00'.sprintf("%02x",$self->get_prefixlen).join('',map {unpack("H",pack("B4",$_))}  ($partial_bitstr =~ /([01]{4})/g) );
}

package IPv4Subnet;

use Socket;
use strict;
use Carp;
use warnings;
use Data::Dumper;


sub new {
	defined ( my $class = shift ) or die "missing class";
	defined ( my $str = shift ) or die "missing string";
	my ( $ip , $length_n ) = ( $str =~ /^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/ ) or croak 'Cannot parse $str';
	bless { ip_n => my_aton($ip) , length_n => $length_n } , $class	;
}

sub get_ip_n {
	return $_[0]->{ip_n} ;
}

sub get_start {
	return $_[0]->get_ip_n & $_[0]->get_mask_n;
}

sub get_stop {
	return $_[0]->get_start + $_[0]->get_length - 1;
}

sub get_start_ip {
	return my_ntoa($_[0]->get_start);
}

sub get_stop_ip {
	return my_ntoa($_[0]->get_stop);
}

sub get_length {
	return 2**(32-$_[0]->get_length_n);
}

sub get_length_n {
	return $_[0]->{length_n};
}

sub get_mask_n {
	($_[0]->get_length_n == 0 )?
		0 : hex('0xffffffff') << ( 32 - $_[0]->get_length_n )  ;
}	

sub get_mask {
	my_ntoa( $_[0]->get_mask_n );
}

sub get_wildcard {
	my_ntoa( ~ $_[0]->get_mask_n );
}

sub my_aton {
	defined ( my $aton_str = inet_aton( $_[0] ) ) or croak '$_[0] cannot be fed to inet_aton';
	return unpack('N',$aton_str);
}

sub my_ntoa {
	return inet_ntoa(pack('N',$_[0]));
}

sub position { 
	my $self = shift;
	defined ( my  $arg = shift ) or die "Incorrect call";
	my $number = my_aton($arg);
	$DEBUG && print STDERR "number is ",my_ntoa($number)," and start is ",my_ntoa($self->get_start)," and stop is ",my_ntoa($self->get_stop),"\n";
	return $number - $self->get_start;
}

sub contains {
	return ( ($_[0]->position($_[1]) < $_[0]->get_length) && ( $_[0]->position($_[1]) >= 0 ) )? 1 : 0;
}

sub calculate_compound_offset {
	defined( my $address = shift ) or die 'missing address';
	defined( my $blocks = shift ) or die 'missing block reference';
	
	my $offset = 0;
	for my $block (@{$blocks}) {
		my $subnet = IPv4Subnet->new($block);
		if ($subnet->contains($address)) {
			return ( $subnet->position($address) + $offset );
		}
		else {
			$offset = $offset + $subnet->get_length;
		}
	}
	die "Address $address does not belong to range:",join(',',@{$blocks});
	return;
}

=head1 COPYRIGHT & LICENSE
 
Copyright 2008 Athanasios Douitsis, all rights reserved.
 
This program is free software; you can use it
under the terms of Artistic License 2.0 which can be found at 
http://www.perlfoundation.org/artistic_license_2_0
 
=cut


1;
		
	
