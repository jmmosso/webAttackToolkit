#!/usr/bin/perl
# webapp_statscan.pl 1.0
# 12/12/2007
# Juan Manuel Ramon (jmanuel@bacchuss.com.ar)

require 'getopts.pl';
Getopts('h:f:t:d:x');

my $data_file = $opt_t;
my @rulez = add_rules($opt_f);

sub add_rules
{
   my ($file) = @_;
   my @rules;

   open(RULES,$file) || die "No es posible abrir el archivo (KB): $file!\n";
   my @lines = <RULES>;

# en @lines tengo todo el contenido del archivo de reglas
   close (RULES);
   foreach my $line (@lines) {
      chomp ($line);

if ($line =~ /^include (.*)$/) {
          if ($opt_x) { print "Agregando include de $1\n";}
          my @line_rules = add_rules($1);
          push (@rules,@line_rules);
      }
      else {push (@rules,$line);}
   }
   return (@rules);
}


foreach $rule (@rulez) 
{

if ($rule =~ /^\s*#/ || $rule eq "\n" ) { next;}

$rule =~ /(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(->|<>|<-)\s+(\S+)\s+(\S+)(.*)$/;

$rest = $8;

if ($rest =~ /content\s*:\s*"([^"]+).*/)

{
$content=$1;
push (@contents, $content);
}   
}



# Metacaracyeres: " \ | ( ) [ { ^ $ * + ? . "
foreach $osi (@contents)
{
if ($osi =~ /\*/) 
	{
	$osi =~ tr/\*/./; #print "Procesado:------------- $osi \n";
	}
if ($osi =~ /\\/) 
	{
	$osi =~ tr/\\/./; #print "Procesado:------------- $osi \n";
	}
if ($osi =~ /\|/) 
	{
	$osi =~ tr/\|/./; #print "Procesado:------------- $osi \n";
	}
if ($osi =~ /\(/) 
	{
	$osi =~ tr/\(/./; #print "Procesado:------------- $osi \n";
	}
if ($osi =~ /\)/) 
	{
	$osi =~ tr/\)/./; #print "Procesado:------------- $osi \n";
	}
if ($osi =~ /\[/) 
	{
	$osi =~ tr/\[/./; #print "Procesado:------------- $osi \n";
	}
if ($osi =~ /\{/) 
	{
	$osi =~ tr/\{*/./; #print "Procesado:------------- $osi \n";
	}
if ($osi =~ /\^/) 
	{
	$osi =~ tr/\^/./; #print "Procesado:------------- $osi \n";
	}
if ($osi =~ /\$/) 
	{
	$osi =~ tr/\$/./; #print "Procesado:------------- $osi \n";
	}
if ($osi =~ /\+/) 
	{
	$osi =~ tr/\+/./; #print "Procesado:------------- $osi \n";
	}
if ($osi =~ /\?/) 
	{
	$osi =~ tr/\?/./; #print "Procesado:------------- $osi \n";
	}
}


print "----------------------------------------------------------------------------\n";
#foreach (@contents)
#{print "$_ \n";}
#print "----------------------------------------------------------------------------\n";

# Proceso de Archivo unico
############################################################


if ($data_file) 
{
open(FILE, "$data_file") or die("Imposible abrir archivo de log $data_file");
@data = <FILE>;

my $linea = 1;

foreach $line (@data)

#########################################################
# Tratamiento del archivo linea por linea - INICIO
{

foreach (@contents)
{
############################################################################################


if ($_ eq "GET") {;}
elsif ($_ eq "http") {;}
elsif ($_ eq ".00.") {;}
elsif ($_ eq ".01.") {;}


elsif ($line =~ /$_/)
{print "Linea $linea - Detectado $_ \n";}


#use Shell qw(echo grep wc);
#$pp = echo($line);
#if ($pp =~ /$_/){print "$_ \n";}


############################################################################################
}
$linea = $linea + 1;
}

#}
close(FILE);
close(RULES);

}

