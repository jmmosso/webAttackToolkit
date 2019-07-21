#!/usr/bin/perl

# Extrae los patrones de las reglas de snort y los procesa.
# Genera un archivo de salida en formato 1 patron/linea 
# webapp_statscan.pl 1.0
# 07/02/2008
# Juan Manuel Ramon (jmanuel@bacchuss.com.ar)

require 'getopts.pl';

Getopts('r:h:f:t:d:x');

if (!$opt_r) {
die "Falta especificar el archivo de reglas de Snort (-r).\n";
}

my $data_file = $opt_r;

print "$data_file\n";
my @rulez = add_rules($data_file);

$usuario = `whoami`;
$hora = `date +%d.%m.%Y.%R`;
$dir = `pwd`;

print "\n";
print "--------------------------------------------------------------------------------------------------------\n";
print "Extracción de patrones de base Snort.\n";
print "Cualquier comentario a <jmanuel\@bacchuss.com.ar>\n";
print "\n";
print "---------------------------------------------------------------------------------------------------------\n";

print "\n";
print "IMPORTANTE: En algunas ocasiones el simbolo '.' devuelto por la herramienta\n";
print "es producto del procesamiento de metacaracteres por parte de funciones (Perl).\n";
print "Algunos metacaracteres: (*, + (, ), [, %, ?, etc.).\n";
print "\n";
print "---------------------------------------------------------------------------------------------------------\n";
print LF"\n";

print "Utilizando base de conocimientos (KB): ................ $data_file. \n";

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


my $ind_rules = 0;
my $patrones = 0;

foreach $rule (@rulez) 
{

if ($rule =~ /^\s*#/ || $rule eq "\n" ) { next;}

#Descompongo la regla en sus componentes fundamentales así puedo referenciarlos. El formato es:
# ALERT|LOG PROTO src srcport direction dst dstport
$rule =~ /(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(->|<>|<-)\s+(\S+)\s+(\S+)(.*)$/;

#la variable $rest tiene los keywords de la regla de snort
$rest = $8;
$rest1= $8;
$rest2= $8;

if ($rest =~ /content\s*:\s*"([^"]+).*content\s*:\s*"([^"]+)/)
{
$content=$1;
$content1=$2;
$ind_rules = $ind_rules +1;
$patrones = $patrones +2;

push (@contents, $content);
push (@contents, $content1);
}


elsif ($rest =~ /content\s*:\s*"([^"]+).*/)
{
$content=$1;
$ind_rules = $ind_rules +1;
$patrones = $patrones +1;

push (@contents, $content);
}   

}

#foreach $osi (@contents)
#{
#if ($osi =~ /\*/) 
#	{
#	$osi =~ tr/\*/./; #print "Procesado:------------- $osi \n";
#	}
#if ($osi =~ /\\/) 
#	{
#	$osi =~ tr/\\/./; #print "Procesado:------------- $osi \n";
#	}
#if ($osi =~ /\|/) 
#	{
#	$osi =~ tr/\|/./; #print "Procesado:------------- $osi \n";
#	}
#if ($osi =~ /\(/) 
#	{
#	$osi =~ tr/\(/./; #print "Procesado:------------- $osi \n";
#	}
#if ($osi =~ /\)/) 
#	{
#	$osi =~ tr/\)/./; #print "Procesado:------------- $osi \n";
#	}
#if ($osi =~ /\[/) 
#	{
#	$osi =~ tr/\[/./; #print "Procesado:------------- $osi \n";
#	}
#if ($osi =~ /\{/) 
#	{
#	$osi =~ tr/\{*/./; #print "Procesado:------------- $osi \n";
#	}
#if ($osi =~ /\^/) 
#	{
#	$osi =~ tr/\^/./; #print "Procesado:------------- $osi \n";
#	}
#if ($osi =~ /\$/) 
#	{
#	$osi =~ tr/\$/./; #print "Procesado:------------- $osi \n";
#	}
#if ($osi =~ /\+/) 
#	{
#	$osi =~ tr/\+/./; #print "Procesado:------------- $osi \n";
#	}
#if ($osi =~ /\?/) 
#	{
#	$osi =~ tr/\?/./; #print "Procesado:------------- $osi \n";
#	}
#
#}


# Rutina de eliminaciçon de patrones repetidos en array de patrones
my %hash;
@hash{@contents} = ();
my @contents_NoRep = keys %hash;
@contents = @contents_NoRep;


# Archivo de salida de patrones IDS

$logfile = "patrones_snrt.patt";
open(LF, ">$logfile") or die "NO es posible crear archivo de patrones $logfile: $!";

my $patronesu = 0;

foreach $line (@contents)
{
$patronesu = $patronesu + 1;
print LF "$line\n";
}


print "\n";
print "--------------------------------------------------------------------------------------------------------\n";
print "Patrones de Detección procesados y generados:\n";
print "Resultados:\n";
print "Se han procesado $ind_rules reglas IDS.\n";
print "Se han detectado $patrones patrones de deteccion.\n";
print "Se han generado $patronesu patrones de deteccion unicos.\n";
print "\n";
print "--------------------------------------------------------------------------------------------------------\n";
print "\n";
close(LF);



