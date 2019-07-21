#!/usr/bin/perl
# webapp_statscan.pl 1.0
# 12/12/2007
# Juan Manuel Ramon (jmanuel@bacchuss.com.ar)

require 'getopts.pl';
# require destination and rule file or help

#le agrego el modificador t para abrir el archivo a analizar "target"

Getopts('h:f:t:d:x');

##############################################################################
#############################################################################
#
# ESTE ES EL ARRAY DE PATRONES QUE GENERAN RUIDO Y DEBEN SER ELIMINADOS DE LA BUSQUEDA
# fORMATO: RESPETA METACARACTERES DE PERL.

my $EXCLUDE = 'GET|HTTP|%20|404|127.0.0.1|\.|\[|\]|script|=|BM';

##############################################################################
#############################################################################

if ($opt_h) {
die "Usage $0 -f <rule file> [-t <target file> || -d <target dir> ] [options]\
\t-x debug\tTurn on debugging information.\
\t-h help\t\tDuh? This is it.\n";
}

if (!$opt_f) {
die "Falta especificar la Base de Conocimiento (KB) a utilizar (-f).\n";
}

if (!$opt_t && !$opt_d) {
die "Falta especificar el archivo/directorio de logs a analizar (-t/-d).\n";
}

my @rulez = add_rules($opt_f);
my $KB = $opt_f;
my $data_file = $opt_t;
my $data_dir = $opt_d;

$usuario = `whoami`;
$hora = `date +%d.%m.%Y.%R`;
$dir = `pwd`;

#Archivo de LOGS de la aplicacion
$logfile = "web_s2.log-$hora";
open(LF, ">>$logfile") or die "NO es posible crear archivo de logs $logfile: $!";

print LF "\n";
print LF "--------------------------------------------------------------------------------------------------------\n";
print LF "Este es el registro de actividad de web_s2.pl\n";
print LF "Cualquier comentario a <jmanuel\@bacchuss.com.ar>\n";
print LF "\n";
print LF "--------------------------------------------------------------------------------------------------------\n";
print "\n";
print "--------------------------------------------------------------------------------------------------------\n";
print "Este es el registro de actividad de web_s2.pl\n";
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
print LF"IMPORTANTE: En algunas ocasiones el simbolo '.' devuelto por la herramienta\n";
print LF"es producto del procesamiento de metacaracteres por parte de funciones (Perl).\n";
print LF"Algunos metacaracteres: (*, + (, ), [, %, ?, etc.).\n";
print LF"\n";
print LF"---------------------------------------------------------------------------------------------------------\n";


print "Utilizando base de conocimientos (KB): ................ $KB. \n";
print LF "Utilizando base de conocimientos (KB): ................ $KB. \n";

if ($data_file) {
print "Procesando archivo de logs: ........................... $data_file.\n";
print LF "Procesando archivo de logs: ........................... $data_file.\n";

}

if ($data_dir) {
print "Procesando directorio de logs: ........................ $data_dir\n";
print LF "Procesando directorio de logs: ........................ $data_dir\n";
}

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



#yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
#foreach $l (@rules) 
#{
#print "... $l \n";
#}
#yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy

# EN EL ARRAY RULES TENGO TODAS LAS REGLAS DEL ARCHIVO (-F)

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

#if ($rest =~ /content/)
#{
#	if ($rest1 =~ /sid\s*:\s*([^;]+)/)
#	{
#	$sid=$1;
#	print "El Snort ID (SID) es: ................... $sid\n";
#	print "\n";
#	}
#
#	if ($rest2 =~ /reference\s*:\s*([^;]+)/)
#	{
#	$ref=$1;
#	print "La referencia sugerida es: .............. $ref\n";
#	print "\n";
#	}
#}


if ($rest =~ /content\s*:\s*"([^"]+).*content\s*:\s*"([^"]+)/)
{
$content=$1;
$content1=$2;
$ind_rules = $ind_rules +1;
$patrones = $patrones +2;

if ($content =~ /^GET$/i) {;}
elsif ($content =~ /^GET(\s)$/i) {;}
else {push (@contents, $content);}

if ($content1 =~ /^GET$/i) {;}
elsif ($content1 =~ /^GET(\s)$/i) {;}
else {push (@contents, $content1);}

}


elsif ($rest =~ /content\s*:\s*"([^"]+).*/)

{
$content=$1;
$ind_rules = $ind_rules +1;
$patrones = $patrones +1;

if ($content =~ /^GET$/i) {;}
elsif ($content =~ /HTTP/i) {;}
elsif ($content =~ /^GET(\s)$/i) {;}
else {push (@contents, $content);}

}   
}


#ahora
#foreach $line (@contents)
#{
#print "111- $line \n";
#}

#ahora

print LF "\n";
print LF "--------------------------------------------------------------------------------------------------------\n";
print LF "Reglas de detección procesadas: ....................... $ind_rules.\n";
print LF "Patrones de detección obtenidos: ...................... $patrones.\n";
print LF "\n";

print "\n";
print "--------------------------------------------------------------------------------------------------------\n";
print "Reglas de Detección procesadas: ....................... $ind_rules.\n";
print "Patrones de detección obtenidos: ...................... $patrones.\n";
print "\n";



print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
print LF "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";

print LF "\n";
print LF "                      ***  COMIENZO ANALISIS   ***                                    \n";
print LF "\n";

print "\n";
print "                       ***  COMIENZO ANALISIS   ***                                    \n";
print "\n";



# Proceso de Archivo unico
############################################################


if ($data_file) 
{

print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
print "Analizando archivo de Log: ........................... $data_file\n";
print "\n";
print LF "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
print LF "Analizando archivo de Log: ........................... $data_file\n";
print LF "\n";

open(FILE, "$data_file") or die("Imposible abrir archivo de log $data_file");

@data = <FILE>;

my $index = 0;

foreach $line (@data)

#########################################################
# Tratamiento del archivo linea por linea - INICIO
{


foreach (@contents)
{
############################################################################################


print "$_ \n";
print "-----------------------------------------\n";
#	if ($_ =~ /$EXCLUDE/i)
#	{}
#	else 
#		{

#if ( $line =~ /$_/ ) 
#{
#print "Detectado $_ en linea $index \n";
#}

if ($_ =~ /\*/)
{
$_ =~ s /*/\/;
$_ = $_.'*';
print "$_ \n";
}

if ( $line =~ /$_/i)
{
print "Encontrado $texto en linea $index. \n";
}


############################################################################################
}
$index = $index +1;


}



# Tratamiento del archivo linea por linea - FIN
#########################################################
#}

# cerrar archivo 
close(FILE);


}



# Proceso de Directorio completo
############################################################
if ($data_dir) 
{

# MEcanica: Directorio -> Archivos -> Lineas -> por cada linea todos los patrones.
#-----------------------------------------------------------------------------------------------------------
# Proceso de Directorios

#$dirtoget="/home/jmanuel/jmwork/herramientas/webapp_statscan/logs";


opendir(IMD, $data_dir) || die("Cannot open directory");

@thefiles= readdir(IMD);

closedir(IMD);


foreach $f (@thefiles)
{
#+++++++++++++++++++++++++++++++++++++++++
if ( $f ne '.') {
if ( $f ne '..') 
{ 

#$abs_path=$data_dir."/".$f;
$abs_path=$data_dir.$f;

print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
print "Analizando archivo de Log: ............................ $f \n";
print "\n";

print LF "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
print LF "Analizando archivo de Log: ........................... $f \n";
print LF "\n";

open(FILE, "$abs_path") or die("Unable to open file");

@data = <FILE>;

my $index = 0;

foreach $line (@data)

#########################################################
# Tratamiento del archivo linea por linea - INICIO
{

$index = $index+1;

foreach (@contents)
{
print "222- $_";


# limpieza de patrones (inicio)
#----------------------------------------------------------------------------
#if ($_ =~ /\*/)
#		{
#		$_ =~ tr/*/./;
#		print "ssssssssssss  $_ \n";
#		push (@contents, $_);
#		}
#if ($_ =~ /\[/)
#		{
#		$_ =~ tr/[/./;
#		print "ssssssssssss  $_ \n";
#		push (@contents, $_);
#		}
#if ($_ =~ /^(.htr)/)
#		{
#		$_ =~ tr/(.htr)/(.htr)/;
#		print "ssssssssssss  $_ \n";
#		push (@contents, $_);
#		}
#if ($_ =~ /\%/)
#		{
#		$_ =~ tr/%/./;
#		print "ssssssssssss  $_ \n";
#		push (@contents, $_);
#		}
#if ($_ =~ /\+/)
#		{
#		$_ =~ tr/+/./;
#		print "ssssssssssss  $_ \n";
#		push (@contents, $_);
#		}

#if ($_ =~ /\?/)
#		{
#		$_ =~ tr/?/./;
#		print "ssssssssssss  $_ \n";
#		push (@contents, $_);
#		}
#if ($_ =~ /\(/)
#		{
#		$_ =~ tr/\(/./;
#		print "ssssssssssss  $_ \n";
#		push (@contents, $_);
#		}
#if ($_ =~ /\)/)
#		{
#		$_ =~ tr/\)/./;
#		print "ssssssssssss  $_ \n";
#		push (@contents, $_);
#		}
#if ($_ =~ /\*/)
#		{
#		$_ =~ tr/*/./;
#		print "ssssssssssss  $_ \n";
#		push (@contents, $_);
#		}
#
# limpieza de patrones (fin)
#----------------------------------------------------------------------------

if ($line =~ /$_/ ) 

{
		print "Detectado! [$_] en linea $index \n";
		print "\n";
		print LF "Detectado! [$_] en linea $index \n";
		print LF"\n";
}
}


# Tratamiento del archivo linea por linea - FIN
#########################################################
}

# cerrar archivo 
close(FILE);

}
}
		
}
}
print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
print LF "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
print "\n";
print "\n";
close(LF);
