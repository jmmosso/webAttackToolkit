#!/usr/bin/perl
# web_s2.pl 2.0
# 13/02/2008
# Juan Manuel Ramon (jmanuel@bacchuss.com.ar)

require 'getopts.pl';
# permite especificar los archivos/directorios de trabajo (patrones y logs)
#perl2exe_include "AhoCorasick.pm";
#perl2exe_include "SearchMachine.pm";
use Algorithm::AhoCorasick qw(find_all);

#use Algorithm::AhoCorasick qw(find_first);
#rutina de deteccion de patrones O(n)
#Debe ser instalada previamente

#----------------------------------------------------------------------------------------------------
#1 Menu de la aplicacion, variables de input y mensajes
Getopts('h:r:t:d:x');

if ($opt_h) {
die "Usage $0 -f <rule file> [-t <target file> || -d <target dir> ] [options]\
\t-x debug\tTurn on debugging information.\
\t-h help\t\tDuh? This is it.\n";
}

if (!$opt_r) {die "Falta especificar la Base de Conocimiento (KB) a utilizar (-r).\n";}

if (!$opt_t && !$opt_d) {die "Falta especificar el archivo/directorio de logs a analizar (-t/-d).\n";}

my @rulez = add_rules($opt_r);
my $KB = $opt_r;
my $data_file = $opt_t;
my $data_dir = $opt_d;

$usuario = `whoami`;
$dir = `pwd`;
($fecha,$hora) = &time_stamp();

sub time_stamp {
my ($d,$t);
my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
$year += 1900;
$mon++;
$d = sprintf("%4d-%2.2d-%2.2d",$year,$mon,$mday);
$t = sprintf("%2.2d:%2.2d:%2.2d",$hour,$min,$sec);
return($d,$t);
}


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


#----------------------------------------------------------------------------------------------------
#2 Apertura archivo de resultados de la aplicacion

$logfile = "webs2_" . $fecha . "_". $hora . ".log";
open(LF, ">$logfile") or die "NO es posible crear archivo de logs $logfile: $!";


#----------------------------------------------------------------------------------------------------
#3 Bloque de carga de patrones de detecci�n (-r)
sub add_rules
{
my ($file) = @_;
my @rules;
$patrones = 0;

open(RULES,$file) || die "No es posible abrir el archivo de patrones (KB): $file!\n";
my @lines = <RULES>;

foreach my $line (@lines) 
{
if ($line =~ /^\s*#/ || $linexx eq "\n" ) { next;}
chomp ($line);
push (@rules,$line);
$patrones = $patrones + 1;
}
return (@rules);
close (RULES);
}

@contents=@rulez;

#foreach (@rulez)
#{
#print "$_ \n";
#}

print LF "\n";
print LF "--------------------------------------------------------------------------------------------------------\n";
print LF "Patrones de detecci�n obtenidos: ...................... $patrones\n";
print LF "\n";
print "\n";
print "--------------------------------------------------------------------------------------------------------\n";
print "Patrones de detecci�n obtenidos: ...................... $patrones\n";
print "\n";

print LF "--------------------------------------------------------------------------------------------------------\n";
print LF "\n";
print LF "              ***  COMIENZO ANALISIS   ***                                    \n";
print LF "\n";
print "--------------------------------------------------------------------------------------------------------\n";
print "\n";
print "               ***  COMIENZO ANALISIS   ***                                    \n";
print "\n";


#----------------------------------------------------------------------------------------------------
#4 Bloque de Procesamiento de archivo de logs (-t)
if ($data_file) 
{
print "--------------------------------------------------------------------------------------------------------\n";
print "N.Linea:                                          Posicion: Patron\n";
print "---------------------------------------------------------------------------------------------------------\n";
print LF"--------------------------------------------------------------------------------------------------------\n";
print LF"--------------------------------------------------------------------------------------------------------\n";
print LF"N.Linea:                                          Posicion: Patron\n";
print LF"---------------------------------------------------------------------------------------------------------\n";

open(FILE, "$data_file") or die("Imposible abrir archivo de log $data_file.\n");
@data = <FILE>;
$index = 0;

foreach $linexx (@data)
{
chomp ($linexx);
$index = $index + 1;
if ($linexx =~ /^\s*#/ || $linexx eq "\n" ) { next;}

#############################################################
# Parseo las lineas para extraer parametros

#2007-08-01 00:50:48 139.18.2.68 - 192.168.204.23 80 GET /pia/Binaria_Seguros/seguro_retiro_colectivo.asp - 200 0 findlinks/1.1.4-beta1+(+http://wortschatz.uni-leipzig.de/findlinks/) - -
$linexx =~ /(\S+)\s+(\S+)\s+(\S+)\s+\S\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)\s+(\d\d\d)\s+(\d+)\s+(.+)\s+(.+)\s+(.+)/;

$fecha = $1;
$hora = $2;
$sip = $3;
$dip = $4;
$port = $5;
$metodo = $6;
$payload = $7;
$resultado = $8;
$octetos = $9;
$agente = $10;
$cookie = $11;
$referrer = $12;

#print "$fecha\n";
#print "$hora\n";
#print "$sip\n";
#print "$dip\n";
#print "$port\n";
#print "$metodo\n";
#print "$resultado\n";
#print "$octetos\n";
#print "$agente\n";
#print "$cookie\n";
#print "$referrer\n";
#print "\n";

############################################################
# Normalizacion de patron (ASCII -> Char), (Cap.Let -> Low.Let)
$linexx =~ tr/+/ /;
$linexx =~ s/%([a-fA-F0-9]{2,2})/chr(hex($1))/eg;
$linexx =~ s/<!--(.|\n)*-->//g;
$linexx =~ tr/A-Z/a-z/;


$found1 = find_all($linexx, @rulez);
#$found1 = find_all($payload, @rulez);
if (!$found1) 
	{
     	#print "no keywords found\n";
 	} 
else 
	{
     	foreach $pos (sort keys %$found1) 
		{
         	$keywords = join ', ', @{$found1->{$pos}};
         	print "$index                                                  $pos: $keywords\n";
		print LF "$index                                                  $pos: $keywords\n";
     		}
 	}

}
close (FILE);

print "--------------------------------------------------------------------------------------------------------\n";
print "Se han procesado $index lineas de datos del archivo de log: $data_file.\n";
print "\n";
print LF "--------------------------------------------------------------------------------------------------------\n";
print LF "Se han procesado $index lineas de datos del archivo de log: $data_file.\n";
print LF "\n";

}# Fin bloque de proceso de archivo de logs




#################################################################################################

if ($data_dir) 
{
opendir(IMD, $data_dir) || die("No es posible acceder al directorio de logs.\n");
@logs= readdir(IMD);
closedir(IMD);

foreach $f (@logs)
{
if ($f eq '.') { next;}
if ($f eq '..') { next;}

$abs_path=$data_dir.$f;

print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
print "Analizando archivo de Log: ............................ $f. \n";
print "\n";
print LF "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
print LF "Analizando archivo de Log: ........................... $f. \n";
print LF "\n";

print "--------------------------------------------------------------------------------------------------------\n";
print "N.Linea:                                          Posicion: Patron\n";
print "---------------------------------------------------------------------------------------------------------\n";

print LF"--------------------------------------------------------------------------------------------------------\n";
print LF"N.Linea:                                          Posicion: Patron\n";
print LF"---------------------------------------------------------------------------------------------------------\n";



open(FILE, "$abs_path") or die("Imposible abrir archivo de log $data_file.\n");
@data = <FILE>;
my $index = 0;

foreach $line (@data)
{
chomp ($line);
$index = $index + 1;
if ($line =~ /^\s*#/ || $line eq "\n" ) { next;}

#############################################################
# Parseo las lineas para extraer parametros
#2007-08-01 00:50:48 139.18.2.68 - 192.168.204.23 80 GET /pia/Binaria_Seguros/seguro_retiro_colectivo.asp - 200 0 findlinks/1.1.4-beta1+(+http://wortschatz.uni-leipzig.de/findlinks/) - -
$line =~ /(\S+)\s+(\S+)\s+(\S+)\s+\S\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)\s+(\d\d\d)\s+(\d+)\s+(.+)\s+(.+)\s+(.+)/;

$fecha = $1;
$hora = $2;
$sip = $3;
$dip = $4;
$port = $5;
$metodo = $6;
$payload = $7;
$resultado = $8;
$octetos = $9;
$agente = $10;
$cookie = $11;
$referrer = $12;

#print "$fecha\n";
#print "$hora\n";
#print "$sip\n";
#print "$dip\n";
#print "$port\n";
#print "$metodo\n";
#print "$resultado\n";
#print "$octetos\n";
#print "$agente\n";
#print "$cookie\n";
#print "$referrer\n";
#print "\n";

############################################################
# Normalizacion de patron (ASCII -> Char), (Cap.Let -> Low.Let)
$line =~ tr/+/ /;
$line =~ s/%([a-fA-F0-9]{2,2})/chr(hex($1))/eg;
$line =~ s/<!--(.|\n)*-->//g;
$line =~ tr/A-Z/a-z/;


$found1 = find_all($line, @rulez);
#$found1 = find_all($payload, @rulez);
if (!$found1) 
	{
     	#print "no keywords found\n";
 	} 
else 
	{
     	foreach $pos (sort keys %$found1) 
		{
         	$keywords = join ', ', @{$found1->{$pos}};
         	print "$index                                                  $pos: $keywords\n";
		print LF "$index                                                  $pos: $keywords\n";
     		}
 	}

}

close(FILE);

print "\n";
print LF "\n";
}
}


