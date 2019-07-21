#!/usr/bin/perl
# webapp_statscan.pl 2.0
# 13/02/2008
# Juan Manuel Ramon (jmanuel@bacchuss.com.ar)

require 'getopts.pl';
# permite especificar los archivos/directorios de trabajo (patrones y logs)

#use Algorithm::AhoCorasick qw(find_first);
#rutina de detección de patrones O(n)
#Debe ser instalada previamente

#----------------------------------------------------------------------------------------------------
#1 Menu de la aplicacion, variables de input y mensajes
Getopts('h:r:t:d:x');

if ($opt_h) {
die "Usage $0 -f <rule file> [-t <target file> || -d <target dir> ] [options]\
\t-x debug\tTurn on debugging information.\
\t-h help\t\tDuh? This is it.\n";
}

if (!$opt_t && !$opt_d) {die "Falta especificar el archivo/directorio de logs a analizar (-t/-d).\n";}

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
#3 Bloque de carga de patrones de detección (-r)

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

open(FILE, "$data_file") or die("Imposible abrir archivo de log $data_file.\n");
@data = <FILE>;
$index = 0;
$ind =0;

&detecta (@data);

close (FILE);

print "\n";
print "Fuga de Informacion en archivo de log:.....$data_file. \n";
print "----------------------------------------------------------------------------------------\n";
print LF "\n";
print LF "Fuga de Informacion en archivo de log:.....$data_file. \n";
print LF "----------------------------------------------------------------------------------------\n";

$ss=0;
foreach $item (@datos) 
{
print "$ss. $item \n";
print LF "$ss. $item \n";
$ss=$ss+1;
}

###########################################################
#Seccion de Identificación de comando
#
print "\n";
print "Salida ejecutada el:\n";
print "Dia:.............$fecha\n";
print "Hora:............$hora\n";
print "Desde:............$sip\n";
print "\n";
###########################################################

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

@datos = ();	

foreach $f (@logs)
{
if ($f eq '.') { next;}
if ($f eq '..') { next;}

$abs_path=$data_dir.$f;

open(FILE, "$abs_path") or die("Imposible abrir archivo de log $data_file.\n");
@data = <FILE>;
$index = 0;
$ind =0;

&detecta (@data);

close(FILE);

$ss=0;

#3###################################

if ($datos[0] eq '') 
{#print "no hay datos en el array\n";
}
else
{
print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
print "Analizando archivo de Log: ............................ $f. \n";
print "\n";
print LF "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
print LF "Analizando archivo de Log: ........................... $f. \n";
print LF "\n";

foreach $item (@datos) 
	{
	print "$ss. $item \n";
	print LF "$ss. $item \n";
		$ss=$ss+1;
	}
print "\n";
print LF "\n";
}

@datos = ();	

print "\n";
print LF "\n";
}
}
		


###########################################################
############################################################3

sub detecta 
{

foreach $linexx (@data)
{
chomp ($linexx);
$index = $index + 1;
if ($linexx =~ /^\s*#/ || $linexx eq "\n" ) { next;}


############################################################
# Normalizacion de patron (ASCII -> Char), (Cap.Let -> Low.Let)
$linexx =~ tr/+/ /;
$linexx =~ s/%([a-fA-F0-9]{2,2})/chr(hex($1))/eg;
$linexx =~ s/<!--(.|\n)*-->//g;
$linexx =~ tr/A-Z/a-z/;


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
#print "---> $index - $payload\n";
#print "$resultado\n";
#print "$octetos\n";
#print "$agente\n";
#print "$cookie\n";
#print "$referrer\n";
#print "\n";

if ( $linexx =~ /select/ && $linexx =~ /500/ && $linexx =~ /syntax_error/)
{
$payload =~ /syntax_error_converting_the_varchar_value_'(.*[^+]\S+)_to_a_column_of_data_type/;
$dato=$1;
@datos[$ind] = $dato;
$ind = $ind +1;
}
else {;}
}

}

























































